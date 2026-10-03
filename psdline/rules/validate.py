"""规则校验管线。

发布前必须过四道检查，任何一道出错误都不许生效：

1. **结构**：规则集与每条规则的字段、类型、标识符合法；
2. **语法**：守卫是一棵合法的表达式树（算子存在、元数正确、``in`` 右侧是数组常量）；
3. **取值**：常量与事实类型相容，数值常量落在目录声明的上下界内，枚举常量属于
   声明的取值集合，布尔不与数值混比；
4. **冲突**：同一命令上放行与拒绝规则并存时给出告警（运行时拒绝优先，告警提醒
   现场确认这不是笔误）。

告警不拦发布，错误拦。校验报告随草稿与发布事件一起落流水，事后能查清"当时
这份规则为什么被认为合法"。
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any

from .catalog import FactCatalog, FactDef
from .expr import ALL_OPS, BOOL_OPS, COMPARE_OPS, UNARY_OPS
from .model import DENY, PERMIT

SUPPORTED_SCHEMA = (1,)
RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
EFFECTS = (PERMIT, DENY)
MAX_PRIORITY = 9999
_UNSET = object()


@dataclass(frozen=True)
class Issue:
    """一条校验发现。"""

    path: str
    message: str

    def as_dict(self) -> dict:
        return {"path": self.path, "message": self.message}


@dataclass
class ValidationReport:
    """一次校验的结论：错误非空即不通过。"""

    errors: list = field(default_factory=list)
    warnings: list = field(default_factory=list)

    @property
    def valid(self) -> bool:
        return not self.errors

    def as_dict(self) -> dict:
        return {
            "valid": self.valid,
            "errors": [issue.as_dict() for issue in self.errors],
            "warnings": [issue.as_dict() for issue in self.warnings],
        }


class _Type:
    """表达式类型推断结果：类别、数值上下界、枚举取值与常量字面值。"""

    __slots__ = ("kind", "minimum", "maximum", "values", "const")

    def __init__(
        self,
        kind: str,
        minimum: float | None = None,
        maximum: float | None = None,
        values: tuple = (),
        const: object = _UNSET,
    ) -> None:
        self.kind = kind
        self.minimum = minimum
        self.maximum = maximum
        self.values = values
        self.const = const


_ERROR = _Type("error")
_ANY = _Type("any")
_BOOL = _Type("bool")


def validate_ruleset(content: Any, catalog: FactCatalog) -> ValidationReport:
    """校验一份规则集内容，返回报告（不抛异常）。"""

    report = ValidationReport()
    if not isinstance(content, dict):
        report.errors.append(Issue("$", "规则集必须是一个 JSON 对象"))
        return report
    _check_finite(content, "$", report)
    schema = content.get("schema_version")
    if isinstance(schema, bool) or not isinstance(schema, int):
        report.errors.append(Issue("$.schema_version", "schema_version 必须是整数"))
    elif schema not in SUPPORTED_SCHEMA:
        report.errors.append(
            Issue("$.schema_version", f"不支持的规则结构版本 {schema}，支持 {list(SUPPORTED_SCHEMA)}")
        )
    rules = content.get("rules")
    if not isinstance(rules, list):
        report.errors.append(Issue("$.rules", "rules 必须是数组"))
        return report
    if not rules:
        report.warnings.append(Issue("$.rules", "空规则集：生效后所有门控动作都将被拒绝"))
    seen: set[str] = set()
    for index, rule in enumerate(rules):
        path = f"$.rules[{index}]"
        if not isinstance(rule, dict):
            report.errors.append(Issue(path, "规则必须是对象"))
            continue
        _validate_rule(rule, path, catalog, report)
        rule_id = rule.get("id")
        if isinstance(rule_id, str):
            if rule_id in seen:
                report.errors.append(Issue(path, f"规则标识重复: {rule_id}"))
            seen.add(rule_id)
    _check_conflicts(rules, report)
    return report


def _validate_rule(rule: dict, path: str, catalog: FactCatalog, report: ValidationReport) -> None:
    rule_id = rule.get("id")
    if not isinstance(rule_id, str) or not RULE_ID.match(rule_id):
        report.errors.append(Issue(f"{path}.id", "规则标识必须是 1..64 位字母数字或 _ . -"))
    on = rule.get("on")
    if not isinstance(on, dict):
        report.errors.append(Issue(f"{path}.on", "on 必须是对象"))
    else:
        commands = on.get("command")
        if isinstance(commands, str):
            commands = [commands]
        if (
            not isinstance(commands, list)
            or not commands
            or any(not isinstance(item, str) or not item for item in commands)
        ):
            report.errors.append(Issue(f"{path}.on.command", "command 必须是非空字符串或字符串数组"))
    effect = rule.get("effect")
    if effect not in EFFECTS:
        report.errors.append(Issue(f"{path}.effect", f"effect 必须是 {list(EFFECTS)}"))
    priority = rule.get("priority", 100)
    if isinstance(priority, bool) or not isinstance(priority, int):
        report.errors.append(Issue(f"{path}.priority", "priority 必须是整数"))
    elif not 0 <= priority <= MAX_PRIORITY:
        report.errors.append(Issue(f"{path}.priority", f"priority 必须落在 0..{MAX_PRIORITY}"))
    guard = rule.get("guard")
    if guard is None:
        report.errors.append(Issue(f"{path}.guard", "缺少守卫表达式"))
    else:
        kind = _infer(guard, catalog, f"{path}.guard", report)
        if kind.kind not in ("bool", "error"):
            report.errors.append(Issue(f"{path}.guard", f"守卫必须是布尔表达式，实际为 {kind.kind}"))


def _check_conflicts(rules: list, report: ValidationReport) -> None:
    """同一命令上放行与拒绝并存时告警（运行时拒绝优先，结论确定但值得复核）。"""

    by_command: dict[str, set] = {}
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        on = rule.get("on")
        effect = rule.get("effect")
        if not isinstance(on, dict) or effect not in EFFECTS:
            continue
        commands = on.get("command")
        if isinstance(commands, str):
            commands = [commands]
        if not isinstance(commands, list):
            continue
        for command in commands:
            if isinstance(command, str):
                by_command.setdefault(command, set()).add(effect)
    wildcard = by_command.get("*", set())
    for command, effects in sorted(by_command.items()):
        combined = effects | (wildcard if command != "*" else set())
        if combined == {PERMIT, DENY}:
            report.warnings.append(
                Issue("$.rules", f"命令 {command!r} 上放行与拒绝规则并存，运行时拒绝优先")
            )


def _check_finite(node: Any, path: str, report: ValidationReport) -> None:
    """拒绝 NaN/Inf：它们会让内容哈希与比较语义都变得不可言说。"""

    if isinstance(node, float) and not math.isfinite(node):
        report.errors.append(Issue(path, "不允许出现 NaN 或无穷"))
    elif isinstance(node, dict):
        for key, value in node.items():
            _check_finite(value, f"{path}.{key}", report)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            _check_finite(value, f"{path}[{index}]", report)


def _infer(node: Any, catalog: FactCatalog, path: str, report: ValidationReport) -> _Type:
    """推断表达式类型；发现的问题记进报告，返回 error 类型继续向上。"""

    if not isinstance(node, dict):
        report.errors.append(Issue(path, "表达式节点必须是对象"))
        return _ERROR
    if "const" in node:
        value = node["const"]
        if isinstance(value, bool):
            return _Type("bool", const=value)
        if isinstance(value, (int, float)):
            return _Type("number", value, value, const=value)
        if isinstance(value, str):
            return _Type("string", const=value)
        report.errors.append(Issue(path, f"常量必须是布尔/数值/字符串: {value!r}"))
        return _ERROR
    if "fact" in node:
        name = node["fact"]
        definition = catalog.get(name) if isinstance(name, str) else None
        if definition is None:
            report.errors.append(Issue(path, f"未知现场事实 {name!r}"))
            return _ERROR
        return _from_fact(definition)
    if "param" in node:
        name = node["param"]
        if not isinstance(name, str) or not name:
            report.errors.append(Issue(path, "param 必须是非空字符串"))
            return _ERROR
        return _ANY
    op = node.get("op")
    if op not in ALL_OPS:
        report.errors.append(Issue(path, f"未知算子 {op!r}"))
        return _ERROR
    args = node.get("args")
    if not isinstance(args, list):
        report.errors.append(Issue(path, f"算子 {op} 的 args 必须是数组"))
        return _ERROR
    if op in BOOL_OPS:
        if not args:
            report.errors.append(Issue(path, f"算子 {op} 至少需要一个参数"))
        for index, arg in enumerate(args):
            _expect_bool(_infer(arg, catalog, f"{path}.args[{index}]", report), f"{path}.args[{index}]", report)
        return _BOOL
    if op in UNARY_OPS:
        if len(args) != 1:
            report.errors.append(Issue(path, "not 需要 1 个参数"))
        if args:
            _expect_bool(_infer(args[0], catalog, f"{path}.args[0]", report), f"{path}.args[0]", report)
        return _BOOL
    if op in COMPARE_OPS:
        if len(args) != 2:
            report.errors.append(Issue(path, f"算子 {op} 需要 2 个参数"))
            return _ERROR
        left = _infer(args[0], catalog, f"{path}.args[0]", report)
        right = _infer(args[1], catalog, f"{path}.args[1]", report)
        _check_compare(op, left, right, path, report)
        return _BOOL
    if op == "in":
        if len(args) != 2:
            report.errors.append(Issue(path, "in 需要 2 个参数"))
            return _ERROR
        left = _infer(args[0], catalog, f"{path}.args[0]", report)
        right_node = args[1]
        if not (
            isinstance(right_node, dict)
            and set(right_node) == {"const"}
            and isinstance(right_node["const"], list)
        ):
            report.errors.append(Issue(f"{path}.args[1]", "in 右侧必须是数组常量"))
            return _ERROR
        items = right_node["const"]
        if not items:
            report.errors.append(Issue(f"{path}.args[1]", "in 的候选数组不能为空"))
        for index, item in enumerate(items):
            item_path = f"{path}.args[1][{index}]"
            item_type = _infer({"const": item}, catalog, item_path, report)
            if not _compatible(left, item_type):
                report.errors.append(
                    Issue(item_path, f"in 候选与左侧类型不可比: {item_type.kind} 与 {left.kind}")
                )
                continue
            _check_pair(left, item_type, item_path, report)
        return _BOOL
    if len(args) != 2:
        report.errors.append(Issue(path, f"算子 {op} 需要 2 个参数"))
        return _ERROR
    left = _infer(args[0], catalog, f"{path}.args[0]", report)
    right = _infer(args[1], catalog, f"{path}.args[1]", report)
    for operand, sub in ((left, "args[0]"), (right, "args[1]")):
        if operand.kind not in ("number", "any", "error"):
            report.errors.append(Issue(f"{path}.{sub}", f"算子 {op} 需要数值，实际为 {operand.kind}"))
    return _Type("number")


def _from_fact(definition: FactDef) -> _Type:
    if definition.kind == "enum":
        return _Type("enum", values=definition.values)
    if definition.kind == "number":
        return _Type("number", definition.minimum, definition.maximum)
    return _Type(definition.kind)


def _expect_bool(kind: _Type, path: str, report: ValidationReport) -> None:
    if kind.kind not in ("bool", "any", "error"):
        report.errors.append(Issue(path, f"需要布尔表达式，实际为 {kind.kind}"))


def _compatible(left: _Type, right: _Type) -> bool:
    """两类是否可比较：any/error 放行，枚举按字符串处理，其余要求同类。"""

    if "error" in (left.kind, right.kind) or "any" in (left.kind, right.kind):
        return True
    pair = {left.kind, right.kind}
    if pair <= {"enum", "string"}:
        return True
    return left.kind == right.kind


def _check_compare(op: str, left: _Type, right: _Type, path: str, report: ValidationReport) -> None:
    if not _compatible(left, right):
        report.errors.append(Issue(path, f"{op} 两侧类型不可比: {left.kind} 与 {right.kind}"))
        return
    if op in ("lt", "le", "gt", "ge"):
        kinds = {left.kind, right.kind} - {"any", "error"}
        if kinds and kinds not in ({"number"}, {"string"}):
            report.errors.append(Issue(path, f"{op} 只能比较数值或字符串，实际为 {sorted(kinds)}"))
    _check_pair(left, right, path, report)


def _check_pair(left: _Type, right: _Type, path: str, report: ValidationReport) -> None:
    """取值校验：枚举常量必须在取值集合内，数值常量必须在事实上下界内。"""

    for fact_type, const_type in ((left, right), (right, left)):
        if const_type.const is _UNSET:
            continue
        value = const_type.const
        if fact_type.values and isinstance(value, str) and value not in fact_type.values:
            report.errors.append(Issue(path, f"常量 {value!r} 不在枚举取值 {list(fact_type.values)} 内"))
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            continue
        if fact_type.minimum is not None and value < fact_type.minimum:
            report.errors.append(Issue(path, f"常量 {value} 小于事实下界 {fact_type.minimum}"))
        if fact_type.maximum is not None and value > fact_type.maximum:
            report.errors.append(Issue(path, f"常量 {value} 大于事实上界 {fact_type.maximum}"))
