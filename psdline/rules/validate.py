"""规则校验流水线。

规则从现场来，必须先过校验才允许生效。校验分五级，逐级短路，前一级不过就不做
后一级（结构都没解析出来就谈不上类型检查）：

``syntax``   顶层形状：schema 版本、作用域块、规则必填字段、标识唯一
``schema``   表达式树结构：运算符已知、参数个数正确、字面量合法
``semantic`` 语义：引用的事实都在目录里、运算符两侧类型相容
``range``    取值：数值阈值落在事实声明的物理限值内、枚举取值合法
``safety``   安全 lint：拒绝恒真/恒假的死规则、拒绝缺省放行的非咨询作用域

任何一级不通过，:class:`~psdline.rules.service.RuleService` 都拒绝让规则生效；
校验结果（含全部问题）随审计落盘，现场能看到每一条为什么被拦。
"""

from __future__ import annotations

from typing import Any

from . import dsl
from .catalog import Catalog
from .dsl import COMPARE_OPS, EQUALITY_OPS, LOGIC_OPS, MEMBER_OP, NOT_OP

SUPPORTED_SCHEMA = 1

STAGE_SYNTAX = "syntax"
STAGE_SCHEMA = "schema"
STAGE_SEMANTIC = "semantic"
STAGE_RANGE = "range"
STAGE_SAFETY = "safety"
STAGES = (STAGE_SYNTAX, STAGE_SCHEMA, STAGE_SEMANTIC, STAGE_RANGE, STAGE_SAFETY)

EFFECTS = ("allow", "deny")


class ValidationResult:
    """一次校验的结果：是否通过、卡在哪一级、全部问题。"""

    def __init__(self) -> None:
        self.stage = ""
        self.issues: list[dict] = []

    @property
    def ok(self) -> bool:
        return not self.issues

    def add(self, code: str, message: str, path: str) -> None:
        self.issues.append({"code": code, "message": message, "path": path})

    def as_dict(self) -> dict:
        return {"ok": self.ok, "stage": self.stage, "issues": list(self.issues)}


def validate_ruleset(
    payload: Any, catalog: Catalog, supported_schema: int = SUPPORTED_SCHEMA
) -> ValidationResult:
    """按五级流水线校验一份规则簿。"""

    result = ValidationResult()
    scopes = _check_syntax(payload, result, supported_schema)
    if result.issues:
        result.stage = STAGE_SYNTAX
        return result
    trees = _check_expr_schema(scopes, result)
    if result.issues:
        result.stage = STAGE_SCHEMA
        return result
    _check_semantic(trees, catalog, result)
    if result.issues:
        result.stage = STAGE_SEMANTIC
        return result
    _check_ranges(trees, catalog, result)
    if result.issues:
        result.stage = STAGE_RANGE
        return result
    _check_safety(scopes, trees, result)
    if result.issues:
        result.stage = STAGE_SAFETY
        return result
    return result


# ---- syntax ------------------------------------------------------------


def _check_syntax(
    payload: Any, result: ValidationResult, supported_schema: int
) -> dict[str, dict]:
    if not isinstance(payload, dict):
        result.add("bad_shape", "规则簿必须是一个 JSON 对象", "$")
        return {}
    schema = payload.get("schema")
    if not isinstance(schema, int) or isinstance(schema, bool):
        result.add("bad_schema", "schema 必须是整数", "$.schema")
    elif schema < 1 or schema > supported_schema:
        result.add(
            "unsupported_schema",
            f"schema 版本 {schema} 不受支持（本系统支持 1..{supported_schema}）",
            "$.schema",
        )
    scopes = payload.get("scopes")
    if not isinstance(scopes, dict) or not scopes:
        result.add("bad_scopes", "scopes 必须是非空对象", "$.scopes")
        return {}
    seen_ids: set[str] = set()
    parsed: dict[str, dict] = {}
    for scope_name, scope in scopes.items():
        path = f"$.scopes.{scope_name}"
        if not isinstance(scope, dict):
            result.add("bad_scope", "作用域必须是对象", path)
            continue
        default_effect = scope.get("default_effect", "deny")
        if default_effect not in EFFECTS:
            result.add("bad_default", "default_effect 只能是 allow 或 deny", path)
        advisory = bool(scope.get("advisory", False))
        if default_effect == "allow" and not advisory:
            result.add(
                "unsafe_default",
                "缺省放行只允许用于 advisory 作用域，安全作用域必须缺省拒绝",
                path,
            )
        rules = scope.get("rules")
        if not isinstance(rules, list):
            result.add("bad_rules", "rules 必须是数组", path)
            continue
        parsed_rules = []
        for index, rule in enumerate(rules):
            rule_path = f"{path}.rules[{index}]"
            if not isinstance(rule, dict):
                result.add("bad_rule", "规则必须是对象", rule_path)
                continue
            rule_id = rule.get("id")
            if not isinstance(rule_id, str) or not rule_id:
                result.add("bad_id", "规则 id 必须是非空字符串", rule_path)
                rule_id = f"#{index}"
            elif rule_id in seen_ids:
                result.add("duplicate_id", f"规则 id 重复: {rule_id}", rule_path)
            seen_ids.add(str(rule_id))
            effect = rule.get("effect")
            if effect not in EFFECTS:
                result.add("bad_effect", "effect 只能是 allow 或 deny", rule_path)
            reason = rule.get("reason", "")
            if effect == "deny" and (not isinstance(reason, str) or not reason):
                result.add("missing_reason", "deny 规则必须给出拒绝原因 reason", rule_path)
            if "when" not in rule:
                result.add("missing_when", "规则缺少判定条件 when", rule_path)
            parsed_rules.append(rule)
        parsed[scope_name] = {"scope": scope, "rules": parsed_rules}
    return parsed


# ---- schema ------------------------------------------------------------


def _check_expr_schema(scopes: dict[str, dict], result: ValidationResult) -> dict[str, list]:
    """解析全部 when 表达式，返回 {规则路径: 表达式树}。"""

    trees: dict[str, list] = {}
    for scope_name, bundle in scopes.items():
        for index, rule in enumerate(bundle["rules"]):
            path = f"$.scopes.{scope_name}.rules[{index}]"
            if "when" not in rule:
                continue
            try:
                tree = dsl.parse(rule["when"])
            except dsl.RuleEvalError as error:
                result.add("bad_expr", str(error), f"{path}.when")
                continue
            _check_arity(tree, f"{path}.when", result)
            trees.setdefault(scope_name, []).append((rule, tree, path))
    return trees


def _check_arity(expr: dsl.Expr, path: str, result: ValidationResult) -> None:
    if not isinstance(expr, dsl.Op):
        return
    count = len(expr.args)
    if expr.op in LOGIC_OPS and count < 1:
        result.add("bad_arity", f"运算符 {expr.op} 至少需要一个操作数", path)
    if expr.op == NOT_OP and count != 1:
        result.add("bad_arity", "not 只接受一个操作数", path)
    if expr.op in COMPARE_OPS and count != 2:
        result.add("bad_arity", f"运算符 {expr.op} 需要两个操作数", path)
    if expr.op == MEMBER_OP:
        if count != 2:
            result.add("bad_arity", "in 需要两个操作数", path)
        elif not isinstance(expr.args[1], dsl.Const) or not isinstance(
            expr.args[1].value, list
        ):
            result.add("bad_member", "in 的右操作数必须是字面量列表", path)
    for index, arg in enumerate(expr.args):
        _check_arity(arg, f"{path}.args[{index}]", result)


# ---- semantic ----------------------------------------------------------


def _infer(expr: dsl.Expr, catalog: Catalog, path: str, result: ValidationResult) -> str | None:
    """推断表达式类型，类型不符时记录问题并返回 ``None``。"""

    if isinstance(expr, dsl.Fact):
        spec = catalog.get(expr.name)
        if spec is None:
            result.add("unknown_fact", f"事实不在目录中: {expr.name}", path)
            return None
        # 目录里的枚举量在表达式层按字符串处理，取值合法性由 range 级检查。
        return dsl.TYPE_STRING if spec.kind == "enum" else spec.kind
    if isinstance(expr, dsl.Const):
        return dsl.const_type(expr.value)
    assert isinstance(expr, dsl.Op)
    arg_types = [
        _infer(arg, catalog, f"{path}.args[{index}]", result)
        for index, arg in enumerate(expr.args)
    ]
    if expr.op in LOGIC_OPS or expr.op == NOT_OP:
        for arg_type in arg_types:
            if arg_type is not None and arg_type != dsl.TYPE_BOOL:
                result.add("bad_operand", f"运算符 {expr.op} 的操作数必须是布尔量", path)
                return None
        return dsl.TYPE_BOOL
    if expr.op in EQUALITY_OPS:
        if len(arg_types) != 2:
            return None  # 参数个数问题已在 schema 级记录
        left, right = arg_types
        if left is not None and right is not None:
            comparable = (
                left == right and left in (dsl.TYPE_BOOL, dsl.TYPE_NUMBER, dsl.TYPE_STRING)
            )
            if not comparable:
                result.add(
                    "bad_operand",
                    f"运算符 {expr.op} 两侧类型不相容: {left} vs {right}",
                    path,
                )
                return None
        return dsl.TYPE_BOOL
    if expr.op in COMPARE_OPS:
        for arg_type in arg_types:
            if arg_type is not None and arg_type != dsl.TYPE_NUMBER:
                result.add("bad_operand", f"运算符 {expr.op} 要求数值操作数", path)
                return None
        return dsl.TYPE_BOOL
    if expr.op == MEMBER_OP:
        if len(arg_types) != 2:
            return None  # 参数个数问题已在 schema 级记录
        left, right = arg_types
        if right is not None and right != dsl.TYPE_LIST:
            result.add("bad_operand", "in 的右操作数必须是列表", path)
            return None
        if left is not None and isinstance(expr.args[1], dsl.Const):
            for item in expr.args[1].value:
                item_type = dsl.const_type(item)
                if item_type != left or item_type == dsl.TYPE_LIST:
                    result.add(
                        "bad_operand",
                        f"in 列表元素类型 {item_type} 与左侧 {left} 不相容",
                        path,
                    )
                    return None
        return dsl.TYPE_BOOL
    result.add("bad_op", f"未知运算符: {expr.op}", path)
    return None


def _check_semantic(trees: dict[str, list], catalog: Catalog, result: ValidationResult) -> None:
    for entries in trees.values():
        for _rule, tree, path in entries:
            _infer(tree, catalog, f"{path}.when", result)


# ---- range -------------------------------------------------------------


def _check_value_against_fact(
    fact: dsl.Fact, value: Any, catalog: Catalog, path: str, result: ValidationResult
) -> None:
    spec = catalog.get(fact.name)
    if spec is None:
        return
    problem = spec.check_value(value)
    if problem:
        result.add("bad_value", problem, path)


def _walk_range(expr: dsl.Expr, catalog: Catalog, path: str, result: ValidationResult) -> None:
    if not isinstance(expr, dsl.Op):
        return
    if expr.op in COMPARE_OPS and len(expr.args) == 2:
        left, right = expr.args
        if isinstance(left, dsl.Fact) and isinstance(right, dsl.Const):
            _check_value_against_fact(left, right.value, catalog, path, result)
        elif isinstance(right, dsl.Fact) and isinstance(left, dsl.Const):
            _check_value_against_fact(right, left.value, catalog, path, result)
    if expr.op == MEMBER_OP and len(expr.args) == 2:
        needle, haystack = expr.args
        if isinstance(needle, dsl.Fact) and isinstance(haystack, dsl.Const):
            for item in haystack.value:
                _check_value_against_fact(needle, item, catalog, path, result)
    for index, arg in enumerate(expr.args):
        _walk_range(arg, catalog, f"{path}.args[{index}]", result)


def _check_ranges(trees: dict[str, list], catalog: Catalog, result: ValidationResult) -> None:
    for entries in trees.values():
        for _rule, tree, path in entries:
            _walk_range(tree, catalog, f"{path}.when", result)


# ---- safety ------------------------------------------------------------


def _check_safety(
    scopes: dict[str, dict], trees: dict[str, list], result: ValidationResult
) -> None:
    for scope_name, entries in trees.items():
        for _rule, tree, path in entries:
            if not tree.facts_used():
                result.add(
                    "constant_condition",
                    "判定条件不引用任何事实，是恒真/恒假的死规则，疑似填错",
                    f"{path}.when",
                )
    for scope_name, bundle in scopes.items():
        scope = bundle["scope"]
        if not bundle["rules"] and scope.get("default_effect", "deny") == "allow":
            result.add(
                "empty_allow",
                "作用域没有任何规则却缺省放行，等于拆掉联锁",
                f"$.scopes.{scope_name}",
            )
