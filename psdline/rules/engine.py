"""判定引擎。

判定是 ``(规则内容, schema_version, 命令, 参数, 事实快照)`` 的纯函数：不读时钟、
不读现场、不含随机性，因此历史回放只要钉住版本与快照就能逐比特复现结论。
合并策略是联锁惯例：

- **拒绝优先**：任一命中的拒绝规则守卫为真，整体拒绝；
- **放行必须显式**：没有任何放行规则命中，整体拒绝（故障导向安全）；
- **出错即拒**：任一守卫求值失败（事实缺失、类型不符），整体拒绝并记录原因。

``schema_version`` 分派到对应解释器；旧版本解释器常驻不删，保证任何历史版本
的内容永远可以按当时的语义回放。新增结构版本时只加解释器，不改旧的。
"""

from __future__ import annotations

from ..errors import InterlockError
from .expr import ExprError, evaluate
from .model import DENY, PERMIT, Decision, content_hash
from .validate import SUPPORTED_SCHEMA


def decide(
    content: dict | None,
    schema_version: int,
    command: str,
    params: dict,
    facts: dict,
) -> Decision:
    """按指定结构版本判定一次门控动作。"""

    if content is None:
        return Decision(False, DENY, command, "no_active_version")
    evaluator = _EVALUATORS.get(schema_version)
    if evaluator is None:
        raise InterlockError(
            f"不支持的规则结构版本 {schema_version}，支持 {list(SUPPORTED_SCHEMA)}",
            component="rules",
        )
    decision = evaluator(content, command, params, facts)
    decision.hash = content_hash(content)
    return decision


def _decide_v1(content: dict, command: str, params: dict, facts: dict) -> Decision:
    rules = [rule for rule in content.get("rules", []) if _matches(rule, command)]
    rules.sort(key=lambda rule: (-int(rule.get("priority", 100)), str(rule.get("id", ""))))
    fired: list[dict] = []
    errors: list[str] = []
    for rule in rules:
        try:
            guard = evaluate(rule.get("guard"), facts, params)
            if not isinstance(guard, bool):
                raise ExprError(f"守卫结果不是布尔: {guard!r}")
        except ExprError as error:
            errors.append(f"{rule.get('id', '?')}: {error.message}")
            continue
        if guard:
            fired.append(
                {
                    "rule_id": rule.get("id", ""),
                    "effect": rule.get("effect", ""),
                    "message": rule.get("message", ""),
                }
            )
    matched = len(rules)
    if errors:
        return Decision(False, DENY, command, "evaluation_error", matched=matched, fired=fired, errors=errors)
    denies = [item for item in fired if item["effect"] == DENY]
    if denies:
        return Decision(False, DENY, command, "denied_by_rule", matched=matched, fired=fired)
    permits = [item for item in fired if item["effect"] == PERMIT]
    if permits:
        return Decision(True, PERMIT, command, "permitted_by_rule", matched=matched, fired=fired)
    return Decision(False, DENY, command, "no_matching_permit", matched=matched, fired=fired)


def _matches(rule: dict, command: str) -> bool:
    on = rule.get("on", {})
    commands = on.get("command", []) if isinstance(on, dict) else []
    if isinstance(commands, str):
        commands = [commands]
    return "*" in commands or command in commands


_EVALUATORS = {1: _decide_v1}
