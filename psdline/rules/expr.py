"""联锁条件表达式。

规则守卫是一棵 JSON 表达式树：叶子取常量、现场事实或动作参数，内部节点做布尔、
比较与算术运算。用树形结构而不用嵌入式脚本，条件才能被完整校验、序列化与版本化，
也没有注入面。求值是纯函数：同一份事实快照与参数永远得到同一个结果——这是历史
回放能按当时版本逐比特复现结论的前提，因此求值器不读时钟、不读现场、不含随机性。
"""

from __future__ import annotations

from typing import Any

from ..errors import InterlockError

BOOL_OPS = ("and", "or")
UNARY_OPS = ("not",)
COMPARE_OPS = ("eq", "ne", "lt", "le", "gt", "ge")
ARITH_OPS = ("add", "sub", "mul", "div")
ALL_OPS = BOOL_OPS + UNARY_OPS + COMPARE_OPS + ARITH_OPS + ("in",)


class ExprError(InterlockError):
    """表达式求值失败（缺事实、类型不符、除零等）。"""

    def __init__(self, message: str) -> None:
        super().__init__(message, component="rules")


def _fail(message: str) -> None:
    raise ExprError(message)


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _require_bool(value: Any, where: str) -> bool:
    if isinstance(value, bool):
        return value
    _fail(f"{where} 需要布尔值，实际为 {value!r}")


def _require_number(value: Any, where: str) -> float:
    if _is_number(value):
        return value
    _fail(f"{where} 需要数值，实际为 {value!r}")


def _loose_eq(left: Any, right: Any) -> bool:
    """相等判定：布尔只和布尔比，数值之间比，其余要求类型一致。"""

    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if _is_number(left) and _is_number(right):
        return left == right
    if type(left) is type(right):
        return bool(left == right)
    return False


def _compare(op: str, left: Any, right: Any) -> bool:
    if op in ("eq", "ne"):
        result = _loose_eq(left, right)
        return result if op == "eq" else not result
    if _is_number(left) and _is_number(right):
        pass
    elif isinstance(left, str) and isinstance(right, str):
        pass
    else:
        _fail(f"{op} 两侧类型不可比: {left!r} 与 {right!r}")
    if op == "lt":
        return bool(left < right)
    if op == "le":
        return bool(left <= right)
    if op == "gt":
        return bool(left > right)
    return bool(left >= right)


def evaluate(node: Any, facts: dict, params: dict) -> Any:
    """对一棵表达式树求值；失败抛 :class:`ExprError`，由上层转为拒绝。"""

    if not isinstance(node, dict):
        _fail(f"表达式节点必须是对象: {node!r}")
    if "const" in node:
        return node["const"]
    if "fact" in node:
        name = node["fact"]
        if name not in facts:
            _fail(f"缺少现场事实 {name!r}")
        return facts[name]
    if "param" in node:
        name = node["param"]
        if name not in params:
            _fail(f"缺少动作参数 {name!r}")
        return params[name]
    op = node.get("op")
    if op not in ALL_OPS:
        _fail(f"未知算子 {op!r}")
    args = node.get("args")
    if not isinstance(args, list):
        _fail(f"算子 {op} 的 args 必须是数组")
    if op in BOOL_OPS:
        if not args:
            _fail(f"算子 {op} 至少需要一个参数")
        if op == "and":
            for arg in args:
                if not _require_bool(evaluate(arg, facts, params), "and"):
                    return False
            return True
        for arg in args:
            if _require_bool(evaluate(arg, facts, params), "or"):
                return True
        return False
    if op in UNARY_OPS:
        _arity(op, args, 1)
        return not _require_bool(evaluate(args[0], facts, params), "not")
    if op in COMPARE_OPS:
        _arity(op, args, 2)
        left = evaluate(args[0], facts, params)
        right = evaluate(args[1], facts, params)
        return _compare(op, left, right)
    if op == "in":
        _arity(op, args, 2)
        left = evaluate(args[0], facts, params)
        right = evaluate(args[1], facts, params)
        if not isinstance(right, list):
            _fail("in 右侧必须是数组常量")
        return any(_loose_eq(left, item) for item in right)
    _arity(op, args, 2)
    left = _require_number(evaluate(args[0], facts, params), op)
    right = _require_number(evaluate(args[1], facts, params), op)
    if op == "add":
        return left + right
    if op == "sub":
        return left - right
    if op == "mul":
        return left * right
    if right == 0:
        _fail("除数为零")
    return left / right


def _arity(op: str, args: list, expected: int) -> None:
    if len(args) != expected:
        _fail(f"算子 {op} 需要 {expected} 个参数，实际 {len(args)} 个")
