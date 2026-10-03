"""规则表达式 DSL。

判定条件用一棵 JSON 表达式树描述，不用 ``eval``，不接受任何可执行代码。节点只有
三种：取事实（``{"fact": "gap.clear"}``）、字面量（``{"const": 5}``）和运算
（``{"op": "not", "args": [...]}``）。支持的运算：

``and`` / ``or``   任意个布尔操作数，短路求值
``not``            一个布尔操作数
``eq`` / ``ne``    同类型比较（布尔、数值、字符串）
``lt``/``le``/``gt``/``ge``  数值比较
``in``             右操作数必须是字面量列表，便于静态校验

求值是**全函数**之外的刻意设计：缺事实或运行期类型不符时抛出
:class:`FactMissing` / :class:`RuleEvalError`，由引擎按"不确定即拒绝"的 fail-safe
口径处理，绝不允许半截状态被当成"条件成立"。
"""

from __future__ import annotations

from typing import Any, Mapping

LOGIC_OPS = {"and", "or"}
NOT_OP = "not"
COMPARE_OPS = {"eq", "ne", "lt", "le", "gt", "ge"}
EQUALITY_OPS = {"eq", "ne"}
ORDER_OPS = {"lt", "le", "gt", "ge"}
MEMBER_OP = "in"
ALL_OPS = LOGIC_OPS | {NOT_OP} | COMPARE_OPS | {MEMBER_OP}

TYPE_BOOL = "bool"
TYPE_NUMBER = "number"
TYPE_STRING = "string"
TYPE_LIST = "list"
VALUE_TYPES = {TYPE_BOOL, TYPE_NUMBER, TYPE_STRING, TYPE_LIST}


class FactMissing(Exception):
    """求值需要的事实没有提供。"""

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name


class RuleEvalError(Exception):
    """求值期类型不符或表达式结构非法。"""


def is_number(value: Any) -> bool:
    """判断值是否为数值；``bool`` 在 Python 里是 ``int`` 子类，必须排除。"""

    return isinstance(value, (int, float)) and not isinstance(value, bool)


def const_type(value: Any) -> str | None:
    """返回字面量的类型名；非法字面量返回 ``None``。"""

    if isinstance(value, bool):
        return TYPE_BOOL
    if is_number(value):
        return TYPE_NUMBER
    if isinstance(value, str):
        return TYPE_STRING
    if isinstance(value, list):
        return TYPE_LIST
    return None


def parse(node: Any) -> "Expr":
    """把 JSON 节点解析成表达式树，结构非法时抛 :class:`RuleEvalError`。"""

    if not isinstance(node, dict):
        raise RuleEvalError(f"表达式节点必须是对象: {node!r}")
    if "fact" in node:
        name = node["fact"]
        if not isinstance(name, str) or not name:
            raise RuleEvalError("fact 引用必须是非空字符串")
        return Fact(name)
    if "const" in node:
        value = node["const"]
        if const_type(value) is None:
            raise RuleEvalError(f"非法字面量: {value!r}")
        return Const(value)
    if "op" in node:
        op = node["op"]
        args = node.get("args")
        if op not in ALL_OPS:
            raise RuleEvalError(f"未知运算符: {op!r}")
        if not isinstance(args, list):
            raise RuleEvalError(f"运算符 {op} 的 args 必须是数组")
        return Op(op, [parse(arg) for arg in args])
    raise RuleEvalError(f"无法识别的表达式节点: {node!r}")


class Expr:
    """表达式节点基类。"""

    def evaluate(self, facts: Mapping[str, Any]) -> Any:
        raise NotImplementedError

    def facts_used(self) -> set[str]:
        """返回表达式引用到的全部事实名。"""

        raise NotImplementedError


class Fact(Expr):
    """事实引用。"""

    def __init__(self, name: str) -> None:
        self.name = name

    def evaluate(self, facts: Mapping[str, Any]) -> Any:
        if self.name not in facts:
            raise FactMissing(self.name)
        return facts[self.name]

    def facts_used(self) -> set[str]:
        return {self.name}

    def __repr__(self) -> str:
        return f"Fact({self.name!r})"


class Const(Expr):
    """字面量。"""

    def __init__(self, value: Any) -> None:
        self.value = value

    def evaluate(self, facts: Mapping[str, Any]) -> Any:
        return self.value

    def facts_used(self) -> set[str]:
        return set()

    def __repr__(self) -> str:
        return f"Const({self.value!r})"


def _require_bool(value: Any, op: str) -> bool:
    if not isinstance(value, bool):
        raise RuleEvalError(f"运算符 {op} 的操作数必须是布尔值，得到 {value!r}")
    return value


def _compare(op: str, left: Any, right: Any) -> bool:
    if op in EQUALITY_OPS:
        if is_number(left) and is_number(right):
            same = left == right
        elif type(left) is type(right) and isinstance(left, (bool, str)):
            same = left == right
        else:
            raise RuleEvalError(f"运算符 {op} 的操作数类型不符: {left!r} vs {right!r}")
        return same if op == "eq" else not same
    if not (is_number(left) and is_number(right)):
        raise RuleEvalError(f"运算符 {op} 要求数值操作数: {left!r} vs {right!r}")
    if op == "lt":
        return left < right
    if op == "le":
        return left <= right
    if op == "gt":
        return left > right
    return left >= right


class Op(Expr):
    """运算节点。"""

    def __init__(self, op: str, args: list[Expr]) -> None:
        self.op = op
        self.args = list(args)

    def evaluate(self, facts: Mapping[str, Any]) -> Any:
        if self.op == "and":
            result = True
            for arg in self.args:
                value = _require_bool(arg.evaluate(facts), self.op)
                if not value:
                    return False
                result = value
            return result
        if self.op == "or":
            for arg in self.args:
                value = _require_bool(arg.evaluate(facts), self.op)
                if value:
                    return True
            return False
        if self.op == NOT_OP:
            if len(self.args) != 1:
                raise RuleEvalError("not 只接受一个操作数")
            return not _require_bool(self.args[0].evaluate(facts), self.op)
        if self.op in COMPARE_OPS:
            if len(self.args) != 2:
                raise RuleEvalError(f"运算符 {self.op} 需要两个操作数")
            left = self.args[0].evaluate(facts)
            right = self.args[1].evaluate(facts)
            return _compare(self.op, left, right)
        if self.op == MEMBER_OP:
            if len(self.args) != 2:
                raise RuleEvalError("in 需要两个操作数")
            needle = self.args[0].evaluate(facts)
            haystack = self.args[1].evaluate(facts)
            if not isinstance(haystack, list):
                raise RuleEvalError("in 的右操作数必须是列表")
            return any(_safe_eq(needle, item) for item in haystack)
        raise RuleEvalError(f"未知运算符: {self.op!r}")

    def facts_used(self) -> set[str]:
        used: set[str] = set()
        for arg in self.args:
            used |= arg.facts_used()
        return used

    def __repr__(self) -> str:
        return f"Op({self.op!r}, {self.args!r})"


def _safe_eq(left: Any, right: Any) -> bool:
    """成员判断用的相等：数值互通，其余要求同类型。"""

    if is_number(left) and is_number(right):
        return left == right
    if type(left) is type(right) and isinstance(left, (bool, str)):
        return left == right
    return False
