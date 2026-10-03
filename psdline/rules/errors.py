"""联锁规则系统的异常类型。

规则系统的失败分四类：规则内容本身不合法（校验不通过，不许生效）、并发修改冲突
（基于版本号的乐观锁被抢占）、版本或历史不存在（回退目标、回放对象找不到）、以及
规则库存储损坏（哈希链断裂、提交记录与版本文档不一致）。四类都要能被控制台区分
展示，因此各自独立成类。
"""

from __future__ import annotations

from ..errors import RailError


class RuleError(RailError):
    """规则系统异常的基类。"""

    def __init__(self, message: str, *, component: str = "rules") -> None:
        super().__init__(message, component=component)


class RuleValidationError(RuleError):
    """规则簿未通过校验，携带全部校验问题。"""

    def __init__(self, message: str, issues: list[dict] | None = None) -> None:
        super().__init__(message)
        self.issues = list(issues or [])

    def as_record(self) -> dict:
        return {**super().as_record(), "issues": list(self.issues)}


class RuleConflictError(RuleError):
    """并发修改冲突：调用方基于的基线版本已不是当前生效版本。"""


class RuleNotFoundError(RuleError):
    """引用的版本、判定记录或作用域不存在。"""
