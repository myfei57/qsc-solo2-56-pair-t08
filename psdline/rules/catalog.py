"""事实目录。

目录声明规则可以引用的全部现场量（事实）：类型、取值范围与含义。规则是数据、
目录是代码——现场能调的是条件和阈值，能引用哪些量由系统决定。取值校验（例如
"停站时长阈值不能超过系统上限"）只能对着目录做，因此目录里的范围一律取配置中
的现场限值，配置收紧时规则校验自动跟着收紧。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..config import PlatformConfig
from .dsl import TYPE_BOOL, TYPE_NUMBER, TYPE_STRING


@dataclass(frozen=True)
class FactSpec:
    """一个可引用事实的声明。"""

    name: str
    kind: str  # bool / number / enum
    description: str = ""
    minimum: float | None = None
    maximum: float | None = None
    values: tuple[str, ...] = ()

    def check_value(self, value: object) -> str | None:
        """校验一个字面量是否落在事实的合法取值内，返回问题描述或 ``None``。"""

        if self.kind == TYPE_BOOL:
            if not isinstance(value, bool):
                return f"事实 {self.name} 是布尔量，不能与非布尔值 {value!r} 比较"
            return None
        if self.kind == TYPE_NUMBER:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return f"事实 {self.name} 是数值量，不能与非数值 {value!r} 比较"
            if self.minimum is not None and value < self.minimum:
                return f"阈值 {value} 低于事实 {self.name} 的下限 {self.minimum}"
            if self.maximum is not None and value > self.maximum:
                return f"阈值 {value} 超出事实 {self.name} 的上限 {self.maximum}"
            return None
        # 枚举
        if not isinstance(value, str):
            return f"事实 {self.name} 是枚举量，只能与字符串比较"
        if self.values and value not in self.values:
            return f"取值 {value!r} 不在事实 {self.name} 的合法集合 {list(self.values)} 内"
        return None

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "description": self.description,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "values": list(self.values),
        }


@dataclass(frozen=True)
class Catalog:
    """一份完整的事实目录。"""

    facts: dict[str, FactSpec] = field(default_factory=dict)

    def get(self, name: str) -> FactSpec | None:
        return self.facts.get(name)

    def names(self) -> list[str]:
        return sorted(self.facts)

    def as_dict(self) -> dict:
        return {name: self.facts[name].as_dict() for name in self.names()}


def build_catalog(config: PlatformConfig) -> Catalog:
    """按配置里的现场限值构造事实目录。"""

    max_position = float(config.train.max_position_m)
    specs = [
        FactSpec("gap.clear", TYPE_BOOL, "间隙探测已确认"),
        FactSpec("door.close_durable", TYPE_BOOL, "关门记录已落盘"),
        FactSpec("door.opened", TYPE_BOOL, "站台门已打开"),
        FactSpec("door.queue_empty", TYPE_BOOL, "门控指令队列已清空"),
        FactSpec("gate.open", TYPE_BOOL, "站台门处于开门位"),
        FactSpec("gate.locked", TYPE_BOOL, "站台门处于锁定"),
        FactSpec("align.durable", TYPE_BOOL, "列车对位已落盘"),
        FactSpec(
            "align.error_m",
            TYPE_NUMBER,
            "对位误差（米）",
            minimum=0.0,
            maximum=max_position,
        ),
        FactSpec(
            "interlock.locked_ratio",
            TYPE_NUMBER,
            "全站锁定门比例",
            minimum=0.0,
            maximum=1.0,
        ),
        FactSpec(
            "train.position_m",
            TYPE_NUMBER,
            "列车位置（米）",
            minimum=0.0,
            maximum=max_position,
        ),
        FactSpec(
            "train.dwell_s",
            TYPE_NUMBER,
            "停站时长（秒）",
            minimum=0.0,
            maximum=float(config.train.dwell_max_s),
        ),
        FactSpec(
            "signal.aspect",
            TYPE_STRING,
            "信号机灯位",
            values=("red", "yellow", "green"),
        ),
        FactSpec("sequence.advanced", TYPE_BOOL, "门控事件序号单调前进"),
    ]
    return Catalog(facts={spec.name: spec for spec in specs})
