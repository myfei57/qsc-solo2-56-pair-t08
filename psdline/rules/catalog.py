"""现场事实目录。

规则引用的每一个 ``fact`` 都必须在目录里登记：类型（布尔/数值/字符串/枚举）、
数值上下界、枚举取值。校验管线拿目录做类型检查与取值校验——常量越界、枚举值
不存在、布尔拿去比大小，都在发布前拦下。目录在装配期自校验，非法目录直接拒绝
启动，不允许带着一份糊涂目录跑起来。
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..errors import ConfigError

KINDS = ("bool", "number", "string", "enum")


@dataclass(frozen=True)
class FactDef:
    """一个可引用事实的声明。"""

    name: str
    kind: str
    minimum: float | None = None
    maximum: float | None = None
    values: tuple[str, ...] = field(default_factory=tuple)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "kind": self.kind,
            "minimum": self.minimum,
            "maximum": self.maximum,
            "values": list(self.values),
        }


class FactCatalog:
    """事实目录：校验期查类型与取值范围，运行期不再参与判定。"""

    def __init__(self, definitions: list[FactDef]) -> None:
        self._defs = {definition.name: definition for definition in definitions}

    @classmethod
    def from_mapping(cls, payload: dict) -> "FactCatalog":
        """从 ``{name: {"kind": ..., ...}}`` 形式构造并校验。"""

        if not isinstance(payload, dict) or not payload:
            raise ConfigError("事实目录必须是非空对象", component="rules")
        definitions: list[FactDef] = []
        for name, spec in payload.items():
            if not isinstance(name, str) or not name:
                raise ConfigError("事实名称不能为空", component="rules")
            if not isinstance(spec, dict):
                raise ConfigError(f"事实 {name} 的声明必须是对象", component="rules")
            kind = str(spec.get("kind", ""))
            if kind not in KINDS:
                raise ConfigError(f"事实 {name} 类型非法: {kind!r}", component="rules")
            values = tuple(str(item) for item in spec.get("values", ()))
            minimum = spec.get("minimum")
            maximum = spec.get("maximum")
            if kind == "enum" and not values:
                raise ConfigError(f"枚举事实 {name} 必须给出取值列表", component="rules")
            if kind == "number":
                if minimum is not None and maximum is not None and minimum > maximum:
                    raise ConfigError(f"事实 {name} 的取值上下界颠倒", component="rules")
            elif minimum is not None or maximum is not None:
                raise ConfigError(f"只有数值事实 {name} 才能声明上下界", component="rules")
            definitions.append(
                FactDef(
                    name=name,
                    kind=kind,
                    minimum=minimum,
                    maximum=maximum,
                    values=values,
                )
            )
        return cls(definitions)

    def get(self, name: str) -> FactDef | None:
        """按名查事实声明。"""

        return self._defs.get(name)

    def names(self) -> list[str]:
        """返回全部事实名（排序后）。"""

        return sorted(self._defs)

    def as_mapping(self) -> dict:
        """转回字典形式，供状态接口与落盘核对。"""

        return {name: self._defs[name].as_dict() for name in self.names()}


def default_catalog() -> FactCatalog:
    """门控链路的出厂事实目录，与 :meth:`Platform._fact_snapshot` 一一对应。"""

    return FactCatalog.from_mapping(
        {
            "gap.clear": {"kind": "bool"},
            "train.doors_open": {"kind": "bool"},
            "train.aligned": {"kind": "bool"},
            "psd.open_count": {"kind": "number", "minimum": 0, "maximum": 100000},
            "psd.locked_count": {"kind": "number", "minimum": 0, "maximum": 100000},
            "psd.locked_ratio": {"kind": "number", "minimum": 0.0, "maximum": 1.0},
            "interlock.fault_count": {"kind": "number", "minimum": 0, "maximum": 100000},
            "interlock.armed": {"kind": "bool"},
            "quota.arrival_remaining": {"kind": "number", "minimum": 0},
            "quota.depart_remaining": {"kind": "number", "minimum": 0},
            "station.gate_locked": {"kind": "bool"},
            "sig.aspect": {"kind": "enum", "values": ["red", "yellow", "green"]},
        }
    )
