"""默认规则簿。

首次装配时播种为 v1，逐条镜像系统原来的硬编码联锁条件，保证切换到规则引擎
前后判定口径完全一致：

- ``depart``            发车：间隙探测已确认 且 关门已落盘（原 ``sig.depart_checked``）
- ``door.open``         开门：对位已落盘（原 ``door.open_doors`` 的前置检查）
- ``interlock.release`` 解锁：门在关闭位 且 间隙无异常（原 ``interlock.clear.releasable``）

每个作用域都是"deny 规则拦异常 + 一条显式 allow 规则放行正常"的结构：放行必须
是显式、可审计的规则，缺省一律拒绝。之后现场改条件走"校验 → 生效"流程，不再
改代码。
"""

from __future__ import annotations

DEFAULT_RULEBOOK = {
    "schema": 1,
    "scopes": {
        "depart": {
            "default_effect": "deny",
            "rules": [
                {
                    "id": "depart.gap_blocked",
                    "effect": "deny",
                    "reason": "间隙探测未确认",
                    "when": {"op": "not", "args": [{"fact": "gap.clear"}]},
                },
                {
                    "id": "depart.close_not_durable",
                    "effect": "deny",
                    "reason": "关门未落盘",
                    "when": {"op": "not", "args": [{"fact": "door.close_durable"}]},
                },
                {
                    "id": "depart.ready",
                    "effect": "allow",
                    "reason": "间隙已确认且关门已落盘",
                    "when": {
                        "op": "and",
                        "args": [
                            {"fact": "gap.clear"},
                            {"fact": "door.close_durable"},
                        ],
                    },
                },
            ],
        },
        "door.open": {
            "default_effect": "deny",
            "rules": [
                {
                    "id": "open.not_aligned",
                    "effect": "deny",
                    "reason": "列车对位未落盘",
                    "when": {"op": "not", "args": [{"fact": "align.durable"}]},
                },
                {
                    "id": "open.ready",
                    "effect": "allow",
                    "reason": "对位已落盘",
                    "when": {"fact": "align.durable"},
                },
            ],
        },
        "interlock.release": {
            "default_effect": "deny",
            "rules": [
                {
                    "id": "release.gate_open",
                    "effect": "deny",
                    "reason": "gate_open",
                    "when": {"fact": "gate.open"},
                },
                {
                    "id": "release.gap_blocked",
                    "effect": "deny",
                    "reason": "gap_blocked",
                    "when": {"op": "not", "args": [{"fact": "gap.clear"}]},
                },
                {
                    "id": "release.ready",
                    "effect": "allow",
                    "reason": "门在关闭位且间隙无异常",
                    "when": {
                        "op": "and",
                        "args": [
                            {"op": "not", "args": [{"fact": "gate.open"}]},
                            {"fact": "gap.clear"},
                        ],
                    },
                },
            ],
        },
    },
}
