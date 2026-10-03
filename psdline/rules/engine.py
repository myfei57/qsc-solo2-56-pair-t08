"""规则判定引擎与门控会话。

引擎回答一个问题："给定当前事实，某作用域放行还是拒绝？"判定口径：

1. 任一规则命中且 effect=deny → 拒绝（显式拒绝最优先）
2. 有规则因缺事实/求值失败无法判定，且作用域缺省为 deny → 拒绝（fail-safe：
   看不全现场时按最保守处理）
3. 有规则命中且 effect=allow → 放行
4. 都不命中 → 作用域的 default_effect

**生效时机的取舍（会话钉住）**：一次列车作业（到站→发车）在开工时钉住当时的
规则版本，作业全程用这一版判定；新开工的作业用当前生效版本。中途换版会让
同一趟车的开门、关门、发车各按不同口径判定，产生无法自洽的联锁状态；而
"等全部作业结束再换版"会让规则下发被长停站列车无限期卡住。钉住让两者
都不发生：在途作业口径自洽，新版对后续作业立即生效。审计里每条判定都带
版本号，两版并存期间照样可解释、可回放。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Mapping

from . import dsl
from .model import RuleVersion


@dataclass(frozen=True)
class Verdict:
    """一次门控判定的结果。"""

    allowed: bool
    scope: str
    version: int
    matched: tuple[dict, ...] = ()
    indeterminate: tuple[dict, ...] = ()
    default_applied: bool = False

    @property
    def violations(self) -> list[str]:
        """拒绝原因列表：命中 deny 规则的 reason + 不确定项说明。"""

        reasons = [str(rule["reason"]) for rule in self.matched if rule["effect"] == "deny"]
        reasons.extend(
            f"事实缺失或非法: {item['fact']}" for item in self.indeterminate
        )
        return reasons

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "scope": self.scope,
            "version": self.version,
            "matched": [dict(rule) for rule in self.matched],
            "indeterminate": [dict(item) for item in self.indeterminate],
            "default_applied": self.default_applied,
            "violations": self.violations,
        }


def evaluate_content(
    content: dict, scope: str, facts: Mapping[str, Any], version: int
) -> Verdict:
    """对一份规则簿内容做判定（纯函数，回放与实时判定共用同一口径）。"""

    scopes = content.get("scopes", {}) if isinstance(content, dict) else {}
    block = scopes.get(scope)
    if not isinstance(block, dict):
        # 作用域没有配置任何规则：按 fail-safe 拒绝。
        return Verdict(
            allowed=False,
            scope=scope,
            version=version,
            indeterminate=({"fact": f"scope:{scope}", "error": "scope_undefined"},),
            default_applied=True,
        )
    default_effect = block.get("default_effect", "deny")
    matched: list[dict] = []
    indeterminate: list[dict] = []
    for rule in block.get("rules", []):
        try:
            tree = dsl.parse(rule["when"])
            outcome = tree.evaluate(facts)
        except dsl.FactMissing as error:
            indeterminate.append(
                {"rule": rule.get("id", ""), "fact": error.name, "error": "fact_missing"}
            )
            continue
        except dsl.RuleEvalError as error:
            indeterminate.append(
                {"rule": rule.get("id", ""), "fact": "", "error": str(error)}
            )
            continue
        if outcome is True:
            matched.append(
                {
                    "id": rule.get("id", ""),
                    "effect": rule.get("effect", "deny"),
                    "reason": rule.get("reason", ""),
                }
            )
    denies = [rule for rule in matched if rule["effect"] == "deny"]
    if denies:
        return Verdict(False, scope, version, tuple(matched), tuple(indeterminate))
    if indeterminate and default_effect == "deny":
        return Verdict(False, scope, version, tuple(matched), tuple(indeterminate))
    allows = [rule for rule in matched if rule["effect"] == "allow"]
    if allows:
        return Verdict(True, scope, version, tuple(matched), tuple(indeterminate))
    return Verdict(
        default_effect == "allow",
        scope,
        version,
        tuple(matched),
        tuple(indeterminate),
        default_applied=True,
    )


@dataclass
class GateSession:
    """一次列车作业的门控会话，开工时钉住规则版本。"""

    op_id: str
    pinned_version: int
    opened_at: float
    _content: dict = field(repr=False, default_factory=dict)

    def evaluate(self, scope: str, facts: Mapping[str, Any]) -> Verdict:
        """用钉住的版本判定。"""

        return evaluate_content(self._content, scope, facts, self.pinned_version)

    def as_dict(self) -> dict:
        return {
            "op_id": self.op_id,
            "pinned_version": self.pinned_version,
            "opened_at": self.opened_at,
        }


class RuleEngine:
    """门控引擎：持有当前生效版本，管理钉住会话。

    会话钉住关系会落盘（``rules/sessions`` 文档）：服务重启后在途作业仍按
    开工时的版本判定，不会因为重启被悄悄切到新版本。
    """

    SESSIONS_DOC = "rules/sessions"

    def __init__(self, clock, store=None) -> None:
        self._clock = clock
        self._store = store
        self._lock = threading.RLock()
        self._current: RuleVersion | None = None
        self._sessions: dict[str, GateSession] = {}

    def load(self, version: RuleVersion) -> None:
        """把一个新生效的版本装入引擎（不影响已钉住的会话）。"""

        with self._lock:
            self._current = version

    def begin_session(self, op_id: str) -> GateSession:
        """开工：钉住当前生效版本，返回会话。"""

        with self._lock:
            if self._current is None:
                raise dsl.RuleEvalError("规则库为空，没有可钉住的版本")
            session = GateSession(
                op_id=op_id,
                pinned_version=self._current.version,
                opened_at=self._clock.now(),
                _content=self._current.content,
            )
            self._sessions[op_id] = session
            self._persist_sessions()
            return session

    def session(self, op_id: str) -> GateSession | None:
        with self._lock:
            return self._sessions.get(op_id)

    def close_session(self, op_id: str) -> bool:
        """作业结束，关闭会话。"""

        with self._lock:
            closed = self._sessions.pop(op_id, None) is not None
            if closed:
                self._persist_sessions()
            return closed

    def close_all(self) -> int:
        """关闭全部会话（停运时用），返回关闭数量。"""

        with self._lock:
            count = len(self._sessions)
            if count:
                self._sessions.clear()
                self._persist_sessions()
            return count

    def sessions(self) -> list[dict]:
        """列出仍在进行中的会话及其钉住版本（观察两版并存期）。"""

        with self._lock:
            return [session.as_dict() for session in self._sessions.values()]

    def restore_sessions(self, versions) -> int:
        """重启后从落盘恢复会话钉住关系，返回恢复的会话数。

        钉住的版本在版本库里必然还在（版本不可变、只追加）；找不到说明落盘
        数据被清过，跳过该会话并按当前版本重新开工。
        """

        if self._store is None:
            return 0
        raw = self._store.read(self.SESSIONS_DOC)
        if not isinstance(raw, dict):
            return 0
        restored = 0
        with self._lock:
            for op_id, pin in dict(raw.get("sessions", {})).items():
                version = versions.get(int(pin.get("pinned_version", 0)))
                if version is None:
                    continue
                self._sessions[str(op_id)] = GateSession(
                    op_id=str(op_id),
                    pinned_version=version.version,
                    opened_at=float(pin.get("opened_at", 0.0)),
                    _content=version.content,
                )
                restored += 1
        return restored

    def evaluate(self, scope: str, facts: Mapping[str, Any]) -> Verdict:
        """无会话判定（控制台试算等只读场景），用当前生效版本。"""

        with self._lock:
            if self._current is None:
                raise dsl.RuleEvalError("规则库为空，无法判定")
            return evaluate_content(
                self._current.content, scope, facts, self._current.version
            )

    def _persist_sessions(self) -> None:
        if self._store is None:
            return
        payload = {
            "sessions": {
                op_id: {
                    "pinned_version": session.pinned_version,
                    "opened_at": session.opened_at,
                }
                for op_id, session in self._sessions.items()
            }
        }
        self._store.write(self.SESSIONS_DOC, payload)
