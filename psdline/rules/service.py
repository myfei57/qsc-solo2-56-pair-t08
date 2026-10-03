"""规则服务：把规则、门控与审计连成一条链。

职责边界：

- **改规则**：草稿 → 校验 → 发布 → 生效，每一步都过校验与并发检查，全程落审计；
- **门控**：``decide`` 用当前生效版本判定一次动作，判定连同事实快照、参数、版本号
  与内容哈希一起进审计流水——历史不可变，且可核对；
- **回放**：``decide_as_of`` 按某一时刻生效的版本判定，``verify_replay`` 用审计里
  钉住的版本与快照重算并核对结论一致。

两个关键取舍（详见模块级设计说明与测试）：

1. **生效时机**：默认延迟生效——发布后排队，等控制循环确认现场没有列车在作业才
   切换；立即生效是站点策略开关且必须给理由。作业中途换规则，同一动作前后两版
   结论可能相反，现场无法预期，安全优先于改规则的即时性。
2. **回退不重算**：回退发布一个内容指回旧版的新版本向前约束；已经按旧规则执行
   过的物理动作（开过的门、发过的车）不自动撤销也不自动重算——物理世界没有
   "撤销"，自动重放只会制造假账。服务改为产出对账清单，列出被替换版本生效期间
   全部放行判定，交人工逐条处置。
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

from ..audit import AuditLog
from ..clock import Clock
from ..errors import InterlockError
from ..eventbus import Event, EventBus
from ..ids import IdFactory
from .catalog import FactCatalog
from .engine import decide as engine_decide
from .model import (
    DENY,
    GATE_DEFERRED,
    GATE_IMMEDIATE,
    Decision,
    GatePolicy,
    Quiescence,
    RuleSetVersion,
)
from .store import RuleStore
from .validate import ValidationReport, validate_ruleset


@dataclass(frozen=True)
class RulePolicy:
    """站点策略：哪些路径允许走，默认全收在安全侧。"""

    allow_immediate: bool = False
    allow_forced: bool = True
    unmatched_default: str = "deny"  # 有生效规则集时，未被任何规则覆盖的动作如何处理


class RuleService:
    """规则全生命周期门面；所有公开方法线程安全。"""

    def __init__(
        self,
        store: RuleStore,
        catalog: FactCatalog,
        audit: AuditLog,
        bus: EventBus,
        clock: Clock,
        ids: IdFactory,
        policy: RulePolicy | None = None,
    ) -> None:
        self._store = store
        self._catalog = catalog
        self._audit = audit
        self._bus = bus
        self._clock = clock
        self._ids = ids
        self._policy = policy or RulePolicy()
        self._lock = threading.RLock()

    # ---- 改规则 ---------------------------------------------------------

    def save_draft(self, content: dict, actor: str, draft_id: str | None = None) -> dict:
        """保存草稿并校验；校验不通过也能存（工作区），但永远走不到发布。"""

        with self._lock:
            report = validate_ruleset(content, self._catalog)
            draft_id = draft_id or self._ids.next()
            base = self._store.latest_version_number()
            draft = self._store.save_draft(
                draft_id,
                base,
                content,
                report.as_dict(),
                actor,
                self._clock.now(),
                self._ids.next(),
            )
            self._audit.record(
                "rules_draft_saved",
                "",
                "",
                draft_id=draft.draft_id,
                base_version=draft.base_version,
                valid=report.valid,
                errors=len(report.errors),
                warnings=len(report.warnings),
                actor=actor,
            )
            return {"draft_id": draft.draft_id, "base_version": draft.base_version, "report": report.as_dict()}

    def validate_draft(self, draft_id: str, actor: str) -> dict:
        """重新校验草稿（目录可能已变），报告随草稿落流水。"""

        with self._lock:
            draft = self._require_draft(draft_id)
            return self.save_draft(draft.content, actor, draft_id=draft_id)

    def publish(
        self,
        draft_id: str,
        expected_base: int,
        gate: GatePolicy,
        actor: str,
        op_id: str | None = None,
        quiescence: Quiescence | None = None,
    ) -> dict:
        """发布草稿成为新版本。发布前强制重新校验——不通过不许生效。"""

        op_id = op_id or self._ids.next()
        with self._lock:
            known = self._store.applied(op_id)
            if known is not None:
                # 客户端没收到响应后的重试：直接返回当时的结果，不重复发布。
                return {"version": int(known["version"]), "gate": gate.mode, "op_id": op_id}
            if gate.mode == GATE_IMMEDIATE:
                if not self._policy.allow_immediate:
                    self._audit.record(
                        "rules_publish_rejected", "", "", draft_id=draft_id,
                        reason="immediate_not_allowed", actor=actor,
                    )
                    raise InterlockError("站点策略不允许立即生效", component="rules")
                if not gate.reason:
                    raise InterlockError("立即生效必须给出理由", component="rules")
            draft = self._require_draft(draft_id)
            report = validate_ruleset(draft.content, self._catalog)
            if not report.valid:
                self._audit.record(
                    "rules_publish_rejected", "", "", draft_id=draft_id,
                    errors=[issue.as_dict() for issue in report.errors], actor=actor,
                )
                raise InterlockError("规则校验不通过，拒绝发布", component="rules")
            latest = self._store.latest_version_number()
            if draft.base_version != expected_base or latest != expected_base:
                self._audit.record(
                    "rules_conflict", "", "", draft_id=draft_id,
                    expected_base=expected_base, latest=latest, actor=actor,
                )
                raise InterlockError(
                    f"规则基线冲突：草稿基于 v{draft.base_version}，当前最新 v{latest}，请刷新后重试",
                    component="rules",
                )
            schema = int(draft.content.get("schema_version", 0))
            version = self._store.publish(
                draft_id,
                expected_base,
                draft.content,
                schema,
                gate.mode,
                {"type": "normal"},
                actor,
                self._clock.now(),
                op_id,
                quiescence=quiescence.as_dict() if quiescence else None,
            )
            self._audit.record(
                "rules_published", "", "", draft_id=draft_id, version=version,
                gate=gate.mode, reason=gate.reason or None, actor=actor,
            )
            if gate.mode == GATE_IMMEDIATE:
                self._after_activation(version, "immediate", actor, gate.reason)
            return {"version": version, "gate": gate.mode, "op_id": op_id}

    # ---- 生效门控 -------------------------------------------------------

    def tick(self, quiescence: Quiescence) -> int:
        """控制循环驱动：现场空闲时让待生效版本生效，返回生效版本号（无则为 0）。"""

        with self._lock:
            pending = self._store.pending()
            if pending is None or not quiescence.quiescent:
                return 0
            self._store.activate(
                pending.version,
                GATE_DEFERRED,
                quiescence.as_dict(),
                "control-loop",
                self._clock.now(),
                self._ids.next(),
            )
            self._after_activation(pending.version, GATE_DEFERRED, "control-loop", "")
            return pending.version

    def cancel_pending(self, actor: str, reason: str) -> dict:
        """取消待生效版本（回到已发布状态，可重新排队）。"""

        with self._lock:
            pending = self._store.pending()
            if pending is None:
                raise InterlockError("没有待生效的规则版本", component="rules")
            self._store.cancel_pending(actor, self._clock.now(), self._ids.next(), reason)
            self._audit.record(
                "rules_activation_cancelled", "", "",
                version=pending.version, reason=reason, actor=actor,
            )
            return {"cancelled": pending.version}

    def request_activation(self, version: int, actor: str) -> dict:
        """把已取消的发布版本重新排队等待生效。"""

        with self._lock:
            target = self._store.get_version(version)
            if target is None:
                raise InterlockError(f"规则版本不存在: v{version}", component="rules")
            if self._store.pending() is not None:
                raise InterlockError("已有待生效版本，先取消或等它生效", component="rules")
            self._store.request_activation(version, actor, self._clock.now(), self._ids.next())
            self._audit.record("rules_activation_requested", "", "", version=version, actor=actor)
            return {"pending": version}

    def force_activate(self, actor: str, reason: str, quiescence: Quiescence) -> dict:
        """紧急越控：不等现场空闲立即让待生效版本生效。全程高声审计。"""

        if not reason:
            raise InterlockError("强制生效必须给出理由", component="rules")
        with self._lock:
            if not self._policy.allow_forced:
                raise InterlockError("站点策略不允许强制生效", component="rules")
            pending = self._store.pending()
            if pending is None:
                raise InterlockError("没有待生效的规则版本", component="rules")
            self._store.activate(
                pending.version,
                "forced",
                quiescence.as_dict(),
                actor,
                self._clock.now(),
                self._ids.next(),
                reason,
            )
            self._after_activation(pending.version, "forced", actor, reason)
            return {"version": pending.version, "mode": "forced"}

    # ---- 回退 -----------------------------------------------------------

    def rollback(
        self,
        to_version: int,
        gate: GatePolicy,
        actor: str,
        reason: str,
        quiescence: Quiescence | None = None,
    ) -> dict:
        """回退到历史版本的内容：发布一个内容相同的新版本（历史不改写）。

        已经按被替换版本执行过的动作**不自动撤销、不自动重算**；返回对账清单，
        列出被替换版本生效期间的全部放行判定，交人工逐条处置。
        """

        if not reason:
            raise InterlockError("回退必须给出理由", component="rules")
        with self._lock:
            target = self._store.get_version(to_version)
            if target is None:
                raise InterlockError(f"回退目标版本不存在: v{to_version}", component="rules")
            report = validate_ruleset(target.content, self._catalog)
            if not report.valid:
                raise InterlockError(
                    "回退目标按当前事实目录校验不通过，拒绝生效", component="rules"
                )
            replaced = self._store.active()
            base = self._store.latest_version_number()
            version = self._store.publish(
                "",
                base,
                target.content,
                target.schema_version,
                gate.mode,
                {"type": "rollback", "from_version": to_version, "reason": reason},
                actor,
                self._clock.now(),
                self._ids.next(),
                quiescence=quiescence.as_dict() if quiescence else None,
            )
            if gate.mode == GATE_IMMEDIATE:
                self._after_activation(version, "immediate", actor, reason)
            reconciliation = self._reconciliation(replaced)
            self._audit.record(
                "rules_rollback", "", "",
                from_version=replaced.version if replaced else 0,
                restored_content_of=to_version,
                new_version=version,
                gate=gate.mode,
                reason=reason,
                affected_decisions=len(reconciliation),
                actor=actor,
            )
            return {
                "version": version,
                "restored_content_of": to_version,
                "replaced": replaced.version if replaced else 0,
                "recomputed": False,
                "reconciliation": reconciliation,
                "note": "已按旧版本执行的动作不自动撤销/重算，请人工核对对账清单",
            }

    # ---- 门控判定 -------------------------------------------------------

    def decide(self, command: str, params: dict, facts: dict, actor: str = "") -> Decision:
        """用当前生效版本判定一次门控动作，判定连同快照进审计。"""

        with self._lock:
            active = self._store.active()
            if active is None:
                return Decision(False, DENY, command, "no_active_version")
            decision = engine_decide(active.content, active.schema_version, command, params, facts)
            decision.version = active.version
            self._audit.record(
                "rules_decision", "", "",
                command=command,
                version=active.version,
                hash=decision.hash,
                allowed=decision.allowed,
                reason=decision.reason,
                fired=decision.fired,
                params=dict(params),
                facts=dict(facts),
                actor=actor or None,
            )
            return decision

    def decide_as_of(self, at: float, command: str, params: dict, facts: dict) -> Decision:
        """按某一时刻生效的版本判定（回放旧记录按当时版本算）。"""

        with self._lock:
            version = self._store.version_at(at)
            if version is None:
                return Decision(False, DENY, command, "no_active_version")
            decision = engine_decide(version.content, version.schema_version, command, params, facts)
            decision.version = version.version
            self._audit.record(
                "rules_replay", "", "",
                command=command, as_of=at, version=version.version,
                allowed=decision.allowed, reason=decision.reason,
                authoritative=False,
            )
            return decision

    def preview(self, content: dict, command: str, params: dict, facts: dict, actor: str) -> Decision:
        """试算一份未发布的内容（非权威，结果也进审计）。"""

        with self._lock:
            schema = content.get("schema_version", 0)
            decision = engine_decide(content, int(schema) if isinstance(schema, int) else 0, command, params, facts)
            self._audit.record(
                "rules_preview", "", "",
                command=command, allowed=decision.allowed, reason=decision.reason,
                authoritative=False, actor=actor,
            )
            return decision

    def verify_replay(self, audit_id: str) -> dict:
        """用审计里钉住的版本与快照重算一次判定，核对结论逐比特一致。"""

        with self._lock:
            entry = self._find_audit(audit_id)
            if entry is None or entry.kind != "rules_decision":
                raise InterlockError(f"找不到门控判定审计: {audit_id}", component="rules")
            detail = entry.detail
            version = self._store.get_version(int(detail.get("version", 0)))
            if version is None:
                return {"consistent": False, "reason": "version_missing", "audit_id": audit_id}
            replayed = engine_decide(
                version.content,
                version.schema_version,
                str(detail.get("command", "")),
                dict(detail.get("params", {})),
                dict(detail.get("facts", {})),
            )
            consistent = replayed.allowed == bool(detail.get("allowed")) and (
                [item["rule_id"] for item in replayed.fired]
                == [item.get("rule_id") for item in detail.get("fired", [])]
            )
            return {
                "consistent": consistent,
                "audit_id": audit_id,
                "version": version.version,
                "expected_allowed": bool(detail.get("allowed")),
                "replayed_allowed": replayed.allowed,
            }

    # ---- 查询 -----------------------------------------------------------

    def active_version(self) -> int:
        """当前生效版本号（无则 0），门控挂钩用它决定要不要接管。"""

        return self._store.active().version if self._store.active() else 0

    def status(self) -> dict:
        """规则子系统状态快照。"""

        with self._lock:
            active = self._store.active()
            pending = self._store.pending()
            return {
                "active": active.as_dict() if active else None,
                "pending": pending.as_dict() if pending else None,
                "versions": [version.as_dict() for version in self._store.versions()],
                "drafts": [draft.as_dict() for draft in self._store.drafts()],
                "catalog_facts": self._catalog.names(),
                "catalog": self._catalog.as_mapping(),
                "policy": {
                    "allow_immediate": self._policy.allow_immediate,
                    "allow_forced": self._policy.allow_forced,
                    "unmatched_default": self._policy.unmatched_default,
                },
            }

    # ---- 内部 -----------------------------------------------------------

    def _require_draft(self, draft_id: str):
        draft = self._store.get_draft(draft_id)
        if draft is None:
            raise InterlockError(f"规则草稿不存在: {draft_id}", component="rules")
        return draft

    def _after_activation(self, version: int, mode: str, actor: str, reason: str) -> None:
        active = self._store.active()
        self._audit.record(
            "rules_activated", "", "",
            version=version, mode=mode, reason=reason or None, actor=actor,
        )
        self._bus.publish(
            Event.of(
                "rules",
                "rules",
                "activated",
                version=version,
                mode=mode,
                hash=active.hash if active else "",
                severity="alarm" if mode in ("forced", "immediate") else "notice",
            )
        )

    def _reconciliation(self, replaced: RuleSetVersion | None) -> list:
        """被替换版本生效期间的全部放行判定（对账清单，不重算不撤销）。"""

        if replaced is None or not replaced.activated_at:
            return []
        found = []
        for entry in self._audit.replay():
            if entry.kind != "rules_decision":
                continue
            detail = entry.detail
            if int(detail.get("version", 0)) != replaced.version:
                continue
            if entry.at < replaced.activated_at or not detail.get("allowed"):
                continue
            found.append(
                {
                    "audit_id": entry.id,
                    "at": entry.at,
                    "command": detail.get("command", ""),
                    "reason": detail.get("reason", ""),
                }
            )
        return found

    def _find_audit(self, audit_id: str):
        for entry in self._audit.replay():
            if entry.id == audit_id:
                return entry
        return None
