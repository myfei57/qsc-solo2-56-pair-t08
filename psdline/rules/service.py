"""规则服务：把校验、版本存储、门控引擎与审计连成一条链。

对外只暴露六个动作：校验（``validate``）、试算（``simulate``）、生效
（``activate``）、回退（``rollback``）、历史与影响面查询（``history`` /
``impact``）、回放（``replay`` / ``evaluate_at``）。

不变式：

- **不校验不生效**：``activate`` 与 ``rollback`` 都强制重跑校验流水线，
  不信任调用方"我已经验过了"的说法（目录可能已随配置收紧）。
- **并发 CAS**：每个写动作都要带 ``base_version``（调用方看到的当前版本），
  与库顶不符即冲突——两个值班员同时改，后到者必须重新拉取再提交。
- **单提交点**：版本先生效于提交流水，再刷新引擎；中途崩溃由存储层恢复，
  不会出现"引擎用了没提交的版本"。
- **历史不可变**：回退生成新版本，已执行的判定不重算、不改写；影响面靠
  审计链查询，不靠回放改判。
"""

from __future__ import annotations

import threading
from typing import Any, Mapping

from ..clock import Clock
from . import replay
from .audit import (
    ACTION_ACTIVATE,
    ACTION_DECISION,
    ACTION_ROLLBACK,
    ACTION_SEED,
    ACTION_VALIDATE_FAILED,
    RuleAudit,
)
from .catalog import Catalog
from .engine import GateSession, RuleEngine, Verdict
from .errors import RuleConflictError, RuleNotFoundError, RuleValidationError
from .model import SOURCE_PROPOSE, SOURCE_ROLLBACK, SOURCE_SEED, RuleVersion
from .store import RuleStore
from .validate import validate_ruleset


class RuleService:
    """规则系统的装配入口。"""

    def __init__(
        self,
        store: RuleStore,
        audit: RuleAudit,
        engine: RuleEngine,
        catalog: Catalog,
        clock: Clock,
    ) -> None:
        self._store = store
        self._audit = audit
        self._engine = engine
        self._catalog = catalog
        self._clock = clock
        self._lock = threading.RLock()
        self._decision_seq = len(audit.list(ACTION_DECISION))
        head = store.head()
        if head is not None:
            engine.load(head)
        engine.restore_sessions(store)

    @property
    def catalog(self) -> Catalog:
        return self._catalog

    @property
    def engine(self) -> RuleEngine:
        return self._engine

    @property
    def audit(self) -> RuleAudit:
        return self._audit

    # ---- 查询 ---------------------------------------------------------

    def current(self) -> dict:
        """返回当前生效版本的摘要与引擎状态。"""

        head = self._store.head()
        summary = None
        if head is not None:
            summary = {**head.summary(), "version_hash": self._store.head_hash()}
        return {
            "version": summary,
            "sessions": self._engine.sessions(),
            "audit": self._audit.verify(),
        }

    def history(self) -> list[dict]:
        """按版本号升序返回全部版本的摘要。"""

        return [
            {**version.summary(), "version_hash": version_hash}
            for version, version_hash in self._store.chain()
        ]

    # ---- 校验与试算 ----------------------------------------------------

    def validate(self, content: Any) -> dict:
        """只校验不生效，返回完整校验结果。"""

        return validate_ruleset(content, self._catalog).as_dict()

    def simulate(self, scope: str, facts: Mapping[str, Any]) -> dict:
        """用当前生效版本试算一次（只读，不写审计）。"""

        return self._engine.evaluate(scope, facts).as_dict()

    # ---- 生效 ----------------------------------------------------------

    def seed(self, content: dict, author: str, reason: str) -> dict:
        """空库时播种第一个版本（装配期用），已有版本则拒绝。"""

        with self._lock:
            if self._store.head() is not None:
                raise RuleConflictError("规则库已有版本，不能重复播种")
            result = validate_ruleset(content, self._catalog)
            if not result.ok:
                raise RuleValidationError("默认规则簿未通过校验", result.issues)
            version = RuleVersion(
                version=1,
                created_at=self._clock.now(),
                author=author,
                reason=reason,
                source=SOURCE_SEED,
                content=content,
            )
            return self._commit(version, ACTION_SEED)

    def activate(self, content: dict, base_version: int, author: str, reason: str) -> dict:
        """校验通过后让一份规则簿生效为新版本。"""

        with self._lock:
            head = self._require_base(base_version)
            result = validate_ruleset(content, self._catalog)
            if not result.ok:
                self._audit.record(
                    author,
                    ACTION_VALIDATE_FAILED,
                    {"stage": result.stage, "issues": result.issues, "intent": "activate"},
                )
                raise RuleValidationError(
                    f"规则簿未通过校验（{result.stage} 级），拒绝生效", result.issues
                )
            version = RuleVersion(
                version=(0 if head is None else head.version) + 1,
                created_at=self._clock.now(),
                author=author,
                reason=reason,
                source=SOURCE_PROPOSE,
                content=content,
            )
            return self._commit(version, ACTION_ACTIVATE)

    def rollback(self, target_version: int, base_version: int, author: str, reason: str) -> dict:
        """回退到某一历史版本：生成内容相同的新版本，历史不改写。

        目标版本的内容要用**当前**目录与校验器重验——目录可能已随配置演进，
        旧规则若引用了已退役的事实或越界的阈值，回退同样被拒绝（修复前进，
        不许带病回退）。已按旧版执行的判定不重算，用 :meth:`impact` 查影响面。
        """

        with self._lock:
            head = self._require_base(base_version)
            target = self._store.get(target_version)
            if target is None:
                raise RuleNotFoundError(f"回退目标版本不存在: {target_version}")
            result = validate_ruleset(target.content, self._catalog)
            if not result.ok:
                self._audit.record(
                    author,
                    ACTION_VALIDATE_FAILED,
                    {
                        "stage": result.stage,
                        "issues": result.issues,
                        "intent": "rollback",
                        "target_version": target_version,
                    },
                )
                raise RuleValidationError(
                    f"版本 {target_version} 的内容在当前校验口径下不合法，拒绝回退",
                    result.issues,
                )
            version = RuleVersion(
                version=(0 if head is None else head.version) + 1,
                created_at=self._clock.now(),
                author=author,
                reason=reason,
                source=SOURCE_ROLLBACK,
                content=target.content,
                rollback_of=target_version,
            )
            return self._commit(version, ACTION_ROLLBACK)

    # ---- 门控判定 ------------------------------------------------------

    def gate(
        self,
        session: GateSession,
        scope: str,
        facts: Mapping[str, Any],
        actor: str,
        context: dict | None = None,
    ) -> Verdict:
        """在钉住会话上做一次强制判定，并把判定写进审计链。"""

        verdict = session.evaluate(scope, facts)
        self._record_decision(actor, verdict, scope, facts, session.op_id, context)
        return verdict

    def gate_current(
        self,
        scope: str,
        facts: Mapping[str, Any],
        actor: str,
        context: dict | None = None,
    ) -> Verdict:
        """用当前生效版本做一次强制判定（检修类单点动作），并写审计链。"""

        verdict = self._engine.evaluate(scope, facts)
        self._record_decision(actor, verdict, scope, facts, "maintenance", context)
        return verdict

    def _record_decision(
        self,
        actor: str,
        verdict: Verdict,
        scope: str,
        facts: Mapping[str, Any],
        op_id: str,
        context: dict | None,
    ) -> None:
        """把一次门控判定落进审计链（含全量事实快照，供回放）。"""

        with self._lock:
            self._decision_seq += 1
            seq = self._decision_seq
        self._audit.record(
            actor,
            ACTION_DECISION,
            {
                "decision_id": f"gd-{seq:08d}",
                "op_id": op_id,
                "scope": scope,
                "version": verdict.version,
                "allowed": verdict.allowed,
                "matched": [dict(rule) for rule in verdict.matched],
                "indeterminate": [dict(item) for item in verdict.indeterminate],
                "facts": dict(facts),
                **(dict(context) if context else {}),
            },
        )

    # ---- 影响面与回放 ---------------------------------------------------

    def impact(self, version: int) -> dict:
        """列出某一版规则生效期间的全部门控判定。"""

        decisions = self._audit.decisions_of(version)
        return {
            "version": version,
            "decisions": len(decisions),
            "denied": len([item for item in decisions if not item["payload"]["allowed"]]),
            "entries": decisions,
        }

    def replay(self, decision_id: str) -> dict:
        """按判定记录里的版本与事实重放一次，核对能否重现当时结论。"""

        return replay.replay_decision(self._store, self._audit, decision_id)

    def evaluate_at(self, scope: str, facts: Mapping[str, Any], at: float) -> dict:
        """按 ``at`` 时刻生效的版本判定（历史口径回放）。"""

        return replay.evaluate_at(self._store, scope, facts, at)

    # ---- 内部 -----------------------------------------------------------

    def _require_base(self, base_version: int):
        head = self._store.head()
        current = 0 if head is None else head.version
        if current != base_version:
            raise RuleConflictError(
                f"基线版本过期: 调用方基于 v{base_version}，当前已是 v{current}，"
                "请重新拉取后再提交"
            )
        return head

    def _commit(self, version: RuleVersion, action: str) -> dict:
        """提交版本并联动引擎与审计（存储层保证崩溃安全）。"""

        version_hash = self._store.commit(version)
        self._engine.load(version)
        self._audit.record(
            version.author,
            action,
            {
                "version": version.version,
                "id": version.id,
                "version_hash": version_hash,
                "source": version.source,
                "rollback_of": version.rollback_of,
                "reason": version.reason,
            },
        )
        return {**version.summary(), "version_hash": version_hash}
