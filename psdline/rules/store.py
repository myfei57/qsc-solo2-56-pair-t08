"""规则版本存储。

所有状态迁移都折叠成**一条**只追加流水记录：记录落盘（fsync）即提交，不存在
"写了一半"的中间态，因此部分失败只有两种形态——整条没写上（客户端用同一个
``op_id`` 重试，幂等完成）或最后一条记录撕裂（重启时截断尾行）。重启按序回放
同一份流水重建状态，版本号、生效指针、待生效指针、生效历史全部来自流水，没有
第二份需要保持一致的状态。

事件种类：

- ``DRAFT_SAVED``           草稿保存（草稿是工作区，可覆盖；历史从发布开始）
- ``PUBLISHED``             发布；``gate=immediate`` 时同一条记录原子完成生效
- ``ACTIVATION_REQUESTED``  重新排队等待生效（取消之后）
- ``ACTIVATED``             延迟/强制生效（立即生效不走这条，它随 PUBLISHED 原子完成）
- ``ACTIVATION_CANCELLED``  取消待生效
"""

from __future__ import annotations

import json
import os
import threading
from typing import Any

from ..errors import StorageError
from ..store import JsonlJournal
from .model import ACTIVE, PENDING, PUBLISHED, SUPERSEDED, Draft, RuleSetVersion, content_hash

TOPIC = "rules"

KIND_DRAFT = "DRAFT_SAVED"
KIND_PUBLISHED = "PUBLISHED"
KIND_REQUESTED = "ACTIVATION_REQUESTED"
KIND_ACTIVATED = "ACTIVATED"
KIND_CANCELLED = "ACTIVATION_CANCELLED"


def repair_journal_tail(root: str, topic: str = TOPIC) -> dict:
    """修复掉电撕裂的尾行：最后一行写了一半就截掉；中间行损坏说明文件被
    动过，抛 :class:`StorageError` 而不是悄悄修复——流水中间被改是必须人工
    介入的事件。返回修复报告，供调用方落审计。"""

    report = {"topic": topic, "truncated_bytes": 0, "truncated_at": "", "ok": True}
    index = 0
    last_path = ""
    while True:
        path = os.path.join(root, f"{topic}-{index:05d}.jsonl")
        if not os.path.isfile(path):
            break
        last_path = path
        index += 1
    if not last_path:
        return report
    good_end = 0
    corrupted_at = 0
    trailing = b""
    with open(last_path, "rb") as handle:
        while True:
            offset = handle.tell()
            line = handle.readline()
            if not line:
                break
            if not line.endswith(b"\n"):
                corrupted_at = offset
                break
            try:
                json.loads(line.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError):
                corrupted_at = offset
                trailing = handle.read()
                break
            good_end = handle.tell()
    if not corrupted_at:
        return report
    if trailing.strip():
        # 坏行后面还有好行：不是掉电撕裂，是文件被动过，必须人工介入。
        raise StorageError(f"流水中间损坏，拒绝自动修复: {last_path}", component="store")
    size = os.path.getsize(last_path)
    with open(last_path, "r+b") as handle:
        handle.truncate(good_end)
    report.update(
        truncated_bytes=size - good_end,
        truncated_at=last_path,
        ok=False,
    )
    return report


class RuleStore:
    """规则版本存储：内存状态 + 只追加流水，回放重建。"""

    def __init__(self, journal: JsonlJournal) -> None:
        self._journal = journal
        self._lock = threading.RLock()
        self._drafts: dict[str, Draft] = {}
        self._versions: dict[int, RuleSetVersion] = {}
        self._active = 0
        self._pending = 0
        self._history: list[tuple[float, int, int]] = []
        self._applied: dict[str, Any] = {}
        self._seq = 0
        for record in journal.read_all():
            self._apply(record)

    # ---- 查询 ---------------------------------------------------------

    def get_draft(self, draft_id: str) -> Draft | None:
        with self._lock:
            return self._drafts.get(draft_id)

    def drafts(self) -> list[Draft]:
        with self._lock:
            return sorted(self._drafts.values(), key=lambda draft: draft.updated_at)

    def get_version(self, version: int) -> RuleSetVersion | None:
        with self._lock:
            return self._versions.get(version)

    def versions(self) -> list[RuleSetVersion]:
        with self._lock:
            return [self._versions[number] for number in sorted(self._versions)]

    def active(self) -> RuleSetVersion | None:
        with self._lock:
            return self._versions.get(self._active)

    def pending(self) -> RuleSetVersion | None:
        with self._lock:
            return self._versions.get(self._pending)

    def latest_version_number(self) -> int:
        with self._lock:
            return max(self._versions, default=0)

    def version_at(self, at: float) -> RuleSetVersion | None:
        """返回某一时刻生效的版本（回放旧记录用）。"""

        with self._lock:
            chosen = 0
            for activated_at, seq, version in self._history:
                if activated_at <= at:
                    chosen = version
                else:
                    break
            return self._versions.get(chosen)

    def applied(self, op_id: str) -> Any | None:
        """查询一个操作标识是否已应用；已应用则返回当时的结果（崩溃重试用）。"""

        with self._lock:
            return self._applied.get(op_id)

    # ---- 迁移（每个都是单记录提交点） ---------------------------------

    def save_draft(
        self,
        draft_id: str,
        base_version: int,
        content: dict,
        report: dict,
        actor: str,
        at: float,
        op_id: str,
    ) -> Draft:
        payload = {
            "draft_id": draft_id,
            "base_version": base_version,
            "content": content,
            "report": report,
            "actor": actor,
            "at": at,
            "op_id": op_id,
        }
        self._commit(KIND_DRAFT, payload)
        draft = self.get_draft(draft_id)
        assert draft is not None
        return draft

    def publish(
        self,
        draft_id: str,
        base_version: int,
        content: dict,
        schema_version: int,
        gate: str,
        origin: dict,
        actor: str,
        at: float,
        op_id: str,
        quiescence: dict | None = None,
    ) -> int:
        """发布新版本，返回版本号；``gate=immediate`` 时同记录原子生效。"""

        with self._lock:
            if op_id in self._applied:
                return int(self._applied[op_id]["version"])
            version = self.latest_version_number() + 1
            payload = {
                "version": version,
                "draft_id": draft_id,
                "base_version": base_version,
                "content": content,
                "hash": content_hash(content),
                "schema_version": schema_version,
                "gate": gate,
                "origin": origin,
                "actor": actor,
                "at": at,
                "op_id": op_id,
                "quiescence": quiescence,
            }
            self._commit(KIND_PUBLISHED, payload)
            return version

    def request_activation(self, version: int, actor: str, at: float, op_id: str) -> None:
        self._commit(
            KIND_REQUESTED, {"version": version, "actor": actor, "at": at, "op_id": op_id}
        )

    def activate(
        self,
        version: int,
        mode: str,
        quiescence: dict,
        actor: str,
        at: float,
        op_id: str,
        reason: str = "",
    ) -> None:
        self._commit(
            KIND_ACTIVATED,
            {
                "version": version,
                "mode": mode,
                "quiescence": quiescence,
                "actor": actor,
                "at": at,
                "op_id": op_id,
                "reason": reason,
            },
        )

    def cancel_pending(self, actor: str, at: float, op_id: str, reason: str = "") -> None:
        with self._lock:
            self._commit(
                KIND_CANCELLED,
                {
                    "version": self._pending,
                    "actor": actor,
                    "at": at,
                    "op_id": op_id,
                    "reason": reason,
                },
            )

    # ---- 内部 ---------------------------------------------------------

    def _commit(self, kind: str, payload: dict) -> None:
        """写一条流水并应用；op_id 已应用过则直接跳过（崩溃重试幂等）。"""

        with self._lock:
            op_id = str(payload.get("op_id", ""))
            if op_id and op_id in self._applied:
                return
            record = {"kind": kind, "payload": payload}
            self._journal.append(record)
            self._apply(record)

    def _apply(self, record: dict) -> None:
        kind = record.get("kind")
        payload = record.get("payload", {})
        self._seq += 1
        op_id = str(payload.get("op_id", ""))
        if op_id and op_id in self._applied:
            return
        if kind == KIND_DRAFT:
            self._drafts[payload["draft_id"]] = Draft(
                draft_id=payload["draft_id"],
                base_version=int(payload["base_version"]),
                content=payload["content"],
                report=payload.get("report", {}),
                actor=str(payload.get("actor", "")),
                updated_at=float(payload.get("at", 0.0)),
            )
            result: Any = {"draft_id": payload["draft_id"]}
        elif kind == KIND_PUBLISHED:
            version = int(payload["version"])
            self._versions[version] = RuleSetVersion(
                version=version,
                content=payload["content"],
                hash=str(payload["hash"]),
                schema_version=int(payload["schema_version"]),
                status=PUBLISHED,
                base_version=int(payload["base_version"]),
                origin=dict(payload.get("origin", {})),
                published_at=float(payload.get("at", 0.0)),
                published_by=str(payload.get("actor", "")),
            )
            if payload.get("gate") == "immediate":
                self._activate_locked(
                    version,
                    float(payload.get("at", 0.0)),
                    quiescence=payload.get("quiescence"),
                )
            else:
                self._pending = version
                self._versions[version].status = PENDING
            result = {"version": version}
        elif kind == KIND_REQUESTED:
            version = int(payload["version"])
            if version in self._versions and self._versions[version].status == PUBLISHED:
                self._pending = version
                self._versions[version].status = PENDING
            result = {"version": version}
        elif kind == KIND_ACTIVATED:
            self._activate_locked(
                int(payload["version"]),
                float(payload.get("at", 0.0)),
                quiescence=payload.get("quiescence"),
            )
            result = {"version": int(payload["version"])}
        elif kind == KIND_CANCELLED:
            version = int(payload.get("version", 0))
            if self._pending == version:
                self._pending = 0
                if version in self._versions:
                    self._versions[version].status = PUBLISHED
            result = {"version": version}
        else:  # pragma: no cover - 流水里出现未知种类说明文件被改过
            raise StorageError(f"未知的规则流水事件: {kind!r}", component="store")
        if op_id:
            self._applied[op_id] = result

    def _activate_locked(self, version: int, at: float, quiescence: Any = None) -> None:
        target = self._versions.get(version)
        if target is None:
            raise StorageError(f"要生效的版本不存在: {version}", component="store")
        previous = self._versions.get(self._active)
        if previous is not None:
            previous.status = SUPERSEDED
            previous.superseded_at = at
        target.status = ACTIVE
        target.activated_at = at
        self._active = version
        if self._pending == version:
            self._pending = 0
        self._history.append((at, self._seq, version))
