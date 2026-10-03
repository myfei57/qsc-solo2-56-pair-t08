"""规则审计链。

规则系统自身的审计（提案、生效、回退、每一次门控判定）写成一条哈希链流水：
每条记录带 ``prev_hash`` 指向上一条的 ``hash``，``hash`` 覆盖整条记录内容。
流水只追加不重写，落盘后即不可变——没有更新、删除接口。启动时逐条重算校验，
链断即拒起；运行期任何时刻都可以调 :meth:`RuleAudit.verify` 巡检。

这条链与平台审计（:class:`~psdline.audit.AuditLog`）分工不同：平台审计回答
"系统做了什么"，这条链回答"联锁依据哪一版规则、看了哪些事实、判了什么"，
是回放与定责的唯一依据。
"""

from __future__ import annotations

import threading

from ..clock import Clock
from ..errors import StorageError
from ..store import JsonlJournal
from .model import GENESIS_HASH, hash_payload

ACTION_VALIDATE_FAILED = "validate_failed"
ACTION_ACTIVATE = "activate"
ACTION_ROLLBACK = "rollback"
ACTION_DECISION = "decision"
ACTION_SEED = "seed"


class RuleAudit:
    """哈希链形式的规则审计流水。"""

    def __init__(self, journal: JsonlJournal, clock: Clock) -> None:
        self._journal = journal
        self._clock = clock
        self._lock = threading.RLock()
        self._entries: list[dict] = []
        self._tail_hash = GENESIS_HASH
        self._load()

    def _load(self) -> None:
        records = self._journal.read_all()
        entries = [record for record in records if isinstance(record, dict)]
        broken = _verify(entries)
        if broken is not None:
            raise StorageError(
                f"规则审计链在第 {broken} 条断裂，拒绝启动", component="rules"
            )
        self._entries = entries
        if entries:
            self._tail_hash = str(entries[-1]["hash"])

    def record(self, actor: str, action: str, payload: dict) -> dict:
        """追加一条审计记录，返回落盘后的完整条目。"""

        with self._lock:
            entry = {
                "seq": len(self._entries) + 1,
                "at": self._clock.now(),
                "actor": actor,
                "action": action,
                "payload": payload,
                "prev_hash": self._tail_hash,
            }
            entry["hash"] = hash_payload(entry)
            self._journal.append(entry)
            self._entries.append(entry)
            self._tail_hash = entry["hash"]
            return dict(entry)

    def list(self, action: str | None = None) -> list[dict]:
        """按动作类型过滤列出审计记录。"""

        with self._lock:
            if action is None:
                return [dict(entry) for entry in self._entries]
            return [dict(entry) for entry in self._entries if entry["action"] == action]

    def decisions_of(self, version: int) -> list[dict]:
        """列出某一版规则生效期间的全部门控判定（影响面查询）。"""

        found = []
        for entry in self.list(ACTION_DECISION):
            if entry["payload"].get("version") == version:
                found.append(entry)
        return found

    def find_decision(self, decision_id: str) -> dict | None:
        """按判定标识找一条门控判定记录。"""

        for entry in self.list(ACTION_DECISION):
            if entry["payload"].get("decision_id") == decision_id:
                return entry
        return None

    def verify(self) -> dict:
        """重算整条链，返回校验结果。"""

        with self._lock:
            broken = _verify(self._entries)
            return {
                "ok": broken is None,
                "entries": len(self._entries),
                "broken_at": broken,
                "tail": self._tail_hash,
            }


def _verify(entries: list[dict]) -> int | None:
    """逐条核对链，返回断裂处的序号（从 1 起），完好返回 ``None``。"""

    prev_hash = GENESIS_HASH
    for index, entry in enumerate(entries, start=1):
        if entry.get("seq") != index or entry.get("prev_hash") != prev_hash:
            return index
        stored = entry.get("hash")
        body = {key: value for key, value in entry.items() if key != "hash"}
        if hash_payload(body) != stored:
            return index
        prev_hash = str(stored)
    return None
