"""规则版本存储。

落盘布局（``<storage_root>/rules/`` 下）：

``versions/000001.json`` 等  不可变版本文档，原子写（临时文件 + fsync + rename）
``journal``                 提交流水（JsonlJournal），每条是一个 commit 记录
``head.json``               当前生效指针，原子写

**提交协议**（崩溃安全的根基）：

1. 写版本文档（fsync + rename）
2. 向提交流水追加 commit 记录（fsync）——**这是唯一的提交点**
3. 重写 head.json（fsync + rename）

崩溃只可能落在三步之间：第 1 步前什么都没有；第 2 步前留下一个无人引用的孤儿
版本文档（无害，永不生效）；第 3 步前 head 落后于流水——启动恢复时用流水最后
一条 commit 重建 head。因此"流水里最后一条 commit"永远是要恢复到的状态，
head.json 只是它的缓存。

启动恢复同时校验整条版本哈希链（从创世到 head），断链或哈希不符说明落盘数据
被改或损坏，拒绝加载——宁可起不来，也不能带着被篡改的联锁规则跑。
"""

from __future__ import annotations

import threading

from ..errors import StorageError
from ..store import JsonStore, JsonlJournal
from .model import GENESIS_HASH, RuleVersion

VERSIONS_PREFIX = "rules/versions"
HEAD_DOC = "rules/head"
JOURNAL_TOPIC = "rules-journal"


class RuleStore:
    """版本化规则存储：只追加，不改写。"""

    def __init__(self, store: JsonStore, journal: JsonlJournal | None = None) -> None:
        self._store = store
        self._journal = journal or JsonlJournal(store.root, JOURNAL_TOPIC)
        self._lock = threading.RLock()
        self._head: RuleVersion | None = None
        self._head_hash = GENESIS_HASH
        self._recover()

    # ---- 查询 ---------------------------------------------------------

    def head(self) -> RuleVersion | None:
        """返回当前生效版本，空库返回 ``None``。"""

        with self._lock:
            return self._head

    def head_hash(self) -> str:
        """返回当前链顶哈希（空库为创世哈希）。"""

        with self._lock:
            return self._head_hash

    def get(self, version: int) -> RuleVersion | None:
        """按版本号读取一个历史版本。"""

        with self._lock:
            if self._head is None or version < 1 or version > self._head.version:
                return None
            return self._load(version)

    def chain(self) -> list[tuple[RuleVersion, str]]:
        """按版本号升序返回（版本, 链上哈希）对。"""

        with self._lock:
            head = self._head
            if head is None:
                return []
            found = []
            for number in range(1, head.version + 1):
                version, _prev, version_hash = self._load_with_hash(number)
                found.append((version, version_hash))
            return found

    def journal_records(self) -> list[dict]:
        """返回提交流水的全部记录（恢复与回放共用）。"""

        return self._journal.read_all()

    # ---- 提交 ---------------------------------------------------------

    def commit(self, version: RuleVersion) -> str:
        """按提交协议让一个版本生效，返回它的链上哈希。

        调用方（服务层）必须保证 ``version.version`` 恰好是 ``head + 1``；
        这里再核一遍，防止并发或重试把链接断。
        """

        with self._lock:
            expected = 1 if self._head is None else self._head.version + 1
            if version.version != expected:
                raise StorageError(
                    f"版本号不连续: 期望 {expected}，得到 {version.version}",
                    component="rules",
                )
            prev_hash = self._head_hash
            document = version.as_dict(prev_hash)
            # 第 1 步：版本文档落盘（原子写）。
            self._store.write(self._version_doc(version.version), document)
            # 第 2 步：提交流水追加 commit 记录 —— 提交点。
            self._journal.append(
                {
                    "op": "commit",
                    "version": version.version,
                    "id": version.id,
                    "version_hash": document["version_hash"],
                    "at": version.created_at,
                    "source": version.source,
                }
            )
            # 第 3 步：刷新 head 指针（崩溃后由恢复逻辑按流水重建）。
            self._store.write(
                HEAD_DOC,
                {"version": version.version, "version_hash": document["version_hash"]},
            )
            self._head = version
            self._head_hash = document["version_hash"]
            return document["version_hash"]

    # ---- 恢复 ---------------------------------------------------------

    @staticmethod
    def _version_doc(number: int) -> str:
        return f"{VERSIONS_PREFIX}/{number:06d}"

    def _load(self, number: int) -> RuleVersion:
        return self._load_with_hash(number)[0]

    def _load_with_hash(self, number: int) -> tuple[RuleVersion, str, str]:
        """读取版本文档并核对内容哈希，返回（版本, prev_hash, version_hash）。"""

        raw = self._store.read(self._version_doc(number))
        if raw is None:
            raise StorageError(f"版本文档缺失: {number}", component="rules")
        try:
            return RuleVersion.from_dict(raw)
        except (ValueError, TypeError) as error:
            raise StorageError(
                f"版本文档 {number} 校验失败: {error}", component="rules"
            ) from error

    def _recover(self) -> None:
        commits = [
            record
            for record in self._journal.read_all()
            if isinstance(record, dict) and record.get("op") == "commit"
        ]
        head_doc = self._store.read(HEAD_DOC)
        if not commits:
            if head_doc is not None:
                raise StorageError(
                    "存在 head 指针但提交流水为空，落盘数据不一致", component="rules"
                )
            return
        last = commits[-1]
        number = int(last.get("version", 0))
        version, _prev, version_hash = self._load_with_hash(number)
        if version_hash != last.get("version_hash"):
            raise StorageError(
                f"提交流水与版本文档不一致: 版本 {number}", component="rules"
            )
        self._verify_chain(version)
        # head.json 落后于流水（崩在第 3 步）时按流水重建。
        expected_head = {"version": version.version, "version_hash": version_hash}
        if head_doc != expected_head:
            self._store.write(HEAD_DOC, expected_head)
        self._head = version
        self._head_hash = version_hash

    def _verify_chain(self, head: RuleVersion) -> None:
        """从创世到 head 逐版本核对链哈希。"""

        prev_hash = GENESIS_HASH
        for number in range(1, head.version + 1):
            version, stored_prev, version_hash = self._load_with_hash(number)
            if version.version != number:
                raise StorageError(
                    f"版本链断裂: 期望版本 {number}，文档内是 {version.version}",
                    component="rules",
                )
            if stored_prev != prev_hash:
                raise StorageError(
                    f"版本 {number} 的前驱哈希对不上，链被篡改", component="rules"
                )
            prev_hash = version_hash
