"""规则版本模型。

每次生效（含回退）都产生一个不可变的 :class:`RuleVersion`。版本之间用哈希链
连接：``version_hash`` 覆盖版本头与内容哈希，``prev_hash`` 指向上一版本的
``version_hash``。任何对历史版本内容或元数据的篡改都会让哈希对不上，启动校验
时拒绝加载。回退不是把指针拨回去，而是生成一个内容等于目标版本的新版本——
历史只能追加，不能改写。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

GENESIS_HASH = "0" * 64

SOURCE_SEED = "seed"
SOURCE_PROPOSE = "propose"
SOURCE_ROLLBACK = "rollback"
SOURCES = (SOURCE_SEED, SOURCE_PROPOSE, SOURCE_ROLLBACK)


def canonical(payload: Any) -> str:
    """把负载转成规范 JSON 串（键排序、无空白），供哈希与落盘。"""

    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def hash_payload(payload: Any) -> str:
    """计算负载的 SHA-256 十六进制摘要。"""

    return hashlib.sha256(canonical(payload).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class RuleVersion:
    """一个不可变的规则版本。"""

    version: int
    created_at: float
    author: str
    reason: str
    source: str
    content: dict
    rollback_of: int | None = None

    @property
    def content_hash(self) -> str:
        """规则内容的摘要，版本标识的一部分。"""

        return hash_payload(self.content)

    @property
    def id(self) -> str:
        return f"rv{self.version:06d}-{self.content_hash[:8]}"

    def header(self) -> dict:
        """版本头（不含内容），参与版本哈希。"""

        return {
            "version": self.version,
            "id": self.id,
            "created_at": self.created_at,
            "author": self.author,
            "reason": self.reason,
            "source": self.source,
            "rollback_of": self.rollback_of,
            "content_hash": self.content_hash,
        }

    def version_hash(self, prev_hash: str) -> str:
        """把版本头与前驱哈希链起来算出版本哈希。"""

        return hash_payload({"header": self.header(), "prev_hash": prev_hash})

    def as_dict(self, prev_hash: str) -> dict:
        """落盘格式：版本头 + 链指针 + 版本哈希 + 完整内容。"""

        return {
            **self.header(),
            "prev_hash": prev_hash,
            "version_hash": self.version_hash(prev_hash),
            "content": self.content,
        }

    def summary(self, prev_hash: str | None = None) -> dict:
        """列表用的摘要，不带规则内容。"""

        payload = self.header()
        if prev_hash is not None:
            payload["version_hash"] = self.version_hash(prev_hash)
        return payload

    @classmethod
    def from_dict(cls, payload: dict) -> tuple["RuleVersion", str, str]:
        """从落盘文档还原版本，返回（版本, prev_hash, version_hash）。

        文档里的 ``content_hash`` 与 ``version_hash`` 都会被重算核对，对不上
        说明落盘数据被改过，抛 :class:`ValueError` 由存储层转成存储异常。
        """

        if not isinstance(payload, dict):
            raise ValueError("版本文档必须是对象")
        content = payload.get("content")
        if not isinstance(content, dict):
            raise ValueError("版本文档缺少规则内容")
        version = cls(
            version=int(payload.get("version", 0)),
            created_at=float(payload.get("created_at", 0.0)),
            author=str(payload.get("author", "")),
            reason=str(payload.get("reason", "")),
            source=str(payload.get("source", "")),
            content=content,
            rollback_of=payload.get("rollback_of"),
        )
        if version.source not in SOURCES:
            raise ValueError(f"未知版本来源: {version.source}")
        if payload.get("content_hash") != version.content_hash:
            raise ValueError(f"版本 {version.version} 内容哈希对不上，数据可能被篡改")
        prev_hash = str(payload.get("prev_hash", ""))
        version_hash = version.version_hash(prev_hash)
        if payload.get("version_hash") != version_hash:
            raise ValueError(f"版本 {version.version} 链哈希对不上，数据可能被篡改")
        return version, prev_hash, version_hash
