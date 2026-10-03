"""规则版本与判定的数据模型。

版本状态机：``published``（已发布、未排队）→ ``pending_activation``（等待作业空闲）
→ ``active``（生效中）→ ``superseded``（被取代）。历史版本永不改写、永不删除：
回退不是改历史，而是发布一个内容指回旧版的新版本。内容哈希用规范化 JSON 的
SHA-256，同一内容哈希必然相同，审计里钉住哈希就钉住了"当时是哪份规则"。
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

PUBLISHED = "published"
PENDING = "pending_activation"
ACTIVE = "active"
SUPERSEDED = "superseded"

GATE_DEFERRED = "deferred"
GATE_IMMEDIATE = "immediate"

PERMIT = "permit"
DENY = "deny"


def canonical(content: object) -> str:
    """规范化 JSON：键排序、无空白、拒绝 NaN/Inf，保证同内容同哈希。"""

    return json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def content_hash(content: object) -> str:
    """内容的 SHA-256 哈希。"""

    return hashlib.sha256(canonical(content).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class GatePolicy:
    """生效策略：``deferred`` 等作业空闲后生效；``immediate`` 立即生效（需理由）。"""

    mode: str = GATE_DEFERRED
    reason: str = ""

    def as_dict(self) -> dict:
        return {"mode": self.mode, "reason": self.reason}


@dataclass(frozen=True)
class Quiescence:
    """一次"现场是否空闲"的观测：没有列车在作业才算空闲。"""

    quiescent: bool
    busy: tuple[str, ...] = ()

    def as_dict(self) -> dict:
        return {"quiescent": self.quiescent, "busy": list(self.busy)}


@dataclass
class RuleSetVersion:
    """一份已发布的规则集版本（内容不可变）。"""

    version: int
    content: dict
    hash: str
    schema_version: int
    status: str
    base_version: int
    origin: dict
    published_at: float
    published_by: str
    activated_at: float = 0.0
    superseded_at: float = 0.0

    def as_dict(self) -> dict:
        return {
            "version": self.version,
            "hash": self.hash,
            "schema_version": self.schema_version,
            "status": self.status,
            "base_version": self.base_version,
            "origin": dict(self.origin),
            "published_at": self.published_at,
            "published_by": self.published_by,
            "activated_at": self.activated_at,
            "superseded_at": self.superseded_at,
            "rules": len(self.content.get("rules", [])),
        }


@dataclass
class Draft:
    """规则草稿：发布前的工作区，可反复改；草稿不是历史，历史从发布开始。"""

    draft_id: str
    base_version: int
    content: dict
    report: dict
    actor: str
    updated_at: float

    def as_dict(self) -> dict:
        return {
            "draft_id": self.draft_id,
            "base_version": self.base_version,
            "valid": bool(self.report.get("valid")),
            "errors": len(self.report.get("errors", [])),
            "warnings": len(self.report.get("warnings", [])),
            "actor": self.actor,
            "updated_at": self.updated_at,
        }


@dataclass
class Decision:
    """一次门控判定结论。"""

    allowed: bool
    effect: str
    command: str
    reason: str
    version: int = 0
    hash: str = ""
    matched: int = 0
    fired: list = field(default_factory=list)
    errors: list = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "effect": self.effect,
            "command": self.command,
            "reason": self.reason,
            "version": self.version,
            "hash": self.hash,
            "matched": self.matched,
            "fired": [dict(item) for item in self.fired],
            "errors": list(self.errors),
        }
