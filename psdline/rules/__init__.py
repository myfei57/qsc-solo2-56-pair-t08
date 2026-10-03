"""联锁规则：把判定条件从代码里搬进可校验、可版本化的数据。

- :mod:`~psdline.rules.expr`     条件表达式树（纯函数求值）
- :mod:`~psdline.rules.catalog`  现场事实目录（类型与取值范围）
- :mod:`~psdline.rules.validate` 发布前的语法/取值/冲突校验
- :mod:`~psdline.rules.store`    版本化存储（单记录提交点、回放重建、撕裂修复）
- :mod:`~psdline.rules.engine`   判定引擎（拒绝优先、出错即拒、按结构版本分派）
- :mod:`~psdline.rules.service`  全生命周期门面（草稿/发布/生效/回退/回放）
"""

from __future__ import annotations

from .catalog import FactCatalog, FactDef, default_catalog
from .engine import decide
from .expr import ExprError, evaluate
from .model import (
    ACTIVE,
    DENY,
    GATE_DEFERRED,
    GATE_IMMEDIATE,
    PENDING,
    PERMIT,
    PUBLISHED,
    SUPERSEDED,
    Decision,
    GatePolicy,
    Quiescence,
    RuleSetVersion,
    content_hash,
)
from .service import RulePolicy, RuleService
from .store import RuleStore, repair_journal_tail
from .validate import SUPPORTED_SCHEMA, Issue, ValidationReport, validate_ruleset

__all__ = [
    "ACTIVE",
    "DENY",
    "Decision",
    "ExprError",
    "FactCatalog",
    "FactDef",
    "GATE_DEFERRED",
    "GATE_IMMEDIATE",
    "GatePolicy",
    "Issue",
    "PENDING",
    "PERMIT",
    "PUBLISHED",
    "Quiescence",
    "RulePolicy",
    "RuleService",
    "RuleSetVersion",
    "RuleStore",
    "SUPPORTED_SCHEMA",
    "SUPERSEDED",
    "ValidationReport",
    "content_hash",
    "decide",
    "default_catalog",
    "evaluate",
    "repair_journal_tail",
    "validate_ruleset",
]
