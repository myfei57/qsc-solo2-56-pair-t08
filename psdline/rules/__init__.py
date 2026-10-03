"""可配置联锁规则。

把原来写死在代码里的联锁判定条件变成可配置、可校验、带版本的规则：

- :mod:`~psdline.rules.dsl`       表达式 DSL（JSON 树，无 eval）
- :mod:`~psdline.rules.catalog`   事实目录（可引用的现场量与取值限值）
- :mod:`~psdline.rules.validate`  五级校验流水线，不通过不许生效
- :mod:`~psdline.rules.model`     不可变版本与哈希链
- :mod:`~psdline.rules.store`     版本存储：单提交点 + 崩溃恢复
- :mod:`~psdline.rules.audit`     规则审计链（只追加，可校验）
- :mod:`~psdline.rules.engine`    判定引擎与会话钉住（在途作业不换版）
- :mod:`~psdline.rules.service`   服务层：CAS 并发、生效、回退、影响面
- :mod:`~psdline.rules.replay`    按当时版本回放历史判定
"""

from __future__ import annotations

from .audit import RuleAudit
from .catalog import Catalog, FactSpec, build_catalog
from .defaults import DEFAULT_RULEBOOK
from .engine import GateSession, RuleEngine, Verdict, evaluate_content
from .errors import RuleConflictError, RuleError, RuleNotFoundError, RuleValidationError
from .model import RuleVersion
from .service import RuleService
from .store import RuleStore
from .validate import SUPPORTED_SCHEMA, validate_ruleset

__all__ = [
    "Catalog",
    "DEFAULT_RULEBOOK",
    "FactSpec",
    "GateSession",
    "RuleAudit",
    "RuleConflictError",
    "RuleEngine",
    "RuleError",
    "RuleNotFoundError",
    "RuleService",
    "RuleStore",
    "RuleValidationError",
    "RuleVersion",
    "SUPPORTED_SCHEMA",
    "Verdict",
    "build_catalog",
    "evaluate_content",
    "validate_ruleset",
]
