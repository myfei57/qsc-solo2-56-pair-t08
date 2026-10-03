"""历史回放：按当时的版本重算。

两条入口：

- :func:`replay_decision` 按审计链里的判定记录回放——记录里有版本号与当时的
  事实快照，用对应版本的内容重算，结论必须与记录一致（判定器是确定性的，
  不一致说明数据被改或求值逻辑变了，都是必须报警的事）。
- :func:`evaluate_at` 按时间戳回放——从提交流水找出该时刻生效的版本，用它
  判定给定事实。

回放绝不使用当前生效版本：规则已经换过几轮，用新版算旧账得出的"不一致"
没有意义。
"""

from __future__ import annotations

from typing import Any, Mapping

from .engine import evaluate_content
from .errors import RuleNotFoundError
from .store import RuleStore


def _load_content(store: RuleStore, version: int) -> dict:
    found = store.get(version)
    if found is None:
        raise RuleNotFoundError(f"版本不存在: {version}")
    return found.content


def replay_decision(store: RuleStore, audit, decision_id: str) -> dict:
    """重放一条历史判定，返回当时结论与重算结论的对照。"""

    entry = audit.find_decision(decision_id)
    if entry is None:
        raise RuleNotFoundError(f"判定记录不存在: {decision_id}")
    payload = entry["payload"]
    version = int(payload["version"])
    content = _load_content(store, version)
    verdict = evaluate_content(
        content, str(payload["scope"]), payload.get("facts", {}), version
    )
    reproduced = verdict.allowed == bool(payload["allowed"]) and [
        rule["id"] for rule in verdict.matched
    ] == [rule["id"] for rule in payload.get("matched", [])]
    return {
        "decision_id": decision_id,
        "version": version,
        "recorded": {
            "allowed": bool(payload["allowed"]),
            "matched": [rule["id"] for rule in payload.get("matched", [])],
        },
        "replayed": verdict.as_dict(),
        "reproduced": reproduced,
    }


def evaluate_at(store: RuleStore, scope: str, facts: Mapping[str, Any], at: float) -> dict:
    """找出 ``at`` 时刻生效的版本并判定。"""

    commits = [
        record
        for record in store.journal_records()
        if isinstance(record, dict) and record.get("op") == "commit"
    ]
    chosen = None
    for record in commits:
        if float(record.get("at", 0.0)) <= at:
            chosen = record
        else:
            break
    if chosen is None:
        raise RuleNotFoundError(f"时刻 {at} 之前没有任何生效版本")
    version = int(chosen["version"])
    content = _load_content(store, version)
    verdict = evaluate_content(content, scope, facts, version)
    return {"version": version, "at": at, "verdict": verdict.as_dict()}
