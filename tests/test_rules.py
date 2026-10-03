"""联锁规则：DSL、校验、版本存储、审计链、门控会话、回放与平台集成。"""

from __future__ import annotations

import json

import pytest

from psdline.clock import ManualClock
from psdline.config import default_config
from psdline.errors import StorageError
from psdline.rules import (
    DEFAULT_RULEBOOK,
    RuleAudit,
    RuleConflictError,
    RuleEngine,
    RuleNotFoundError,
    RuleService,
    RuleStore,
    RuleValidationError,
    build_catalog,
    validate_ruleset,
)
from psdline.rules import dsl
from psdline.store import JsonStore, JsonlJournal


# ---- 夹具 ---------------------------------------------------------------


def _catalog():
    return build_catalog(default_config())


def _service(tmp_path, clock=None):
    clock = clock or ManualClock()
    store = JsonStore(str(tmp_path / "state"))
    rule_store = RuleStore(store)
    audit = RuleAudit(JsonlJournal(store.root, "rules-audit"), clock)
    engine = RuleEngine(clock, store=store)
    service = RuleService(rule_store, audit, engine, _catalog(), clock)
    return service, rule_store, audit, engine, clock


def _book(**overrides):
    """构造一份最小合法规则簿，可按需覆盖。"""

    book = {
        "schema": 1,
        "scopes": {
            "depart": {
                "default_effect": "deny",
                "rules": [
                    {
                        "id": "depart.gap_blocked",
                        "effect": "deny",
                        "reason": "间隙探测未确认",
                        "when": {"op": "not", "args": [{"fact": "gap.clear"}]},
                    },
                    {
                        "id": "depart.ready",
                        "effect": "allow",
                        "reason": "间隙已确认",
                        "when": {"fact": "gap.clear"},
                    },
                ],
            }
        },
    }
    book.update(overrides)
    return book


# ---- DSL -----------------------------------------------------------------


def test_dsl_evaluates_facts_and_logic():
    tree = dsl.parse(
        {"op": "and", "args": [{"fact": "a"}, {"op": "not", "args": [{"fact": "b"}]}]}
    )
    assert tree.evaluate({"a": True, "b": False}) is True
    assert tree.evaluate({"a": True, "b": True}) is False
    assert tree.facts_used() == {"a", "b"}


def test_dsl_short_circuits_or():
    tree = dsl.parse({"op": "or", "args": [{"fact": "a"}, {"fact": "missing"}]})
    assert tree.evaluate({"a": True}) is True
    with pytest.raises(dsl.FactMissing):
        tree.evaluate({"a": False})


def test_dsl_compares_numbers_and_membership():
    ge = dsl.parse({"op": "ge", "args": [{"fact": "pos"}, {"const": 100}]})
    assert ge.evaluate({"pos": 100}) is True
    assert ge.evaluate({"pos": 99}) is False
    member = dsl.parse({"op": "in", "args": [{"fact": "aspect"}, {"const": ["green", "yellow"]}]})
    assert member.evaluate({"aspect": "yellow"}) is True
    assert member.evaluate({"aspect": "red"}) is False


def test_dsl_rejects_bad_structure_and_types():
    with pytest.raises(dsl.RuleEvalError):
        dsl.parse({"op": "hack", "args": []})
    with pytest.raises(dsl.RuleEvalError):
        dsl.parse({"fact": 42})
    with pytest.raises(dsl.RuleEvalError):
        dsl.parse("not-a-node")
    not_tree = dsl.parse({"op": "not", "args": [{"fact": "n"}]})
    with pytest.raises(dsl.RuleEvalError):
        not_tree.evaluate({"n": 3})
    lt = dsl.parse({"op": "lt", "args": [{"fact": "a"}, {"fact": "b"}]})
    with pytest.raises(dsl.RuleEvalError):
        lt.evaluate({"a": True, "b": 1})


def test_dsl_bool_is_not_number():
    eq = dsl.parse({"op": "eq", "args": [{"fact": "x"}, {"const": 1}]})
    with pytest.raises(dsl.RuleEvalError):
        eq.evaluate({"x": True})
    assert eq.evaluate({"x": 1}) is True


# ---- 校验 -----------------------------------------------------------------


def test_validate_accepts_default_rulebook():
    result = validate_ruleset(DEFAULT_RULEBOOK, _catalog())
    assert result.ok, result.issues


def test_validate_rejects_bad_syntax():
    assert validate_ruleset("nope", _catalog()).stage == "syntax"
    assert validate_ruleset({"schema": "1", "scopes": {}}, _catalog()).stage == "syntax"
    future = _book(schema=99)
    result = validate_ruleset(future, _catalog())
    assert result.stage == "syntax"
    assert any(issue["code"] == "unsupported_schema" for issue in result.issues)
    no_scopes = _book(scopes={})
    assert validate_ruleset(no_scopes, _catalog()).stage == "syntax"


def test_validate_rejects_duplicate_ids_and_missing_reason():
    book = _book()
    rules = book["scopes"]["depart"]["rules"]
    rules.append(dict(rules[0]))
    result = validate_ruleset(book, _catalog())
    assert result.stage == "syntax"
    assert any(issue["code"] == "duplicate_id" for issue in result.issues)

    book = _book()
    del book["scopes"]["depart"]["rules"][0]["reason"]
    result = validate_ruleset(book, _catalog())
    assert any(issue["code"] == "missing_reason" for issue in result.issues)


def test_validate_rejects_unsafe_default_allow():
    book = _book()
    book["scopes"]["depart"]["default_effect"] = "allow"
    result = validate_ruleset(book, _catalog())
    assert result.stage == "syntax"
    assert any(issue["code"] == "unsafe_default" for issue in result.issues)


def test_validate_rejects_bad_expression_schema():
    book = _book()
    book["scopes"]["depart"]["rules"][0]["when"] = {"op": "not", "args": []}
    assert validate_ruleset(book, _catalog()).stage == "schema"
    book = _book()
    book["scopes"]["depart"]["rules"][0]["when"] = {"op": "wat", "args": []}
    assert validate_ruleset(book, _catalog()).stage == "schema"
    book = _book()
    book["scopes"]["depart"]["rules"][0]["when"] = {
        "op": "in",
        "args": [{"fact": "signal.aspect"}, {"fact": "signal.aspect"}],
    }
    result = validate_ruleset(book, _catalog())
    assert result.stage == "schema"
    assert any(issue["code"] == "bad_member" for issue in result.issues)


def test_validate_rejects_unknown_fact_and_type_mismatch():
    book = _book()
    book["scopes"]["depart"]["rules"][0]["when"] = {"fact": "no.such.fact"}
    result = validate_ruleset(book, _catalog())
    assert result.stage == "semantic"
    assert any(issue["code"] == "unknown_fact" for issue in result.issues)

    book = _book()
    book["scopes"]["depart"]["rules"][0]["when"] = {
        "op": "lt",
        "args": [{"fact": "gap.clear"}, {"const": 3}],
    }
    result = validate_ruleset(book, _catalog())
    assert result.stage == "semantic"
    assert any(issue["code"] == "bad_operand" for issue in result.issues)


def test_validate_rejects_out_of_range_values():
    book = _book()
    book["scopes"]["depart"]["rules"][0]["when"] = {
        "op": "gt",
        "args": [{"fact": "train.dwell_s"}, {"const": 99999}],
    }
    result = validate_ruleset(book, _catalog())
    assert result.stage == "range"
    assert any(issue["code"] == "bad_value" for issue in result.issues)

    book = _book()
    book["scopes"]["depart"]["rules"][0]["when"] = {
        "op": "eq",
        "args": [{"fact": "signal.aspect"}, {"const": "purple"}],
    }
    result = validate_ruleset(book, _catalog())
    assert result.stage == "range"

    book = _book()
    book["scopes"]["depart"]["rules"][0]["when"] = {
        "op": "in",
        "args": [{"fact": "signal.aspect"}, {"const": ["green", "purple"]}],
    }
    assert validate_ruleset(book, _catalog()).stage == "range"


def test_validate_rejects_constant_condition():
    book = _book()
    book["scopes"]["depart"]["rules"][0]["when"] = {"const": True}
    result = validate_ruleset(book, _catalog())
    assert result.stage == "safety"
    assert any(issue["code"] == "constant_condition" for issue in result.issues)


# ---- 版本存储与崩溃恢复 -----------------------------------------------------


def test_store_commit_and_chain(tmp_path):
    service, store, _audit, _engine, _clock = _service(tmp_path)
    service.seed(_book(), author="test", reason="init")
    head = store.head()
    assert head is not None and head.version == 1
    service.activate(_book(), base_version=1, author="a", reason="noop")
    assert store.head().version == 2
    chain = store.chain()
    assert [version.version for version, _hash in chain] == [1, 2]
    assert store.get(1).content == _book()
    assert store.get(99) is None


def test_store_recovers_head_from_journal(tmp_path):
    service, store, _audit, _engine, _clock = _service(tmp_path)
    service.seed(_book(), author="test", reason="init")
    # 模拟崩在第 3 步：删掉 head 指针，留下已提交的流水。
    doc_store = JsonStore(str(tmp_path / "state"))
    doc_store.remove("rules/head")
    rebuilt = RuleStore(JsonStore(str(tmp_path / "state")))
    assert rebuilt.head() is not None and rebuilt.head().version == 1


def test_store_ignores_orphan_version_doc(tmp_path):
    service, store, _audit, _engine, _clock = _service(tmp_path)
    service.seed(_book(), author="test", reason="init")
    # 模拟崩在第 2 步：版本文档写了，流水没提交。
    doc_store = JsonStore(str(tmp_path / "state"))
    orphan = store.head().as_dict(store.head_hash())
    orphan["version"] = 2
    doc_store.write("rules/versions/000002", orphan)
    rebuilt = RuleStore(JsonStore(str(tmp_path / "state")))
    assert rebuilt.head().version == 1


def test_store_rejects_tampered_version(tmp_path):
    service, _store, _audit, _engine, _clock = _service(tmp_path)
    service.seed(_book(), author="test", reason="init")
    doc_store = JsonStore(str(tmp_path / "state"))
    raw = doc_store.read("rules/versions/000001")
    raw["content"]["scopes"]["depart"]["default_effect"] = "allow"
    doc_store.write("rules/versions/000001", raw)
    with pytest.raises(StorageError):
        RuleStore(JsonStore(str(tmp_path / "state")))


def test_store_rejects_broken_chain(tmp_path):
    service, _store, _audit, _engine, _clock = _service(tmp_path)
    service.seed(_book(), author="test", reason="init")
    service.activate(_book(), base_version=1, author="a", reason="v2")
    doc_store = JsonStore(str(tmp_path / "state"))
    doc_store.remove("rules/versions/000001")
    with pytest.raises(StorageError):
        RuleStore(JsonStore(str(tmp_path / "state")))


# ---- 审计链 ----------------------------------------------------------------


def test_audit_chain_verifies_and_detects_tamper(tmp_path):
    service, _store, audit, _engine, _clock = _service(tmp_path)
    service.seed(_book(), author="test", reason="init")
    service.activate(_book(), base_version=1, author="a", reason="v2")
    assert audit.verify()["ok"] is True
    entries = audit.list()
    assert [entry["action"] for entry in entries] == ["seed", "activate"]
    # 篡改落盘流水：重载时必须断链拒起。
    path = audit._journal.segments()[0]
    lines = [json.loads(line) for line in open(path, encoding="utf-8") if line.strip()]
    lines[0]["payload"]["reason"] = "篡改"
    with open(path, "w", encoding="utf-8") as handle:
        for line in lines:
            handle.write(json.dumps(line, ensure_ascii=False) + "\n")
    with pytest.raises(StorageError):
        RuleAudit(JsonlJournal(str(tmp_path / "state"), "rules-audit"), ManualClock())


# ---- 服务：生效、并发、回退 ---------------------------------------------------


def test_activate_requires_valid_content_and_audits_failure(tmp_path):
    service, _store, audit, _engine, _clock = _service(tmp_path)
    service.seed(_book(), author="test", reason="init")
    bad = _book()
    bad["scopes"]["depart"]["rules"][0]["when"] = {"fact": "no.such.fact"}
    with pytest.raises(RuleValidationError) as error:
        service.activate(bad, base_version=1, author="op", reason="bad")
    assert error.value.issues
    failed = audit.list("validate_failed")
    assert len(failed) == 1 and failed[0]["payload"]["intent"] == "activate"
    assert service.current()["version"]["version"] == 1


def test_activate_conflict_on_stale_base_version(tmp_path):
    service, _store, _audit, _engine, _clock = _service(tmp_path)
    service.seed(_book(), author="test", reason="init")
    service.activate(_book(), base_version=1, author="a", reason="v2")
    with pytest.raises(RuleConflictError):
        service.activate(_book(), base_version=1, author="b", reason="并发")
    with pytest.raises(RuleConflictError):
        service.rollback(1, base_version=1, author="b", reason="并发")


def test_rollback_creates_new_version_without_rewriting_history(tmp_path):
    service, store, audit, _engine, _clock = _service(tmp_path)
    service.seed(_book(), author="test", reason="init")
    changed = _book()
    changed["scopes"]["depart"]["rules"].append(
        {
            "id": "depart.dwell_min",
            "effect": "deny",
            "reason": "停站时间不足",
            "when": {"op": "lt", "args": [{"fact": "train.dwell_s"}, {"const": 30}]},
        }
    )
    service.activate(changed, base_version=1, author="a", reason="加停站约束")
    result = service.rollback(1, base_version=2, author="b", reason="回退")
    assert result["version"] == 3
    assert result["source"] == "rollback"
    assert result["rollback_of"] == 1
    history = service.history()
    assert [item["version"] for item in history] == [1, 2, 3]
    assert store.get(3).content == store.get(1).content
    assert store.get(2).content == changed  # 历史版本不被改写
    actions = [entry["action"] for entry in audit.list()]
    assert actions == ["seed", "activate", "rollback"]


def test_rollback_rejects_missing_target_and_incompatible_content(tmp_path):
    service, _store, _audit, _engine, _clock = _service(tmp_path)
    service.seed(_book(), author="test", reason="init")
    with pytest.raises(RuleNotFoundError):
        service.rollback(9, base_version=1, author="a", reason="x")

    # 模拟配置演进：目录里退役了 gap.clear，旧版本内容在新口径下不合法。
    catalog = _catalog()
    shrunk = type(catalog)(
        facts={name: spec for name, spec in catalog.facts.items() if name != "gap.clear"}
    )
    store2 = RuleStore(JsonStore(str(tmp_path / "state")))
    audit2 = RuleAudit(JsonlJournal(str(tmp_path / "state"), "rules-audit"), ManualClock())
    engine2 = RuleEngine(ManualClock())
    evolved = RuleService(store2, audit2, engine2, shrunk, ManualClock())
    with pytest.raises(RuleValidationError):
        evolved.rollback(1, base_version=1, author="a", reason="回退到退役事实")


def test_seed_only_on_empty_store(tmp_path):
    service, _store, _audit, _engine, _clock = _service(tmp_path)
    service.seed(_book(), author="test", reason="init")
    with pytest.raises(RuleConflictError):
        service.seed(_book(), author="test", reason="again")


def test_activate_failure_before_commit_leaves_no_trace(tmp_path):
    service, store, _audit, _engine, _clock = _service(tmp_path)
    service.seed(_book(), author="test", reason="init")
    # 模拟提交流水写失败（崩在提交点前）：激活整体失败，库保持 v1，可安全重试。
    original = store._journal.append

    def broken(_record):
        raise StorageError("模拟磁盘写失败", component="rules")

    store._journal.append = broken
    with pytest.raises(StorageError):
        service.activate(_book(), base_version=1, author="a", reason="v2")
    store._journal.append = original
    assert store.head().version == 1
    rebuilt = RuleStore(JsonStore(str(tmp_path / "state")))
    assert rebuilt.head().version == 1
    service.activate(_book(), base_version=1, author="a", reason="v2")
    assert store.head().version == 2


def test_activate_crash_after_commit_recovers_on_reload(tmp_path):
    service, store, _audit, _engine, _clock = _service(tmp_path)
    service.seed(_book(), author="test", reason="init")
    # 模拟崩在提交点后（head 指针写失败）：调用方看到错误，但提交点已过，
    # 重启恢复后版本实际已生效——提交流水是唯一事实来源。
    doc_store = JsonStore(str(tmp_path / "state"))
    original_write = doc_store.write

    def broken_head(doc_id, payload):
        if doc_id == "rules/head":
            raise StorageError("模拟崩溃", component="rules")
        return original_write(doc_id, payload)

    store._store.write = broken_head
    with pytest.raises(StorageError):
        service.activate(_book(), base_version=1, author="a", reason="v2")
    store._store.write = original_write
    rebuilt = RuleStore(JsonStore(str(tmp_path / "state")))
    assert rebuilt.head() is not None and rebuilt.head().version == 2


# ---- 门控会话：版本钉住 -----------------------------------------------------


def test_session_pins_version_across_activation(tmp_path):
    service, _store, _audit, engine, _clock = _service(tmp_path)
    service.seed(_book(), author="test", reason="init")
    session = engine.begin_session("op-1")
    assert session.pinned_version == 1

    # v2 加一条停站约束；在途会话仍按 v1 判定，新会话按 v2。
    changed = _book()
    changed["scopes"]["depart"]["rules"].append(
        {
            "id": "depart.dwell_min",
            "effect": "deny",
            "reason": "停站时间不足",
            "when": {"op": "lt", "args": [{"fact": "train.dwell_s"}, {"const": 30}]},
        }
    )
    service.activate(changed, base_version=1, author="a", reason="v2")
    facts = {"gap.clear": True, "train.dwell_s": 0.0}
    assert session.evaluate("depart", facts).allowed is True
    fresh = engine.begin_session("op-2")
    assert fresh.pinned_version == 2
    verdict = fresh.evaluate("depart", facts)
    assert verdict.allowed is False
    assert "停站时间不足" in verdict.violations
    assert len(engine.sessions()) == 2
    engine.close_session("op-1")
    assert [item["op_id"] for item in engine.sessions()] == ["op-2"]


def test_missing_fact_fails_safe(tmp_path):
    service, _store, _audit, engine, _clock = _service(tmp_path)
    service.seed(_book(), author="test", reason="init")
    verdict = engine.evaluate("depart", {})
    assert verdict.allowed is False
    assert verdict.indeterminate
    assert "gap.clear" in verdict.violations[0]


def test_undefined_scope_denies(tmp_path):
    service, _store, _audit, engine, _clock = _service(tmp_path)
    service.seed(_book(), author="test", reason="init")
    verdict = engine.evaluate("no.such.scope", {"gap.clear": True})
    assert verdict.allowed is False


def test_sessions_survive_restart(tmp_path):
    service, _store, _audit, engine, clock = _service(tmp_path)
    service.seed(_book(), author="test", reason="init")
    engine.begin_session("op-1")
    # 重建整套服务（模拟重启），会话钉住关系从盘上恢复。
    service2, _store2, _audit2, engine2, _clock2 = _service(tmp_path, clock)
    session = engine2.session("op-1")
    assert session is not None and session.pinned_version == 1
    assert session.evaluate("depart", {"gap.clear": True}).allowed is True


# ---- 回放与影响面 ------------------------------------------------------------


def test_gate_records_decision_and_replay_reproduces(tmp_path):
    service, _store, audit, engine, clock = _service(tmp_path)
    service.seed(_book(), author="test", reason="init")
    session = engine.begin_session("op-1")
    verdict = service.gate(session, "depart", {"gap.clear": True}, actor="test")
    assert verdict.allowed is True
    decisions = audit.list("decision")
    assert len(decisions) == 1
    decision_id = decisions[0]["payload"]["decision_id"]
    replayed = service.replay(decision_id)
    assert replayed["reproduced"] is True
    assert replayed["recorded"]["allowed"] is True

    impact = service.impact(1)
    assert impact["decisions"] == 1
    with pytest.raises(RuleNotFoundError):
        service.replay("gd-99999999")


def test_evaluate_at_uses_version_active_then(tmp_path):
    clock = ManualClock()
    service, _store, _audit, engine, _clock = _service(tmp_path, clock)
    service.seed(_book(), author="test", reason="init")
    clock.advance(100)
    changed = _book()
    changed["scopes"]["depart"]["rules"].append(
        {
            "id": "depart.dwell_min",
            "effect": "deny",
            "reason": "停站时间不足",
            "when": {"op": "lt", "args": [{"fact": "train.dwell_s"}, {"const": 30}]},
        }
    )
    service.activate(changed, base_version=1, author="a", reason="v2")
    facts = {"gap.clear": True, "train.dwell_s": 0.0}
    at_v1 = service.evaluate_at("depart", facts, at=clock.now() - 50)
    assert at_v1["version"] == 1 and at_v1["verdict"]["allowed"] is True
    at_v2 = service.evaluate_at("depart", facts, at=clock.now())
    assert at_v2["version"] == 2 and at_v2["verdict"]["allowed"] is False
    with pytest.raises(RuleNotFoundError):
        service.evaluate_at("depart", facts, at=clock.now() - 10_000_000)


# ---- 平台集成 ----------------------------------------------------------------


def _dwell_rule_book():
    book = json.loads(json.dumps(DEFAULT_RULEBOOK))
    book["scopes"]["depart"]["rules"].append(
        {
            "id": "depart.dwell_min",
            "effect": "deny",
            "reason": "停站时间不足",
            "when": {"op": "lt", "args": [{"fact": "train.dwell_s"}, {"const": 30}]},
        }
    )
    return book


def test_platform_depart_uses_pinned_version(platform):
    platform.start()
    platform.arrive("T01", "ST1", 0)
    platform.check_gap("T01")
    # T01 在站期间规则升级到 v2（加停站约束）：在途作业仍按 v1 放行。
    platform.rules_activate(_dwell_rule_book(), 1, "op", "加停站约束")
    departure = platform.depart("T01", "ST1")
    assert departure["ok"] is True
    assert departure["rules_version"] == 1
    # 新到站的列车钉住 v2：不停够时间不放行。
    platform.arrive("T02", "ST1", 0)
    platform.check_gap("T02")
    blocked = platform.depart("T02", "ST1")
    assert blocked["ok"] is False
    assert "停站时间不足" in blocked["violations"]
    platform.register_dwell("T02", 45.0, "ST1")
    assert platform.depart("T02", "ST1")["ok"] is True


def test_platform_rollback_restores_previous_behavior(platform):
    platform.start()
    platform.rules_activate(_dwell_rule_book(), 1, "op", "加停站约束")
    result = platform.rules_rollback(1, 2, "op", "回退")
    assert result["version"] == 3
    platform.arrive("T01", "ST1", 0)
    platform.check_gap("T01")
    departure = platform.depart("T01", "ST1")
    assert departure["ok"] is True
    assert departure["rules_version"] == 3
    history = platform.rules_history()
    assert [item["version"] for item in history] == [1, 2, 3]
    # 已执行的判定不重算：v2 期间的判定记录仍在审计链里。
    assert platform.rules_impact(2)["version"] == 2


def test_platform_restart_keeps_rules_and_sessions(platform, tmp_path, clock):
    platform.start()
    platform.arrive("T01", "ST1", 0)
    platform.rules_activate(_dwell_rule_book(), 1, "op", "加停站约束")
    root = platform.store.root
    from psdline.app import build_platform

    restarted = build_platform(default_config(), clock=clock, storage_root=root)
    assert restarted.rules_status()["version"]["version"] == 2
    sessions = restarted.rules_status()["sessions"]
    assert any(item["op_id"] == "train-T01" for item in sessions)
    # 重启后在途列车仍按开工时的 v1 判定。
    restarted.check_gap("T01")
    departure = restarted.depart("T01", "ST1")
    assert departure["ok"] is True
    assert departure["rules_version"] == 1


def test_platform_clear_fault_uses_rules(platform):
    gate = platform.gates.by_station("ST1")[0]
    platform.set_fault(gate.id)
    platform.gates.set_open(gate.id, True)
    blocked = platform.clear_fault(gate.id)
    assert blocked["ok"] is False
    assert "gate_open" in blocked["violations"]
    platform.gates.set_open(gate.id, False)
    assert platform.clear_fault(gate.id)["ok"] is True


def test_platform_doors_open_uses_rules(platform):
    from psdline.errors import InterlockError

    # 对位未落盘时规则门控直接拒绝开门。
    with pytest.raises(InterlockError):
        platform.doors_open("T99", "ST1")
    platform.arrive("T01", "ST1", 0)
    assert platform.train_doors.is_open("T01") is True
    decisions = [
        entry for entry in platform.rules_audit()["entries"] if entry["action"] == "decision"
    ]
    assert any(entry["payload"]["scope"] == "door.open" for entry in decisions)


def test_platform_rules_endpoints(platform):
    from psdline.console.api import Api

    api = Api(platform)
    status, payload = api.handle("GET", "/api/rules", {}, {})
    assert status == 200 and payload["version"]["version"] == 1
    status, payload = api.handle("POST", "/api/rules/validate", {}, {"content": _dwell_rule_book()})
    assert status == 200 and payload["ok"] is True
    status, payload = api.handle(
        "POST",
        "/api/rules/activate",
        {},
        {"content": _dwell_rule_book(), "base_version": 1, "author": "op", "reason": "v2"},
    )
    assert status == 200 and payload["version"] == 2
    # 基线过期 → 409 冲突。
    status, payload = api.handle(
        "POST",
        "/api/rules/activate",
        {},
        {"content": _dwell_rule_book(), "base_version": 1, "author": "op", "reason": "并发"},
    )
    assert status == 409
    # 校验不过 → 409 且带问题清单。
    bad = _dwell_rule_book()
    bad["scopes"]["depart"]["rules"][0]["when"] = {"fact": "no.such.fact"}
    status, payload = api.handle(
        "POST",
        "/api/rules/activate",
        {},
        {"content": bad, "base_version": 2, "author": "op", "reason": "bad"},
    )
    assert status == 409 and payload["issues"]
    status, payload = api.handle(
        "POST", "/api/rules/rollback", {}, {"target_version": 1, "base_version": 2, "author": "op"}
    )
    assert status == 200 and payload["version"] == 3
    status, payload = api.handle("GET", "/api/rules/history", {}, {})
    assert [item["version"] for item in payload["versions"]] == [1, 2, 3]
    status, payload = api.handle("GET", "/api/rules/audit", {}, {})
    assert status == 200 and payload["verify"]["ok"] is True
