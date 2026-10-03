"""联锁规则：表达式、校验、版本化、生效门控、回退、回放、崩溃与并发。"""

from __future__ import annotations

import threading
from dataclasses import replace

import pytest

from psdline.app import build_platform
from psdline.clock import ManualClock
from psdline.config import default_config
from psdline.errors import InterlockError, RailError, StorageError
from psdline.rules import (
    ExprError,
    GatePolicy,
    default_catalog,
    evaluate,
    validate_ruleset,
)
from psdline.rules.model import content_hash


def _ruleset(rules, schema=1):
    return {"schema_version": schema, "rules": rules}


def _permit_depart():
    return {
        "id": "PERMIT-DEPART",
        "on": {"command": "train.depart"},
        "effect": "permit",
        "guard": {
            "op": "and",
            "args": [
                {"fact": "gap.clear"},
                {"fact": "train.aligned"},
            ],
        },
    }


def _permit_open():
    return {
        "id": "PERMIT-OPEN",
        "on": {"command": "door.open"},
        "effect": "permit",
        "guard": {"fact": "train.aligned"},
    }


def _deny_faults(limit=0):
    return {
        "id": "DENY-FAULTS",
        "on": {"command": "*"},
        "effect": "deny",
        "priority": 900,
        "guard": {"op": "gt", "args": [{"fact": "interlock.fault_count"}, {"const": limit}]},
    }


def _publish(platform, rules, gate="deferred", reason=""):
    draft = platform.save_rule_draft(_ruleset(rules))
    assert draft["report"]["valid"], draft["report"]
    return platform.publish_rules(
        draft["draft_id"], draft["base_version"], gate=gate, reason=reason
    ), draft


def _activate(platform):
    platform.cycle()
    assert platform.rules_status()["active"] is not None


# ---- 表达式求值 -----------------------------------------------------------


def test_expr_leaves_and_boolean():
    facts = {"a": True, "b": False, "n": 3}
    assert evaluate({"fact": "a"}, facts, {}) is True
    assert evaluate({"const": 7}, facts, {}) == 7
    assert evaluate({"param": "x"}, facts, {"x": "v"}) == "v"
    assert evaluate({"op": "and", "args": [{"fact": "a"}, {"fact": "b"}]}, facts, {}) is False
    assert evaluate({"op": "or", "args": [{"fact": "a"}, {"fact": "b"}]}, facts, {}) is True
    assert evaluate({"op": "not", "args": [{"fact": "b"}]}, facts, {}) is True


def test_expr_compare_in_and_arithmetic():
    facts = {"n": 3, "s": "yellow"}
    assert evaluate({"op": "lt", "args": [{"fact": "n"}, {"const": 4}]}, facts, {}) is True
    assert evaluate({"op": "ge", "args": [{"fact": "n"}, {"const": 3}]}, facts, {}) is True
    assert evaluate(
        {"op": "in", "args": [{"fact": "s"}, {"const": ["yellow", "green"]}]}, facts, {}
    ) is True
    assert evaluate({"op": "add", "args": [{"fact": "n"}, {"const": 1}]}, facts, {}) == 4
    assert evaluate({"op": "mul", "args": [{"fact": "n"}, {"const": 2}]}, facts, {}) == 6


def test_expr_fail_closed_on_bad_input():
    with pytest.raises(ExprError):
        evaluate({"fact": "missing"}, {}, {})
    with pytest.raises(ExprError):
        evaluate({"op": "div", "args": [{"const": 1}, {"const": 0}]}, {}, {})
    with pytest.raises(ExprError):  # 布尔不是数值
        evaluate({"op": "add", "args": [{"const": True}, {"const": 1}]}, {}, {})
    with pytest.raises(ExprError):  # and 只接受布尔
        evaluate({"op": "and", "args": [{"const": 1}]}, {}, {})
    with pytest.raises(ExprError):
        evaluate({"op": "nope", "args": []}, {}, {})


def test_expr_bool_never_equals_number():
    assert evaluate({"op": "eq", "args": [{"const": True}, {"const": 1}]}, {}, {}) is False
    assert evaluate({"op": "eq", "args": [{"const": 1}, {"const": 1.0}]}, {}, {}) is True


# ---- 校验 -----------------------------------------------------------------


def test_validate_accepts_sound_ruleset():
    catalog = default_catalog()
    report = validate_ruleset(_ruleset([_permit_depart(), _deny_faults()]), catalog)
    assert report.valid, report.as_dict()
    assert report.warnings  # 放行与拒绝并存 → 告警


def test_validate_rejects_bad_structure():
    catalog = default_catalog()
    assert not validate_ruleset("not-a-dict", catalog).valid
    assert not validate_ruleset(_ruleset([_permit_depart()], schema=99), catalog).valid
    assert not validate_ruleset({"schema_version": 1}, catalog).valid
    bad_id = _ruleset([{**_permit_depart(), "id": "bad id!"}])
    assert not validate_ruleset(bad_id, catalog).valid
    dup = _ruleset([_permit_depart(), _permit_depart()])
    assert not validate_ruleset(dup, catalog).valid
    bad_effect = _ruleset([{**_permit_depart(), "effect": "maybe"}])
    assert not validate_ruleset(bad_effect, catalog).valid


def test_validate_rejects_bad_expressions():
    catalog = default_catalog()
    unknown_fact = _ruleset([{**_permit_depart(), "guard": {"fact": "no.such"}}])
    assert not validate_ruleset(unknown_fact, catalog).valid
    non_bool_guard = _ruleset([{**_permit_depart(), "guard": {"fact": "psd.open_count"}}])
    assert not validate_ruleset(non_bool_guard, catalog).valid
    bad_arity = _ruleset(
        [{**_permit_depart(), "guard": {"op": "lt", "args": [{"const": 1}]}}]
    )
    assert not validate_ruleset(bad_arity, catalog).valid
    type_mismatch = _ruleset(
        [{**_permit_depart(), "guard": {"op": "lt", "args": [{"fact": "gap.clear"}, {"const": 1}]}}]
    )
    assert not validate_ruleset(type_mismatch, catalog).valid


def test_validate_value_ranges_and_enums():
    catalog = default_catalog()
    over_range = _ruleset(
        [{**_permit_depart(), "guard": {"op": "le", "args": [{"fact": "psd.locked_ratio"}, {"const": 1.5}]}}]
    )
    report = validate_ruleset(over_range, catalog)
    assert not report.valid and "上界" in report.errors[0].message
    bad_enum = _ruleset(
        [{**_permit_depart(), "guard": {"op": "eq", "args": [{"fact": "sig.aspect"}, {"const": "blue"}]}}]
    )
    report = validate_ruleset(bad_enum, catalog)
    assert not report.valid and "枚举" in report.errors[0].message
    good_enum = _ruleset(
        [{**_permit_depart(), "guard": {"op": "in", "args": [{"fact": "sig.aspect"}, {"const": ["green", "yellow"]}]}}]
    )
    assert validate_ruleset(good_enum, catalog).valid
    nan_rule = _ruleset([_permit_depart()])
    nan_rule["rules"][0]["guard"] = {"op": "lt", "args": [{"const": float("nan")}, {"const": 1}]}
    assert not validate_ruleset(nan_rule, catalog).valid


# ---- 发布与生效门控 --------------------------------------------------------


def test_invalid_ruleset_never_publishes(platform):
    draft = platform.save_rule_draft(_ruleset([{**_permit_depart(), "guard": {"fact": "no.such"}}]))
    assert draft["report"]["valid"] is False
    with pytest.raises(RailError):
        platform.publish_rules(draft["draft_id"], draft["base_version"])
    assert platform.rules_status()["active"] is None


def test_deferred_activation_waits_for_quiescence(platform, clock):
    platform.start()
    platform.arrive("T01", "ST1", 0)  # 列车在作业中
    _publish(platform, [_permit_depart()])
    assert platform.rules_status()["pending"] is not None
    platform.cycle()
    assert platform.rules_status()["active"] is None  # 作业未结束，不生效
    platform.check_gap("T01")
    platform.depart("T01", "ST1")  # 作业结束
    clock.advance(1)
    platform.cycle()
    status = platform.rules_status()
    assert status["active"]["version"] == 1
    assert status["pending"] is None


def test_immediate_activation_rejected_by_default_policy(platform):
    draft = platform.save_rule_draft(_ruleset([_permit_depart()]))
    with pytest.raises(RailError):
        platform.publish_rules(draft["draft_id"], draft["base_version"], gate="immediate", reason="x")
    assert platform.rules_status()["active"] is None


def test_immediate_activation_with_policy(tmp_path, clock):
    config = replace(
        default_config(), rules=replace(default_config().rules, allow_immediate=True)
    )
    platform = build_platform(config, clock=clock, storage_root=str(tmp_path / "state"))
    draft = platform.save_rule_draft(_ruleset([_permit_depart()]))
    with pytest.raises(RailError):  # 立即生效必须给理由
        platform.publish_rules(draft["draft_id"], draft["base_version"], gate="immediate")
    published = platform.publish_rules(
        draft["draft_id"], draft["base_version"], gate="immediate", reason="抢修需要"
    )
    assert published["ok"] is True
    assert platform.rules_status()["active"]["version"] == 1


def test_force_activate_and_cancel(platform):
    platform.start()
    platform.arrive("T01", "ST1", 0)  # 现场不空闲
    _publish(platform, [_permit_depart()])
    with pytest.raises(RailError):
        platform.force_activate_rules("")  # 强制生效必须给理由
    forced = platform.force_activate_rules("抢修窗口")
    assert forced["version"] == 1
    assert platform.rules_status()["active"]["version"] == 1
    kinds = [entry.kind for entry in platform.audit.list()]
    assert "rules_activated" in kinds

    _publish(platform, [_permit_depart(), _deny_faults()])
    cancelled = platform.cancel_rules_activation("再想想")
    assert cancelled["cancelled"] == 2
    assert platform.rules_status()["pending"] is None


def test_publish_conflict_on_stale_base(platform):
    first = platform.save_rule_draft(_ruleset([_permit_depart()]))
    second = platform.save_rule_draft(_ruleset([_deny_faults()]))
    platform.publish_rules(first["draft_id"], first["base_version"])
    with pytest.raises(RailError):
        platform.publish_rules(second["draft_id"], second["base_version"])
    kinds = [entry.kind for entry in platform.audit.list()]
    assert "rules_conflict" in kinds


# ---- 门控联动 ---------------------------------------------------------------


def test_gate_denies_and_permits_depart(platform):
    platform.start()
    _publish(platform, [_permit_open(), _permit_depart()])
    _activate(platform)
    platform.arrive("T01", "ST1", 0)
    denied = platform.depart("T01", "ST1")  # 未确认间隙 → 规则拒绝
    assert denied["ok"] is False
    assert any("规则集 v1" in item for item in denied["violations"])
    platform.check_gap("T01")
    allowed = platform.depart("T01", "ST1")
    assert allowed["ok"] is True


def test_gate_deny_rule_wins_over_permit(platform):
    platform.start()
    _publish(platform, [_permit_open(), _permit_depart(), _deny_faults(limit=0)])
    _activate(platform)
    platform.arrive("T01", "ST1", 0)
    platform.check_gap("T01")
    gate = platform.gates.by_station("ST1")[0]
    # 直接置位故障（绕过门控的 set_fault 路径），让拒绝规则命中
    platform.faults.set_fault(platform.lockouts, gate.id, platform.clock.now())
    denied = platform.depart("T01", "ST1")
    assert denied["ok"] is False
    decision = [e for e in platform.audit.list() if e.kind == "rules_decision"][-1]
    assert decision.detail["allowed"] is False
    assert decision.detail["reason"] == "denied_by_rule"


def test_no_rules_keeps_legacy_behavior(platform):
    platform.start()
    platform.arrive("T01", "ST1", 0)
    platform.check_gap("T01")
    assert platform.depart("T01", "ST1")["ok"] is True
    assert not [e for e in platform.audit.list() if e.kind == "rules_decision"]


# ---- 回退 -------------------------------------------------------------------


def test_rollback_creates_new_version_and_reconciliation(platform):
    platform.start()
    _publish(platform, [_permit_open(), _permit_depart()])
    _activate(platform)
    _publish(platform, [_permit_open(), _permit_depart(), _deny_faults(limit=0)])  # v2 更严
    _activate(platform)
    platform.arrive("T01", "ST1", 0)
    platform.check_gap("T01")
    assert platform.depart("T01", "ST1")["ok"] is True  # v2 期间放行一次

    result = platform.rollback_rules(1, "v2 误拦正常发车")
    assert result["version"] == 3
    assert result["restored_content_of"] == 1
    assert result["replaced"] == 2
    assert result["recomputed"] is False  # 不重算历史
    # 对账清单列出被替换版本（v2）生效期间的放行判定，交人工处置
    commands = [item["command"] for item in result["reconciliation"]]
    assert commands == ["door.open", "train.depart"]
    platform.cycle()
    status = platform.rules_status()
    assert status["active"]["version"] == 3
    versions = {item["version"]: item["status"] for item in status["versions"]}
    assert versions == {1: "superseded", 2: "superseded", 3: "active"}  # 历史不可变


def test_rollback_requires_reason_and_known_version(platform):
    _publish(platform, [_permit_depart()])
    _activate(platform)
    with pytest.raises(RailError):
        platform.rollback_rules(1, "")
    with pytest.raises(RailError):
        platform.rollback_rules(99, "不存在的版本")


# ---- 回放 -------------------------------------------------------------------


def test_replay_uses_version_active_at_the_time(platform, clock):
    platform.start()
    _publish(platform, [_permit_open(), _permit_depart()])
    _activate(platform)
    platform.arrive("T01", "ST1", 0)
    platform.check_gap("T01")
    assert platform.depart("T01", "ST1")["ok"] is True
    decision_audit = [e for e in platform.audit.list() if e.kind == "rules_decision"][-1]

    # v2 拒绝一切发车（无放行规则），但回放 v1 时期的判定仍按 v1 算
    _publish(platform, [_deny_faults(limit=99)])
    _activate(platform)
    check = platform.replay_rule_decision(decision_audit.id)
    assert check["consistent"] is True
    assert check["version"] == 1
    assert check["replayed_allowed"] is True


def test_decide_as_of_picks_historical_version(platform, clock):
    _publish(platform, [_permit_depart()])
    _activate(platform)
    clock.advance(10)
    moment = clock.now()
    clock.advance(10)
    _publish(platform, [_deny_faults(limit=99)])
    _activate(platform)
    service = platform.rules
    facts = {"gap.clear": True, "train.aligned": True}
    now = service.decide_as_of(clock.now(), "train.depart", {}, facts)
    assert now.allowed is False  # 当前版本无放行规则
    then = service.decide_as_of(moment, "train.depart", {}, facts)
    assert then.allowed is True  # 当时 v1 生效
    assert then.version == 1


# ---- 崩溃安全 -----------------------------------------------------------------


def test_op_id_retry_is_idempotent(platform):
    draft = platform.save_rule_draft(_ruleset([_permit_depart()]))
    op_id = "publish-op-1"
    first = platform.publish_rules(draft["draft_id"], draft["base_version"], op_id=op_id)
    second = platform.publish_rules(draft["draft_id"], draft["base_version"], op_id=op_id)
    assert first["version"] == second["version"] == 1
    assert len(platform.rules_status()["versions"]) == 1  # 没有重复版本


def test_restart_recovers_pending_and_history(tmp_path, clock):
    root = str(tmp_path / "state")
    platform = build_platform(default_config(), clock=clock, storage_root=root)
    _publish(platform, [_permit_depart()])
    assert platform.rules_status()["pending"]["version"] == 1

    restarted = build_platform(default_config(), clock=clock, storage_root=root)
    assert restarted.rules_status()["pending"]["version"] == 1  # 待生效状态还在
    restarted.cycle()
    assert restarted.rules_status()["active"]["version"] == 1

    clock.advance(30)
    moment = clock.now()
    clock.advance(30)
    _publish(restarted, [_deny_faults(limit=99)])
    restarted.cycle()
    assert restarted.rules_status()["active"]["version"] == 2

    again = build_platform(default_config(), clock=clock, storage_root=root)
    facts = {"gap.clear": True, "train.aligned": True}
    historical = again.rules.decide_as_of(moment, "train.depart", {}, facts)
    assert historical.version == 1 and historical.allowed is True  # 回放按当时版本算
    current = again.rules.decide_as_of(clock.now(), "train.depart", {}, facts)
    assert current.version == 2 and current.allowed is False


def test_torn_journal_tail_is_truncated(tmp_path, clock):
    root = str(tmp_path / "state")
    platform = build_platform(default_config(), clock=clock, storage_root=root)
    _publish(platform, [_permit_depart()])
    journal = tmp_path / "state" / "rules-00000.jsonl"
    with open(journal, "ab") as handle:  # 模拟掉电：最后一条记录写了一半
        handle.write(b'{"kind": "ACTIVATED", "payload": {"ver')
    restarted = build_platform(default_config(), clock=clock, storage_root=root)
    assert restarted.rules_status()["pending"]["version"] == 1  # 状态完好
    repairs = [e for e in restarted.audit.list() if e.kind == "rules_journal_repaired"]
    assert repairs and repairs[0].detail["truncated_bytes"] > 0


def test_corrupt_journal_middle_refuses_repair(tmp_path, clock):
    root = str(tmp_path / "state")
    platform = build_platform(default_config(), clock=clock, storage_root=root)
    _publish(platform, [_permit_depart()])
    _activate(platform)
    journal = tmp_path / "state" / "rules-00000.jsonl"
    lines = journal.read_bytes().splitlines(keepends=True)
    lines[0] = b'{"kind": "PUBLISHED", "payload": corrupted}\n'  # 中间被改
    journal.write_bytes(b"".join(lines))
    with pytest.raises(StorageError):
        build_platform(default_config(), clock=clock, storage_root=root)


# ---- 并发 ---------------------------------------------------------------------


def test_concurrent_publish_single_winner(platform):
    first = platform.save_rule_draft(_ruleset([_permit_depart()]))
    barrier = threading.Barrier(8)
    outcomes = []
    errors = []

    def attempt():
        barrier.wait()
        try:
            outcomes.append(platform.publish_rules(first["draft_id"], first["base_version"]))
        except RailError as error:
            errors.append(error)

    threads = [threading.Thread(target=attempt) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(outcomes) == 1  # 同一基线只有一个发布成功
    assert len(errors) == 7
    assert len(platform.rules_status()["versions"]) == 1


def test_concurrent_gate_and_activate_consistent(platform):
    platform.start()
    _publish(platform, [_permit_open(), _permit_depart()])
    _activate(platform)
    platform.arrive("T01", "ST1", 0)
    platform.check_gap("T01")
    results = []

    def depart():
        results.append(platform.depart("T01", "ST1")["ok"])

    threads = [threading.Thread(target=depart) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert all(isinstance(item, bool) for item in results)  # 判定不撕裂


# ---- 审计 ---------------------------------------------------------------------


def test_audit_records_full_lifecycle(platform):
    platform.start()
    draft = platform.save_rule_draft(_ruleset([_permit_open(), _permit_depart()]))
    platform.publish_rules(draft["draft_id"], draft["base_version"])
    platform.cycle()
    platform.arrive("T01", "ST1", 0)
    platform.check_gap("T01")
    platform.depart("T01", "ST1")
    kinds = [entry.kind for entry in platform.audit.list()]
    for expected in ("rules_draft_saved", "rules_published", "rules_activated", "rules_decision"):
        assert expected in kinds
    decision = [e for e in platform.audit.list() if e.kind == "rules_decision"][-1]
    assert decision.detail["version"] == 1
    assert decision.detail["hash"] == content_hash(_ruleset([_permit_open(), _permit_depart()]))
    assert "gap.clear" in decision.detail["facts"]  # 快照随判定进审计


def test_preview_is_non_authoritative(platform):
    decision = platform.preview_rules(
        _ruleset([_permit_depart()]), "train.depart", {"train_id": "T01"}
    )
    assert decision["ok"] is True
    previews = [e for e in platform.audit.list() if e.kind == "rules_preview"]
    assert previews and previews[0].detail["authoritative"] is False
