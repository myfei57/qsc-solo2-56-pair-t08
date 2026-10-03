"""命令行入口。

六个子命令覆盖日常使用：

``serve``   启动控制台 HTTP 服务，可选地在启动后探测接口；
``demo``    在本地跑一遍完整流程（到站开门 → 间隙探测 → 发车 → 批量开门 →
            门区联动 → 故障置位与解除 → 序号回绕 → 控制周期 → 清扫），用于交付
            前的真实运行检查；
``status``  打印当前状态快照；
``config``  打印生效配置；
``rules``   联锁规则管理：show / history / catalog / audit / validate /
            activate / rollback / impact / replay；
``reset``   清掉落盘的平台计数。
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time

from .app import Platform, build_platform
from .clock import ManualClock, SystemClock
from .config import config_to_mapping, default_config, load_config
from .console.server import ConsoleServer, probe_endpoints
from .errors import RailError

DEFAULT_PROBE_PATHS = ("/api/status", "/api/readiness", "/api/stations", "/", "/alarms")


def _build(args: argparse.Namespace) -> Platform:
    config = load_config(args.config) if getattr(args, "config", None) else default_config()
    if getattr(args, "storage_root", None):
        return build_platform(config, storage_root=args.storage_root)
    return Platform(config=config)


def _dump(payload: object) -> None:
    print(json.dumps(payload, ensure_ascii=False, indent=2, default=str))


def _cmd_serve(args: argparse.Namespace) -> int:
    platform = _build(args)
    server = ConsoleServer(platform, host=args.host, port=args.port)
    base_url = server.start()
    payload: dict = {"listening": base_url, "routes": server.api.routes()}
    if args.probe:
        payload["probe"] = probe_endpoints(base_url, list(DEFAULT_PROBE_PATHS))
    _dump(payload)
    if args.duration > 0:
        try:
            time.sleep(args.duration)
        except KeyboardInterrupt:  # pragma: no cover - 交互路径
            pass
        server.stop()
        return 0
    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:  # pragma: no cover - 交互路径
        server.stop()
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    clock = ManualClock() if args.fast else SystemClock()
    config_path = getattr(args, "config", None)
    config = load_config(config_path) if config_path else default_config()
    storage_root = getattr(args, "storage_root", None) or tempfile.mkdtemp(prefix="psdline-demo-")
    platform = build_platform(config, clock=clock, storage_root=storage_root)

    startup = platform.start()
    arrival = platform.arrive(args.train, args.station, 0)
    position = platform.refresh_position(args.train, 12)
    gap = platform.check_gap(args.train)
    queued = platform.enqueue(args.train, "cmd-1", "open", args.station)
    processed = platform.process_queue(args.train)
    swept = platform.sweep(args.station)
    fault = platform.set_fault(_first_gate(platform, args.station))
    cleared = platform.clear_fault(_first_gate(platform, args.station))
    batched = platform.batch_open(args.station)
    renumber = platform.renumber(args.station, _mirror_mapping(platform, args.station))
    sequence = platform.sequence_verdict(65534, 4)
    dwell = platform.register_dwell(args.train, 45.0, args.station)
    route = platform.assign_route(args.train, args.station, _next_station(platform, args.station), 1200)
    departure = platform.depart(args.train, args.station)
    cycles = [platform.cycle(dt=args.dt) for _ in range(args.cycles)]
    final_sweep = platform.sweep(args.station)

    # 演示自检用临时端口，避免和本机常驻服务抢 8080。
    server = ConsoleServer(platform, port=0)
    base_url = server.start()
    probe = probe_endpoints(base_url, list(DEFAULT_PROBE_PATHS))
    server.stop()

    report = {
        "storage_root": storage_root,
        "startup": startup,
        "arrival": {key: arrival[key] for key in ("ok", "position_m", "violations")},
        "position": position,
        "gap": gap,
        "queued": {key: queued[key] for key in ("ok", "train_id")},
        "processed": processed,
        "swept": swept,
        "batch": {key: batched[key] for key in ("ok", "order", "opened", "nearest")},
        "renumber": {key: renumber[key] for key in ("ok", "revision", "active_group")},
        "fault": fault,
        "cleared": cleared,
        "sequence": sequence,
        "dwell": dwell,
        "route": route,
        "departure": departure,
        "cycles_run": len(cycles),
        "last_cycle": cycles[-1],
        "final_sweep": {key: final_sweep[key] for key in ("closed", "scanned")},
        "probe": probe,
        "status": platform.status(),
    }
    _dump(report)

    failures = [name for name, item in probe.items() if not item["ok"]]
    for name, operation in (
        ("arrival", arrival),
        ("processed", processed),
        ("renumber", renumber),
        ("cleared", cleared),
        ("sequence", sequence),
        ("departure", departure),
    ):
        if not operation.get("ok"):
            failures.extend(f"{name}:{item}" for item in operation.get("violations", []))
    if failures:
        print(f"检查未通过: {failures}", file=sys.stderr)
        return 1
    return 0


def _mirror_mapping(platform: Platform, station_id: str) -> dict[str, str]:
    """给演示重排构造一份反向映射。"""

    groups = sorted(platform.station_view(station_id)["groups"])
    rotated = groups[1:] + groups[:1]
    return {key: value for key, value in zip(groups, rotated)}


def _first_gate(platform: Platform, station_id: str) -> str:
    """返回演示用的第一樘站台门。"""

    gates = platform.gates.by_station(station_id)
    return gates[0].id if gates else ""


def _next_station(platform: Platform, station_id: str) -> str:
    """返回线路上下一个站台，用于演示交路。"""

    stations = platform.namespace.station_ids()
    if len(stations) < 2:
        return station_id
    index = stations.index(station_id) if station_id in stations else 0
    return stations[(index + 1) % len(stations)]


def _cmd_status(args: argparse.Namespace) -> int:
    platform = _build(args)
    payload = platform.status()
    payload["groups"] = platform.snapshot()["groups"]
    _dump(payload)
    return 0


def _cmd_config(args: argparse.Namespace) -> int:
    config_path = getattr(args, "config", None)
    config = load_config(config_path) if config_path else default_config()
    _dump(config_to_mapping(config))
    return 0


def _cmd_reset(args: argparse.Namespace) -> int:
    platform = _build(args)
    removed = platform.reset_state()
    _dump({"storage_root": platform.store.root, "platform_state_removed": removed})
    return 0


def _load_json_file(path: str) -> dict:
    """读取一份 JSON 文件（规则簿等）。"""

    try:
        with open(path, "r", encoding="utf-8") as handle:
            payload = json.load(handle)
    except (OSError, json.JSONDecodeError) as error:
        raise RailError(f"读取 JSON 文件失败 {path}: {error}", component="cli") from error
    if not isinstance(payload, dict):
        raise RailError(f"文件内容必须是 JSON 对象: {path}", component="cli")
    return payload


def _base_version(platform: Platform, args: argparse.Namespace) -> int:
    """解析生效/回退用的基线版本，缺省取当前生效版本。"""

    if args.base_version >= 0:
        return args.base_version
    current = platform.rules_status()["version"]
    return 0 if current is None else int(current["version"])


def _cmd_rules(args: argparse.Namespace) -> int:
    platform = _build(args)
    action = args.rules_action
    if action == "show":
        _dump(platform.rules_status())
        return 0
    if action == "history":
        _dump({"versions": platform.rules_history()})
        return 0
    if action == "catalog":
        _dump(platform.rules_catalog())
        return 0
    if action == "audit":
        _dump(platform.rules_audit())
        return 0
    if action == "validate":
        result = platform.rules_validate(_load_json_file(args.file))
        _dump(result)
        return 0 if result["ok"] else 1
    if action == "activate":
        result = platform.rules_activate(
            _load_json_file(args.file),
            _base_version(platform, args),
            args.author,
            args.reason,
        )
        _dump(result)
        return 0
    if action == "rollback":
        _dump(
            platform.rules_rollback(
                args.target_version, _base_version(platform, args), args.author, args.reason
            )
        )
        return 0
    if action == "impact":
        _dump(platform.rules_impact(args.version))
        return 0
    if action == "replay":
        _dump(platform.rules_replay(args.decision_id))
        return 0
    raise RailError(f"未知规则动作: {action}", component="cli")


def build_parser() -> argparse.ArgumentParser:
    """构造命令行解析器。"""

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--config", help="JSON 配置文件路径", default=argparse.SUPPRESS)
    common.add_argument("--storage-root", help="覆盖状态存储目录", default=argparse.SUPPRESS)
    parser = argparse.ArgumentParser(
        prog="psdline", description="作业顺序与联锁控制服务", parents=[common]
    )
    sub = parser.add_subparsers(dest="command", required=True)

    serve = sub.add_parser("serve", help="启动控制台服务", parents=[common])
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--duration", type=float, default=0.0, help="运行多少秒后退出，0 表示常驻")
    serve.add_argument("--probe", action="store_true", help="启动后探测接口")
    serve.set_defaults(func=_cmd_serve)

    demo = sub.add_parser("demo", help="跑一遍完整流程", parents=[common])
    demo.add_argument("--train", default="T01", help="演示用的列车标识")
    demo.add_argument("--station", default="ST1", help="演示用的站台标识")
    demo.add_argument("--cycles", type=int, default=120, help="演示控制周期数")
    demo.add_argument("--dt", type=float, default=1.0, help="控制周期步长（秒）")
    demo.add_argument("--fast", action="store_true", help="使用可推进时钟，跳过真实等待")
    demo.set_defaults(func=_cmd_demo)

    status = sub.add_parser("status", help="打印状态快照", parents=[common])
    status.set_defaults(func=_cmd_status)

    config = sub.add_parser("config", help="打印生效配置", parents=[common])
    config.set_defaults(func=_cmd_config)

    reset = sub.add_parser("reset", help="清掉落盘的平台计数", parents=[common])
    reset.set_defaults(func=_cmd_reset)

    rules = sub.add_parser("rules", help="联锁规则：校验、生效、回退、回放", parents=[common])
    rules_sub = rules.add_subparsers(dest="rules_action", required=True)
    for name, help_text in (
        ("show", "当前生效版本与门控会话"),
        ("history", "版本历史"),
        ("catalog", "事实目录"),
        ("audit", "规则审计链"),
    ):
        rules_sub.add_parser(name, help=help_text, parents=[common]).set_defaults(func=_cmd_rules)
    validate = rules_sub.add_parser("validate", help="校验规则簿，不生效", parents=[common])
    validate.add_argument("file", help="规则簿 JSON 文件")
    validate.set_defaults(func=_cmd_rules)
    activate = rules_sub.add_parser("activate", help="校验通过后生效为新版本", parents=[common])
    activate.add_argument("file", help="规则簿 JSON 文件")
    activate.add_argument("--base-version", type=int, default=-1, help="基线版本（缺省取当前）")
    activate.add_argument("--author", default="operator", help="操作人")
    activate.add_argument("--reason", default="", help="变更原因")
    activate.set_defaults(func=_cmd_rules)
    rollback = rules_sub.add_parser("rollback", help="回退到历史版本", parents=[common])
    rollback.add_argument("target_version", type=int, help="目标版本号")
    rollback.add_argument("--base-version", type=int, default=-1, help="基线版本（缺省取当前）")
    rollback.add_argument("--author", default="operator", help="操作人")
    rollback.add_argument("--reason", default="", help="回退原因")
    rollback.set_defaults(func=_cmd_rules)
    impact = rules_sub.add_parser("impact", help="查询某版本期间的判定影响面", parents=[common])
    impact.add_argument("version", type=int, help="版本号")
    impact.set_defaults(func=_cmd_rules)
    replay = rules_sub.add_parser("replay", help="按当时版本重放一条判定", parents=[common])
    replay.add_argument("decision_id", help="判定标识（gd-xxxxxxxx）")
    replay.set_defaults(func=_cmd_rules)
    return parser


def main(argv: list[str] | None = None) -> int:
    """命令行主入口。"""

    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors="backslashreplace")
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.func(args))
    except RailError as error:
        print(json.dumps(error.as_record(), ensure_ascii=False), file=sys.stderr)
        return 2
