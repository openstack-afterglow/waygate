"""Gateway agent asset and standalone agent behavior tests."""

import base64
import configparser
import importlib.util
import json
import os
import queue
import shlex
import stat
import subprocess
import sys
import threading
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from waygate.services.config_render import AGENT_DIR, AGENT_FILES, render_agent_userdata

_AGENT_PATH = AGENT_DIR / "waygate_agent.py"


@pytest.fixture
def agent(monkeypatch, tmp_path):
    spec = importlib.util.spec_from_file_location("waygate_agent_under_test", _AGENT_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "LOG", str(tmp_path / "agent.log"))
    return module


def _config(**overrides) -> dict:
    return {
        "bootstrap_token": "current-token-abcdefghijklmnop",
        "listen_port": 51820,
        "tunnel_address": "10.8.0.1/24",
        "tunnel_cidr": "10.8.0.0/24",
    } | overrides


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.fixture
def installer_runtime(tmp_path, monkeypatch):
    """Redirect every installer OS command into a disposable guest filesystem."""
    root = tmp_path / "guest"
    units = root / "etc/systemd/system"
    wants = units / "timers.target.wants"
    wants.mkdir(parents=True)
    timer = units / "afterglow-waygate-reconcile.timer"
    timer.write_text("[Timer]\nOnBootSec=20s\n")
    (wants / timer.name).symlink_to("../" + timer.name)
    (units / "afterglow-waygate-reconcile.service").write_text("[Service]\nType=oneshot\n")
    script = root / "opt/afterglow/waygate_agent.py"
    script.parent.mkdir(parents=True)
    script.write_text("old agent\n")
    state = tmp_path / "state.json"
    state.write_text(json.dumps({"timer_active": True, "timer_enabled": True, "service_active": True}))
    events = tmp_path / "events.jsonl"
    commands = tmp_path / "bin"
    commands.mkdir()
    for command in ("systemctl", "install", "rm"):
        executable = commands / command
        executable.write_text(f"#!{sys.executable}\n" + '''
import json, os, subprocess, sys
from pathlib import Path
root = Path(os.environ["INSTALL_ROOT"])
source = Path(os.environ["INSTALL_SOURCE"])
command = Path(sys.argv[0]).name
args = sys.argv[1:]
with open(os.environ["INSTALL_EVENTS"], "a") as stream:
    stream.write(json.dumps([command, *args]) + "\\n")
def mapped(arg):
    path = Path(arg)
    if path.is_absolute() and not path.is_relative_to(source) and not path.is_relative_to(root):
        return str(root / str(path).lstrip("/"))
    return arg
if command == "systemctl":
    state_path = Path(os.environ["INSTALL_STATE"])
    state = json.loads(state_path.read_text())
    action = args[0]
    if action == "show":
        if os.environ.get("FAIL_LOOKUP"):
            sys.exit(1)
        unit = root / "etc/systemd/system" / args[-1]
        print("masked" if unit.is_symlink() else "loaded" if unit.exists() else "not-found")
        sys.exit(0)
    if action == "stop":
        if os.environ.get("FAIL_STOP") == args[1]:
            sys.exit(1)
        state["timer_active" if args[1].endswith(".timer") else "service_active"] = False
    elif action == "disable":
        state["timer_enabled"] = False
    elif action == "enable":
        if args != ["enable", "--now", "afterglow-waygate-reconcile.service"]:
            sys.exit(99)
        state["service_active"] = True
    elif action != "daemon-reload":
        sys.exit(99)
    state_path.write_text(json.dumps(state))
else:
    binary = "/usr/bin/install" if command == "install" else "/bin/rm"
    sys.exit(subprocess.run([binary, *map(mapped, args)]).returncode)
''')
        executable.chmod(0o755)
    monkeypatch.setenv("PATH", str(commands) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("INSTALL_ROOT", str(root))
    monkeypatch.setenv("INSTALL_SOURCE", str(AGENT_DIR))
    monkeypatch.setenv("INSTALL_STATE", str(state))
    monkeypatch.setenv("INSTALL_EVENTS", str(events))
    # Shell builtins bypass PATH. Relocate only the config-existence probe;
    # install/rm/systemctl still execute the real installer control flow.
    installer = tmp_path / "install.sh"
    installer.write_text((AGENT_DIR / "install.sh").read_text().replace(
        '"$DEST/etc/waygate/agent.json"', '"$INSTALL_ROOT/etc/waygate/agent.json"'
    ))
    monkeypatch.setenv("INSTALL_SCRIPT", str(installer))
    return root, state, events


@pytest.mark.parametrize("configured", [True, False])
@pytest.mark.parametrize("dest", [None, "/", "staged"])
def test_install_migrates_timer_without_touching_host_systemd(installer_runtime, dest, configured):
    root, state, events = installer_runtime
    if configured:
        config = root / "etc/waygate/agent.json"
        config.parent.mkdir(parents=True)
        config.write_text(json.dumps(_config()))
    args = ["sh", os.environ["INSTALL_SCRIPT"], str(AGENT_DIR)]
    if dest is not None:
        args.append(str(root) if dest == "staged" else dest)
    subprocess.run(args, check=True)

    units = root / "etc/systemd/system"
    assert not (units / "afterglow-waygate-reconcile.timer").exists()
    assert not (units / "timers.target.wants/afterglow-waygate-reconcile.timer").is_symlink()
    service = configparser.ConfigParser()
    service.read(units / "afterglow-waygate-reconcile.service")
    assert service["Service"]["Type"] == "simple"
    assert shlex.split(service["Service"]["ExecStart"])[-1] == "run"
    for _, target, mode in AGENT_FILES:
        assert _mode(root / target.lstrip("/")) == int(mode, 8)
    calls = [json.loads(line) for line in events.read_text().splitlines()]
    controls = [call for call in calls if call[0] == "systemctl"]
    if dest == "staged":
        assert controls == []
        assert json.loads(state.read_text()) == {
            "timer_active": True, "timer_enabled": True, "service_active": True,
        }
    else:
        assert json.loads(state.read_text()) == {
            "timer_active": False, "timer_enabled": False, "service_active": configured,
        }
        stops = [call for call in controls if call[1] in ("stop", "disable")]
        assert stops == [
            ["systemctl", "stop", "afterglow-waygate-reconcile.timer"],
            ["systemctl", "disable", "afterglow-waygate-reconcile.timer"],
            ["systemctl", "stop", "afterglow-waygate-reconcile.service"],
        ]
        first_install = next(index for index, call in enumerate(calls) if call[0] == "install")
        assert all(calls.index(call) < first_install for call in stops)
        assert ["systemctl", "daemon-reload"] in controls
        if configured:
            assert controls[-2:] == [
                ["systemctl", "daemon-reload"],
                ["systemctl", "enable", "--now", "afterglow-waygate-reconcile.service"],
            ]
        else:
            assert not any(call[1] == "enable" for call in controls)


def test_install_aborts_before_replacement_when_timer_cannot_stop(installer_runtime, monkeypatch):
    root, state, events = installer_runtime
    monkeypatch.setenv("FAIL_STOP", "afterglow-waygate-reconcile.timer")
    result = subprocess.run(["sh", os.environ["INSTALL_SCRIPT"], str(AGENT_DIR)], check=False)

    assert result.returncode != 0
    assert json.loads(state.read_text())["timer_active"] is True
    assert (root / "opt/afterglow/waygate_agent.py").read_text() == "old agent\n"
    assert (root / "etc/systemd/system/afterglow-waygate-reconcile.timer").exists()
    assert not any(json.loads(line)[0] in ("rm", "install") for line in events.read_text().splitlines())


def test_install_on_fresh_system_never_tries_to_stop_missing_units(installer_runtime):
    root, _, events = installer_runtime
    units = root / "etc/systemd/system"
    (units / "afterglow-waygate-reconcile.timer").unlink()
    (units / "afterglow-waygate-reconcile.service").unlink()
    subprocess.run(["sh", os.environ["INSTALL_SCRIPT"], str(AGENT_DIR), "/"], check=True)

    controls = [call for line in events.read_text().splitlines() if (call := json.loads(line))[0] == "systemctl"]
    assert all(call[1] not in ("stop", "disable") for call in controls)
    assert controls[-1] == ["systemctl", "daemon-reload"]


def test_interface_section_includes_gateway_address_and_port(agent):
    assert agent.interface_section(_config(), "private-key") == [
        "[Interface]",
        "Address = 10.8.0.1/24",
        "ListenPort = 51820",
        "SaveConfig = false",
        "PrivateKey = private-key",
        "",
    ]


def test_write_wg_conf_skips_disabled_peers_and_includes_psk(agent, monkeypatch, tmp_path):
    wg_conf = tmp_path / "wg0.conf"
    monkeypatch.setattr(agent, "WG_CONF", str(wg_conf))

    agent.write_wg_conf(
        _config(),
        "private-key",
        {
            "peers": [
                {"public_key": "enabled-key", "preshared_key": "psk", "allowed_ips": ["10.8.0.2/32"]},
                {"public_key": "disabled-key", "enabled": False, "allowed_ips": ["10.8.0.3/32"]},
            ]
        },
    )

    text = wg_conf.read_text()
    assert "Address = 10.8.0.1/24" in text
    assert "PublicKey = enabled-key\nPresharedKey = psk\nAllowedIPs = 10.8.0.2/32" in text
    assert "disabled-key" not in text
    assert _mode(wg_conf) == 0o600


def test_adopt_next_token_persists_before_switching(agent, monkeypatch, tmp_path):
    config_path = tmp_path / "agent.json"
    cfg = _config()
    config_path.write_text(json.dumps(cfg))
    monkeypatch.setattr(agent, "CONFIG_PATH", str(config_path))
    fsync = agent.os.fsync
    synced = {"file": False, "directory": False}

    def durable_before_adoption(fd):
        assert cfg == _config()
        if stat.S_ISDIR(agent.os.fstat(fd).st_mode):
            assert synced["file"]
            assert json.loads(config_path.read_text())["bootstrap_token"] == "new-token-abcdefghijklmnop"
            synced["directory"] = True
        else:
            synced["file"] = True
        fsync(fd)

    monkeypatch.setattr(agent.os, "fsync", durable_before_adoption)

    assert agent.adopt_next_token(cfg, {"next_token": "new-token-abcdefghijklmnop"}) is True

    assert synced["directory"]
    assert cfg["bootstrap_token"] == "new-token-abcdefghijklmnop"
    assert json.loads(config_path.read_text()) == cfg
    assert _mode(config_path) == 0o600
    assert not (tmp_path / "agent.json.tmp").exists()


def test_adopt_next_token_keeps_current_when_persist_fails(agent, monkeypatch, tmp_path):
    monkeypatch.setattr(agent, "CONFIG_PATH", str(tmp_path / "missing" / "agent.json"))
    cfg = _config()

    assert agent.adopt_next_token(cfg, {"next_token": "new-token-abcdefghijklmnop"}) is False

    assert cfg == _config()


def test_failed_directory_sync_blocks_adoption_and_later_loading(agent, monkeypatch, tmp_path):
    config_path = tmp_path / "agent.json"
    cfg = _config()
    config_path.write_text(json.dumps(cfg))
    monkeypatch.setattr(agent, "CONFIG_PATH", str(config_path))
    fsync = agent.os.fsync

    def fail_directory_sync(fd):
        if stat.S_ISDIR(agent.os.fstat(fd).st_mode):
            raise OSError("directory sync failed")
        fsync(fd)

    monkeypatch.setattr(agent.os, "fsync", fail_directory_sync)
    assert agent.adopt_next_token(cfg, {"next_token": "new-token-abcdefghijklmnop"}) is False
    assert cfg == _config()
    with pytest.raises(OSError, match="directory sync failed"):
        agent.load_config()
    monkeypatch.setattr(agent.os, "fsync", fsync)
    assert agent.load_config()["bootstrap_token"] == "new-token-abcdefghijklmnop"


@pytest.mark.parametrize("desired", [{}, {"next_token": None}, {"next_token": "current-token-abcdefghijklmnop"}])
def test_adopt_next_token_noop_when_absent_or_same(agent, monkeypatch, tmp_path, desired):
    config_path = tmp_path / "agent.json"
    monkeypatch.setattr(agent, "CONFIG_PATH", str(config_path))
    cfg = _config()

    assert agent.adopt_next_token(cfg, desired) is False

    assert cfg == _config()
    assert not config_path.exists()


def test_agent_source_prebuilt_when_image_info_exists(agent, monkeypatch, tmp_path):
    image_info = tmp_path / "image-info.json"
    monkeypatch.setattr(agent, "IMAGE_INFO_PATH", str(image_info))
    assert agent.agent_source() == "cloud-init"

    image_info.write_text("{}")
    assert agent.agent_source() == "prebuilt"


@pytest.fixture
def report_runtime(agent, monkeypatch, tmp_path):
    """Real HTTP and subprocess boundaries without touching host WireGuard."""
    requests = queue.Queue()
    response = {"status": 204, "desired": {"peers": [], "nat_networks": []}}

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.put((self.command, self.path, self.headers["Authorization"], body))
            self.send_response(response["status"])
            self.end_headers()

        def do_GET(self):
            requests.put((self.command, self.path, self.headers["Authorization"], None))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(response["desired"]).encode())

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    cfg = _config(status_url=base + "/status", desired_state_url=base + "/desired-state")
    config_path = tmp_path / "agent.json"
    config_path.write_text(json.dumps(cfg))
    monkeypatch.setattr(agent, "CONFIG_PATH", str(config_path))
    monkeypatch.setattr(agent, "IMAGE_INFO_PATH", str(tmp_path / "image-info.json"))
    dump = tmp_path / "dump"
    dump.write_text("private\tpublic\t51820\toff\n")
    wg = tmp_path / "wg"
    wg.write_text('#!/bin/sh\n[ "$*" = "show wg0 dump" ] || exit 99\ncat "$WG_DUMP"\nexit "$WG_EXIT"\n')
    wg.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path) + os.pathsep + os.environ["PATH"])
    monkeypatch.setenv("WG_DUMP", str(dump))
    monkeypatch.setenv("WG_EXIT", "0")
    try:
        yield cfg, requests, response, dump
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_report_reads_counters_and_reloads_rotated_config(agent, report_runtime):
    cfg, requests, _, dump = report_runtime
    dump.write_text(
        "private\tpublic\t51820\toff\n"
        "peer-a\tpsk\tendpoint\t10.8.0.2/32\t1700000000\t123456\t987654\t25\n"
        "peer-b\t(none)\t(none)\t10.8.0.3/32\t0\t0\t0\t0\n"
    )
    started = datetime.now(UTC)
    assert agent.cmd_report(agent.load_config()) == 0
    method, path, bearer, body = requests.get_nowait()
    assert (method, path, bearer) == ("POST", "/status", "Bearer " + cfg["bootstrap_token"])
    assert body["agent_source"] == "cloud-init"
    assert started <= datetime.fromisoformat(body["reported_at"]) <= datetime.now(UTC)
    assert body["report_interval_seconds"] == 1
    assert body["peers"] == [
        {
            "public_key": "peer-a",
            "last_handshake_at": "2023-11-14T22:13:20+00:00",
            "rx_bytes": 123456,
            "tx_bytes": 987654,
        },
        {"public_key": "peer-b", "last_handshake_at": None, "rx_bytes": 0, "tx_bytes": 0},
    ]

    assert agent.adopt_next_token(cfg, {"next_token": "rotated-token-abcdefghijklmnop"})
    Path(agent.IMAGE_INFO_PATH).write_text("{}")
    assert agent.cmd_report(agent.load_config()) == 0
    _, _, bearer, body = requests.get_nowait()
    assert bearer == "Bearer " + cfg["bootstrap_token"]
    assert body["agent_source"] == "prebuilt"
    assert requests.empty()


def test_report_distinguishes_failed_dump_from_no_peers(agent, report_runtime, monkeypatch):
    _, requests, _, _ = report_runtime
    monkeypatch.setenv("WG_EXIT", "1")
    assert agent.cmd_report(agent.load_config()) == 1
    assert requests.empty()

    monkeypatch.setenv("WG_EXIT", "0")
    assert agent.cmd_report(agent.load_config()) == 0
    assert requests.get_nowait()[3]["peers"] == []


@pytest.mark.parametrize("error", [FileNotFoundError(), subprocess.TimeoutExpired("wg", 5)])
def test_report_skips_post_when_wg_cannot_run(agent, report_runtime, monkeypatch, error):
    _, requests, _, _ = report_runtime

    def fail(*args, **kwargs):
        raise error

    monkeypatch.setattr(agent.subprocess, "run", fail)
    assert agent.cmd_report(agent.load_config()) == 1
    assert requests.empty()


@pytest.mark.parametrize("status", [401, 429, 503])
def test_report_returns_failure_on_rejected_post(agent, report_runtime, status):
    _, requests, response, _ = report_runtime
    response["status"] = status
    assert agent.cmd_report(agent.load_config()) == 1
    assert requests.get_nowait()[0:2] == ("POST", "/status")
    assert requests.empty()


def test_reconcile_applies_desired_state_without_reporting(agent, report_runtime, monkeypatch, tmp_path):
    cfg, requests, response, _ = report_runtime
    response["desired"]["next_token"] = "rotated-token-abcdefghijklmnop"
    private = tmp_path / "privatekey"
    private.write_text("private-key\n")
    wg_conf = tmp_path / "wg0.conf"
    monkeypatch.setattr(agent, "PRIVATE_KEY_PATH", str(private))
    monkeypatch.setattr(agent, "WG_CONF", str(wg_conf))
    actions = []
    monkeypatch.setattr(agent, "syncconf", lambda: actions.append("syncconf"))
    monkeypatch.setattr(agent, "apply_masquerade", lambda cidr, nets: actions.append((cidr, nets)))

    assert agent.cmd_reconcile(agent.load_config()) == 0
    assert requests.get_nowait()[0:2] == ("GET", "/desired-state")
    assert requests.empty()
    assert actions == ["syncconf", (cfg["tunnel_cidr"], [])]
    assert "PrivateKey = private-key" in wg_conf.read_text()
    assert agent.load_config()["bootstrap_token"] == "rotated-token-abcdefghijklmnop"


@pytest.mark.parametrize("install_packages", [True, False], ids=["cloud-init", "prebuilt"])
def test_installed_agent_runs_both_jobs_in_both_image_modes(report_runtime, tmp_path, install_packages):
    cfg, requests, _, _ = report_runtime
    root = tmp_path / "guest"
    if not install_packages:
        subprocess.run(["sh", str(AGENT_DIR / "install.sh"), str(AGENT_DIR), str(root)], check=True)
        (root / "etc/waygate/image-info.json").write_text("{}")
    userdata = yaml.safe_load(
        base64.b64decode(
            render_agent_userdata(
                server_name="report-gateway",
                listen_port=51820,
                tunnel_cidr="10.8.0.0/24",
                register_url=cfg["status_url"].replace("/status", "/register"),
                desired_state_url=cfg["desired_state_url"],
                status_url=cfg["status_url"],
                bootstrap_token=cfg["bootstrap_token"],
                install_packages=install_packages,
            )
        )
    )
    for entry in userdata["write_files"]:
        path = root / entry["path"].lstrip("/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(entry["content"])
        path.chmod(int(entry["permissions"], 8))

    commands = [shlex.split(command) for command in userdata["runcmd"]]
    registration = commands.index(["/usr/bin/python3", "/opt/afterglow/waygate_agent.py", "register"])
    activation = commands.index(["systemctl", "enable", "--now", "afterglow-waygate-reconcile.service"])
    assert registration < commands.index(["systemctl", "daemon-reload"]) < activation
    units = root / "etc/systemd/system"
    assert {unit.name for unit in units.iterdir()} == {"afterglow-waygate-reconcile.service"}
    service = configparser.ConfigParser()
    service.read(units / "afterglow-waygate-reconcile.service")
    assert (root / service["Unit"]["ConditionPathExists"].lstrip("/")).is_file()
    assert "wg-quick@wg0.service" in service["Unit"]["After"].split()
    assert service["Service"]["Type"] == "simple"
    assert service["Service"]["Restart"] == "on-failure"
    _, script, *args = shlex.split(service["Service"]["ExecStart"])
    assert args == ["run"]
    private = root / "etc/wireguard/privatekey"
    private.parent.mkdir(parents=True, exist_ok=True)
    private.write_text("test-private-key\n")
    # Execute the installed service entrypoint once in a separate process.
    # Stub only host-mutating wg syncconf/NAT and the blocking sleep; config,
    # HTTP request, wg show and the agent dispatch run from the installed file.
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import runpy, sys; from pathlib import Path; "
            "root = Path(sys.argv[1]); ns = runpy.run_path(str(root / sys.argv[2].lstrip('/'))); "
            "g = ns['main'].__globals__; "
            "g.update(CONFIG_PATH=str(root / 'etc/waygate/agent.json'), "
            "IMAGE_INFO_PATH=str(root / 'etc/waygate/image-info.json'), "
            "PRIVATE_KEY_PATH=str(root / 'etc/wireguard/privatekey'), "
            "WG_CONF=str(root / 'etc/wireguard/wg0.conf'), LOG=str(root / 'agent.log')); "
            "g['syncconf'] = lambda: None; g['apply_masquerade'] = lambda *args: None; "
            "g['time'].sleep = lambda _: (_ for _ in ()).throw(KeyboardInterrupt()); "
            "sys.exit(ns['main'](sys.argv[3:]))",
            str(root),
            script,
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert requests.get_nowait()[:3] == ("GET", "/desired-state", "Bearer " + cfg["bootstrap_token"])
    method, path, bearer, body = requests.get_nowait()
    assert (method, path, bearer) == ("POST", "/status", "Bearer " + cfg["bootstrap_token"])
    assert body["agent_source"] == ("cloud-init" if install_packages else "prebuilt")
    assert body["report_interval_seconds"] == 1
    assert body["peers"] == []
    assert requests.empty()


def test_run_serializes_reconcile_and_one_second_reports_with_rotated_token(
    agent, report_runtime, monkeypatch, tmp_path
):
    cfg, requests, response, _ = report_runtime
    response["desired"]["next_token"] = "rotated-token-abcdefghijklmnop"
    private = tmp_path / "privatekey"
    private.write_text("private-key\n")
    monkeypatch.setattr(agent, "PRIVATE_KEY_PATH", str(private))
    monkeypatch.setattr(agent, "WG_CONF", str(tmp_path / "wg0.conf"))
    monkeypatch.setattr(agent, "syncconf", lambda: None)
    monkeypatch.setattr(agent, "apply_masquerade", lambda *args: None)
    clock = SimpleNamespace(now=0.0)

    def advance(seconds):
        assert seconds >= 0
        clock.now += seconds
        if clock.now >= 16:
            raise KeyboardInterrupt

    monkeypatch.setattr(agent, "time", SimpleNamespace(monotonic=lambda: clock.now, sleep=advance))
    assert agent.main(["run"]) == 0
    calls = []
    while not requests.empty():
        calls.append(requests.get_nowait())
    assert [call[0] for call in calls] == ["GET", "POST", *["POST"] * 14, "GET", "POST"]
    assert calls[0][2] == "Bearer " + cfg["bootstrap_token"]
    assert all(call[2] == "Bearer " + response["desired"]["next_token"] for call in calls[1:])
    assert all(call[3]["report_interval_seconds"] == 1 for call in calls if call[0] == "POST")


@pytest.mark.parametrize("interval,expected_reports", [(2, 8), (60, 1)])
def test_run_uses_configured_report_interval_without_extra_reconciles(
    agent,
    report_runtime,
    monkeypatch,
    interval,
    expected_reports,
):
    cfg, requests, _, _ = report_runtime
    Path(agent.CONFIG_PATH).write_text(json.dumps(cfg | {"report_interval_seconds": interval}))
    clock = SimpleNamespace(now=0.0)

    def advance(seconds):
        clock.now += seconds
        if clock.now >= 15:
            raise KeyboardInterrupt

    reconciles = []
    monkeypatch.setattr(agent, "cmd_reconcile", lambda config: reconciles.append(clock.now))
    monkeypatch.setattr(agent, "time", SimpleNamespace(monotonic=lambda: clock.now, sleep=advance))
    assert agent.main(["run"]) == 0
    calls = []
    while not requests.empty():
        calls.append(requests.get_nowait())
    assert reconciles == [0.0]
    assert len(calls) == expected_reports
    assert all(call[3]["report_interval_seconds"] == interval for call in calls)


@pytest.mark.parametrize("interval", [True, 0, 61, "1", 1.5])
def test_run_rejects_invalid_reporting_interval(agent, interval):
    with pytest.raises(ValueError, match="report_interval_seconds"):
        agent.report_interval({"report_interval_seconds": interval})


def test_agent_dispatch_exposes_only_register_and_run(agent):
    assert agent.main(["reconcile"]) == 2
    assert agent.main(["report"]) == 2


def test_install_removes_masked_obsolete_timer(installer_runtime):
    root, state, _ = installer_runtime
    timer = root / "etc/systemd/system/afterglow-waygate-reconcile.timer"
    timer.unlink()
    timer.symlink_to("/dev/null")
    subprocess.run(["sh", os.environ["INSTALL_SCRIPT"], str(AGENT_DIR), "/"], check=True)

    assert not timer.is_symlink()
    assert json.loads(state.read_text())["timer_active"] is False
    assert json.loads(state.read_text())["timer_enabled"] is False


def test_install_aborts_before_replacement_when_service_manager_unavailable(installer_runtime, monkeypatch):
    root, _, events = installer_runtime
    monkeypatch.setenv("FAIL_LOOKUP", "1")
    result = subprocess.run(["sh", os.environ["INSTALL_SCRIPT"], str(AGENT_DIR), "/"], check=False)

    assert result.returncode != 0
    assert (root / "opt/afterglow/waygate_agent.py").read_text() == "old agent\n"
    assert not any(json.loads(line)[0] in ("rm", "install") for line in events.read_text().splitlines())


def test_slow_reconcile_delays_reports_without_catchup_burst(agent, report_runtime, monkeypatch):
    _, requests, _, _ = report_runtime
    clock = SimpleNamespace(now=0.0)
    reconciles = []
    report_times = []
    report = agent.cmd_report

    def slow_reconcile(_cfg):
        reconciles.append(clock.now)
        clock.now += 20

    def sample(cfg):
        report_times.append(clock.now)
        return report(cfg)

    def advance(seconds):
        clock.now += seconds
        if clock.now >= 56:
            raise KeyboardInterrupt

    monkeypatch.setattr(agent, "cmd_reconcile", slow_reconcile)
    monkeypatch.setattr(agent, "cmd_report", sample)
    monkeypatch.setattr(agent, "time", SimpleNamespace(monotonic=lambda: clock.now, sleep=advance))

    assert agent.main(["run"]) == 0
    assert reconciles == [0, 35]
    assert report_times == [*range(20, 35), 55]
    bodies = []
    while not requests.empty():
        bodies.append(requests.get_nowait()[3])
    assert all(body["report_interval_seconds"] == 1 and body["peers"] == [] for body in bodies)


def test_run_resumes_after_failed_reconcile_and_status_post(agent, report_runtime, monkeypatch):
    _, requests, response, _ = report_runtime
    clock = SimpleNamespace(now=0.0)
    reconciles = []
    response["status"] = 503

    def failing_reconcile(_cfg):
        reconciles.append(clock.now)
        raise OSError("temporary desired-state failure")

    def advance(seconds):
        clock.now += seconds
        response["status"] = 204
        if clock.now >= 2:
            raise KeyboardInterrupt

    monkeypatch.setattr(agent, "cmd_reconcile", failing_reconcile)
    monkeypatch.setattr(agent, "time", SimpleNamespace(monotonic=lambda: clock.now, sleep=advance))

    assert agent.main(["run"]) == 0
    assert reconciles == [0]
    first, second = requests.get_nowait(), requests.get_nowait()
    assert first[:3] == second[:3] == ("POST", "/status", "Bearer " + agent.load_config()["bootstrap_token"])
    assert first[3]["peers"] == second[3]["peers"] == []
    assert requests.empty()
