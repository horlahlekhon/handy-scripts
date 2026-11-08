from __future__ import annotations

import csv
import io
import json
import os
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml

from credwatch import cli
from credwatch.alert import MailerError
from credwatch.backends import get_backend
from credwatch.backends.base import Backend, BackendError
from credwatch.backends.linux_audit import LinuxAuditBackend
from credwatch.config import load_config
from credwatch.models import Connection, FileAccessEvent, NetworkSnapshot, ProcessedEvent, Verdict
from credwatch.platform_info import TargetUser
from credwatch.store import Store

NOW = datetime.now(UTC)


class FakeRunner:
    def __init__(self, stdout="active\n", rc=0):
        self.calls = []
        self._out, self._rc = stdout, rc

    def run(self, argv, *, check=False, timeout=60):
        self.calls.append(list(argv))
        return subprocess.CompletedProcess(list(argv), self._rc, self._out, "")


class FakeBackend(Backend):
    name = "fake"

    def __init__(self, problems=()):
        self._problems = tuple(problems)

    def events(self, stop):
        return iter(())

    def export_native_log(self, dest_dir):
        return None

    def health(self):
        return self._problems


def ev(path="/h/.aws/credentials", exe="/usr/bin/curl", ts=None, **kw):
    return FileAccessEvent(
        timestamp=ts or NOW - timedelta(minutes=5), path=path, pid=42, ppid=1, exe=exe,
        comm=exe.rsplit("/", 1)[-1], success=True, backend="fake", raw="raw", inode=7, dev=8, **kw,
    )


def pe(allowed, snapshot=None, **kw):
    canonical = kw.pop("canonical_path", None)
    return ProcessedEvent(ev(**kw), Verdict(allowed, None if not allowed else "rule"), snapshot, canonical)


@pytest.fixture
def env(tmp_path, monkeypatch):
    data = tmp_path / "data"
    cfg = tmp_path / "config.yaml"
    cfg.write_text(yaml.safe_dump({
        "data_dir": str(data),
        "email": {"from_addr": "a@b.c", "to_addrs": ["x@y.z"]},
    }))
    wl = tmp_path / "watch.txt"
    wl.write_text("/h/.aws/credentials\n/h/.ssh\n")
    monkeypatch.setattr(cli, "WATCH_LIST_PATH", wl)
    monkeypatch.setattr(cli, "_is_root", lambda: True)
    monkeypatch.setattr(cli, "SECRETS_PATH", tmp_path / "nosecrets")
    monkeypatch.setattr(cli, "SubprocessRunner", FakeRunner)
    monkeypatch.setattr(cli, "get_backend", lambda c, w, r: FakeBackend())
    monkeypatch.delenv("CREDWATCH_SMTP_USER", raising=False)
    monkeypatch.delenv("CREDWATCH_SMTP_PASSWORD", raising=False)
    monkeypatch.setattr(cli, "PROBE_TIMEOUT_SECONDS", 0.2)
    monkeypatch.setattr(cli, "PROBE_POLL_SECONDS", 0.05)
    data.mkdir(mode=0o700)
    data.chmod(0o700)
    return {"argv": ["--config", str(cfg)], "data": data, "tmp": tmp_path}


def seed(env, *events, heartbeat=True, meta=None):
    store = Store(env["data"] / "events.db")
    for e in events:
        store.record(e)
    if heartbeat:
        store.set_meta("heartbeat", datetime.now(UTC).isoformat())
    for k, v in (meta or {}).items():
        store.set_meta(k, v)
    store.close()


def snap():
    return NetworkSnapshot(42, NOW, True, (Connection("ipv4", "tcp", "1.1.1.1:1", "2.2.2.2:2", "ESTABLISHED"),), (), None)


# --- parse_duration -------------------------------------------------------------


@pytest.mark.parametrize("text,expected", [
    ("30m", timedelta(minutes=30)), ("12h", timedelta(hours=12)),
    ("7d", timedelta(days=7)), ("2w", timedelta(weeks=2)),
])
def test_parse_duration_units(text, expected):
    assert cli.parse_duration(text) == expected


@pytest.mark.parametrize("text", ["", "abc", "5", "5x", "-1d", "0d", "1.5h"])
def test_parse_duration_rejects_garbage(text):
    with pytest.raises(Exception) as ei:
        cli.parse_duration(text)
    assert "invalid duration" in str(ei.value)


# --- report ---------------------------------------------------------------------


def test_report_flagged_json(env, capsys):
    seed(env, pe(False, snapshot=snap(), canonical_path="/real"), pe(True), pe(False))
    assert cli.main([*env["argv"], "report", "--last", "1h", "--flagged", "--format", "json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert len(data) == 2 and all(r["allowed"] is False for r in data)
    first = next(r for r in data if r["snapshot"])
    assert first["canonical_path"] == "/real" and first["inode"] == 7 and first["dev"] == 8
    assert first["snapshot"]["connections"][0]["raddr"] == "2.2.2.2:2"


def test_report_csv_header(env, capsys):
    seed(env, pe(False))
    assert cli.main([*env["argv"], "report", "--last", "1h", "--format", "csv"]) == 0
    rows = list(csv.reader(io.StringIO(capsys.readouterr().out)))
    assert tuple(rows[0]) == cli.CSV_COLUMNS and len(rows) == 2


def test_report_csv_neutralizes_formulas_and_controls(env, capsys):
    seed(env, pe(False, path="=cmd|' /C calc'!A0\x1b[31m", exe="@evil"))
    cli.main([*env["argv"], "report", "--last", "1h", "--format", "csv"])
    out = capsys.readouterr().out
    assert "\x1b" not in out and "'=cmd" in out and "'@evil" in out


def test_report_table_escapes_controls(env, capsys):
    seed(env, pe(False, path="/h/a\nb\x1b"))
    cli.main([*env["argv"], "report", "--last", "1h"])
    out = capsys.readouterr().out
    assert "\x1b" not in out and "a\\nb" in out and "FLAGGED" in out


def test_report_process_filter_and_window(env, capsys):
    seed(env, pe(False, exe="/usr/bin/curl"), pe(False, exe="/usr/bin/wget"),
         pe(False, exe="/usr/bin/curl", ts=NOW - timedelta(days=3)))
    cli.main([*env["argv"], "report", "--last", "1d", "--process", "curl", "--format", "json"])
    assert len(json.loads(capsys.readouterr().out)) == 1


def test_report_output_is_0600_and_refuses_symlink(env, capsys):
    seed(env, pe(False))
    out = env["tmp"] / "r.json"
    out.write_text("old")
    out.chmod(0o644)
    assert cli.main([*env["argv"], "report", "--last", "1h", "--format", "json", "--output", str(out)]) == 0
    assert (out.stat().st_mode & 0o777) == 0o600 and json.loads(out.read_text())
    target = env["tmp"] / "victim"
    target.write_text("keep")
    link = env["tmp"] / "link"
    link.symlink_to(target)
    assert cli.main([*env["argv"], "report", "--last", "1h", "--output", str(link)]) == 1
    assert target.read_text() == "keep"


def test_report_requires_root(env, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_is_root", lambda: False)
    assert cli.main([*env["argv"], "report", "--last", "1h"]) == 2
    assert "requires root" in capsys.readouterr().err


# --- status ---------------------------------------------------------------------


def test_status_healthy(env, capsys):
    seed(env, pe(False), pe(True), meta={
        "health_alert_state": json.dumps({"canary": {"problems": ["boom"], "sent_at": 1.0}}),
        "last_alert_error": "2026 smtp\x1b down",
    })
    (env["data"] / "captures").mkdir()
    (env["data"] / "captures" / "credwatch-20260101-000000.pcap").write_text("x")
    assert cli.main([*env["argv"], "status"]) == 0
    out = capsys.readouterr().out
    assert "service:          active" in out and "2 total, 1 flagged" in out
    assert "canary: boom" in out and "\x1b" not in out and "1 files" in out


def test_status_degraded_when_heartbeat_stale(env, capsys):
    stale = (datetime.now(UTC) - timedelta(seconds=600)).isoformat()
    seed(env, heartbeat=False, meta={"heartbeat": stale})
    assert cli.main([*env["argv"], "status"]) == 1
    assert "stale" in capsys.readouterr().out


def test_status_degraded_when_no_heartbeat(env):
    seed(env, heartbeat=False)
    assert cli.main([*env["argv"], "status"]) == 1


def test_status_degraded_on_backend_problems(env, monkeypatch):
    seed(env)
    monkeypatch.setattr(cli, "get_backend", lambda c, w, r: FakeBackend(("rules missing",)))
    assert cli.main([*env["argv"], "status"]) == 1


def test_status_requires_root(env, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_is_root", lambda: False)
    assert cli.main([*env["argv"], "status"]) == 2
    assert "status requires root (sudo credwatch status)" in capsys.readouterr().err


def test_status_probe_ok(env, capsys):
    canary = env["data"] / "canary"
    canary.write_text("x")
    seed(env)

    def reader_event():
        store = Store(env["data"] / "events.db")
        store.record(pe(False, path=str(canary), ts=datetime.now(UTC) + timedelta(seconds=1)))
        store.close()

    import threading
    t = threading.Timer(0.05, reader_event)
    t.start()
    try:
        assert cli.main([*env["argv"], "status", "--probe"]) == 0
    finally:
        t.join()
    assert "probe: ok" in capsys.readouterr().out


def test_status_probe_fails_without_event(env, capsys):
    (env["data"] / "canary").write_text("x")
    seed(env)
    assert cli.main([*env["argv"], "status", "--probe"]) == 1
    assert "FAILED" in capsys.readouterr().out


def test_status_probe_fails_when_canary_unreadable(env):
    seed(env)
    assert cli.main([*env["argv"], "status", "--probe"]) == 1


def test_service_state_darwin_uses_launchctl(env):
    cfg = load_config(Path(env["argv"][1]), "darwin", TargetUser("u", 1, 1, Path("/h")))
    r = FakeRunner()
    assert cli._service_state(cfg, r) == "running"
    assert r.calls == [["launchctl", "print", "system/com.credwatch.daemon"]]


# --- run ------------------------------------------------------------------------


class Recorder:
    last = None

    def __init__(self, *a, **kw):
        self.args, self.kw = a, kw
        type(self).last = self


class FakeDaemon(Recorder):
    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.problems, self.alert_errors, self.stops = [], [], []

    def run(self, stop):
        self.stops.append(stop)

    def report_problem(self, m):
        self.problems.append(m)

    def report_alert_error(self, m):
        self.alert_errors.append(m)


@pytest.fixture
def run_env(env, monkeypatch):
    class Disp(Recorder):
        pass

    class Cap(Recorder):
        pass

    monkeypatch.setattr(cli, "Daemon", FakeDaemon)
    monkeypatch.setattr(cli, "AlertDispatcher", Disp)
    monkeypatch.setattr(cli, "CaptureSupervisor", Cap)
    monkeypatch.setattr(cli.logging_setup, "configure", lambda *a, **k: None)
    return {**env, "disp": Disp, "cap": Cap}


def test_run_requires_root(env, monkeypatch, capsys):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    monkeypatch.setattr(cli, "_is_root", lambda: os.geteuid() == 0)
    assert cli.main([*env["argv"], "run"]) == 2
    assert "credwatch run must be run as root" in capsys.readouterr().err


def test_run_wires_hooks_late_bound_and_survives_missing_credentials(run_env, caplog):
    assert cli.main([*run_env["argv"], "run"]) == 0
    daemon = FakeDaemon.last
    run_env["cap"].last.kw["on_failure"]("tcpdump died")
    run_env["disp"].last.kw["on_error"]("smtp down")
    assert daemon.problems == ["tcpdump died"] and daemon.alert_errors == ["smtp down"]
    assert daemon.stops and daemon.stops[0].is_set() is False
    store = Store(run_env["data"] / "events.db")
    assert "CREDWATCH_SMTP_USER" in store.get_meta("last_alert_error")
    store.close()
    assert any(r.levelname == "CRITICAL" for r in caplog.records)


def test_run_mailer_factory_loads_credentials_lazily(run_env, monkeypatch):
    monkeypatch.setenv("CREDWATCH_SMTP_USER", "u")
    monkeypatch.setenv("CREDWATCH_SMTP_PASSWORD", "pw")
    assert cli.main([*run_env["argv"], "run"]) == 0
    mailer = run_env["disp"].last.kw["mailer_factory"]()
    assert "pw" not in repr(mailer)
    store = Store(run_env["data"] / "events.db")
    assert store.get_meta("last_alert_error") is None
    store.close()


def test_run_watch_list_option_overrides_default_file(run_env, monkeypatch, tmp_path):
    seen = []
    monkeypatch.setattr(cli, "get_backend", lambda c, w, r: seen.append(tuple(w)) or FakeBackend())
    custom = tmp_path / "custom-watch.txt"
    custom.write_text("/only/this\n")
    assert cli.main([*run_env["argv"], "run", "--watch-list", str(custom)]) == 0
    assert seen == [(Path("/only/this"),)]


def test_run_watch_list_option_is_hidden_from_help(capsys):
    with pytest.raises(SystemExit):
        cli.main(["run", "--help"])
    assert "--watch-list" not in capsys.readouterr().out


def test_run_startup_failure_returns_nonzero(run_env, monkeypatch, capsys):
    def boom(c, w, r):
        raise BackendError("no backend here")

    monkeypatch.setattr(cli, "get_backend", boom)
    assert cli.main([*run_env["argv"], "run"]) == 1
    assert "no backend here" in capsys.readouterr().err


def test_late_binding_before_daemon_exists_only_logs(caplog):
    ref = cli._DaemonRef()
    ref.problem("p")
    ref.alert_error("e")
    assert len(caplog.records) == 2


# --- test-email -----------------------------------------------------------------


def test_test_email_failure_does_not_print_password(env, monkeypatch, capsys):
    monkeypatch.setenv("CREDWATCH_SMTP_USER", "me@example.com")
    monkeypatch.setenv("CREDWATCH_SMTP_PASSWORD", "hunter2secret")

    class Boom:
        def __init__(self, cfg, creds):
            pass

        def send(self, subject, body):
            raise MailerError("login failed for me@example.com with hunter2secret")

    monkeypatch.setattr(cli, "Mailer", Boom)
    assert cli.main([*env["argv"], "test-email"]) == 1
    err = capsys.readouterr().err
    assert "MailerError" in err and "hunter2secret" not in err and "me@example.com" not in err


def test_test_email_success_subject(env, monkeypatch, capsys):
    monkeypatch.setenv("CREDWATCH_SMTP_USER", "u")
    monkeypatch.setenv("CREDWATCH_SMTP_PASSWORD", "p")
    sent = []

    class Ok:
        def __init__(self, cfg, creds):
            pass

        def send(self, subject, body):
            sent.append(subject)

    monkeypatch.setattr(cli, "Mailer", Ok)
    assert cli.main([*env["argv"], "test-email"]) == 0
    assert sent[0].startswith("[credwatch][") and sent[0].endswith("] test email")


def test_test_email_missing_credentials(env, capsys):
    assert cli.main([*env["argv"], "test-email"]) == 1
    assert "CredentialsError" in capsys.readouterr().err


# --- install --------------------------------------------------------------------


def test_install_without_installer_exits_2(env, monkeypatch, capsys):
    import sys
    monkeypatch.setitem(sys.modules, "credwatch.installer", None)
    assert cli.main([*env["argv"], "install"]) == 2
    assert "installer not available yet" in capsys.readouterr().err


def _fake_install(monkeypatch, report=None, error=None):
    import credwatch.installer as installer_mod
    calls = []

    def fake(os_name, target, *, runner, start=True, **kw):
        calls.append((os_name, target, runner, start))
        if error is not None:
            raise error
        return report

    monkeypatch.setattr(installer_mod, "run_install", fake)
    return calls


def test_install_builds_args_and_prints_report(env, monkeypatch, capsys):
    import os
    from credwatch.installer import InstallReport
    import pwd
    me = pwd.getpwuid(os.getuid()).pw_name
    report = InstallReport(
        created=("directory /var/lib/credwatch",), unchanged=("file /etc/credwatch/config.yaml",),
        warnings=("fill in secrets",), watched=4, skipped=(Path("/h/a b/.env"),),
    )
    calls = _fake_install(monkeypatch, report)
    assert cli.main([*env["argv"], "install", "--user", me, "--no-start"]) == 0
    os_name, target, runner, start = calls[0]
    assert os_name == "linux" and target.name == me and start is False
    assert isinstance(runner, FakeRunner)
    out, err = capsys.readouterr()
    assert "created:   directory /var/lib/credwatch" in out
    assert "unchanged: file /etc/credwatch/config.yaml" in out
    assert "watched:   4 paths" in out
    assert "skipped:   /h/a b/.env" in out
    assert "warning:   fill in secrets" in err


def test_install_error_exits_nonzero(env, monkeypatch, capsys):
    from credwatch.installer import InstallError
    _fake_install(monkeypatch, error=InstallError("audit rules are immutable (-e 2)"))
    assert cli.main([*env["argv"], "install"]) == 1
    assert "immutable (-e 2)" in capsys.readouterr().err


def test_install_unknown_user_exits_nonzero(env, monkeypatch, capsys):
    _fake_install(monkeypatch)
    assert cli.main([*env["argv"], "install", "--user", "no-such-user-credwatch"]) == 1
    assert "no such user" in capsys.readouterr().err


# --- get_backend ----------------------------------------------------------------


def _cfg(env, os_name):
    return load_config(Path(env["argv"][1]), os_name, TargetUser("u", 1, 1, Path("/h")))


def test_get_backend_linux(env):
    b = get_backend(_cfg(env, "linux"), [Path("/h/a"), Path("/h/b c")], FakeRunner())
    assert isinstance(b, LinuxAuditBackend) and b._expected == 1


def test_get_backend_darwin_unavailable(env):
    with pytest.raises(BackendError, match="macOS backend not available"):
        get_backend(_cfg(env, "darwin"), [], FakeRunner())


def test_install_other_import_error_is_not_masked(env, monkeypatch):
    import builtins
    real = builtins.__import__

    def fake(name, *a, **k):
        if name == "credwatch.installer":
            raise ModuleNotFoundError("No module named 'yaml2'", name="yaml2")
        return real(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake)
    with pytest.raises(ModuleNotFoundError):
        cli.main([*env["argv"], "install"])


def test_status_and_report_do_not_create_db(env, capsys):
    assert cli.main([*env["argv"], "status"]) == 1
    assert cli.main([*env["argv"], "report", "--last", "1h"]) == 1
    assert "no event database at" in capsys.readouterr().err
    assert not (env["data"] / "events.db").exists()


def test_cell_prefixes_only_strings():
    assert cli._cell(-5) == "-5"
    assert cli._cell("-5") == "'-5"


def test_report_csv_negative_pid_not_prefixed(env, capsys):
    store = Store(env["data"] / "events.db")
    e = ev()
    store.record(ProcessedEvent(FileAccessEvent(**{**e.__dict__, "pid": -1}), Verdict(False, None), None))
    store.close()
    cli.main([*env["argv"], "report", "--last", "1h", "--format", "csv"])
    row = list(csv.DictReader(io.StringIO(capsys.readouterr().out)))[0]
    assert row["pid"] == "-1"


def test_run_daemon_crash_returns_1(run_env, monkeypatch, capsys):
    def crash(self, stop):
        raise RuntimeError("kaboom")

    monkeypatch.setattr(FakeDaemon, "run", crash)
    assert cli.main([*run_env["argv"], "run"]) == 1
    assert "kaboom" in capsys.readouterr().err


def test_status_ignores_failing_service_probe(env, monkeypatch, capsys):
    class Exploding(FakeRunner):
        def run(self, argv, *, check=False, timeout=60):
            raise subprocess.TimeoutExpired(argv, 1)

    monkeypatch.setattr(cli, "SubprocessRunner", Exploding)
    seed(env)
    assert cli.main([*env["argv"], "status"]) == 0
    assert "unknown (TimeoutExpired)" in capsys.readouterr().out
