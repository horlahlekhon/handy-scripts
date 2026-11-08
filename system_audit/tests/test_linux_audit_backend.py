import stat
import subprocess
import threading
import time
from pathlib import Path

import pytest

from credwatch.backends.base import BackendError
from credwatch.backends.linux_audit import (
    LinuxAuditBackend,
    count_loaded_rules,
    ensure_auditd,
    install_rules,
    render_rules,
)

FIXTURES = Path(__file__).parent / "fixtures"


class FakeRunner:
    def __init__(self, responses=None):
        self.responses = responses or {}
        self.calls = []

    def run(self, argv, *, check=False, timeout=60):
        self.calls.append(tuple(argv))
        for prefix, results in self.responses.items():
            if tuple(argv[: len(prefix)]) == prefix:
                res = results.pop(0) if isinstance(results, list) and len(results) > 1 else (
                    results[0] if isinstance(results, list) else results
                )
                return subprocess.CompletedProcess(argv, *res)
        return subprocess.CompletedProcess(argv, 0, "", "")

    def count(self, prefix):
        return sum(1 for c in self.calls if c[: len(prefix)] == prefix)


def test_render_rules_exact_format():
    out = render_rules([Path("/a/b"), Path("/c")])
    assert "-w /a/b -p rwa -k credwatch\n-w /c -p rwa -k credwatch\n" in out.text
    assert out.text.startswith("#")
    assert out.skipped == ()


def test_render_rules_skips_whitespace_paths(caplog):
    out = render_rules([Path("/ok"), Path("/has space/x")])
    assert out.skipped == (Path("/has space/x"),)
    assert "has space" not in out.text
    assert "WARNING" in caplog.text or caplog.records


@pytest.mark.parametrize("ch", ["\n", "\x00", "\x7f", "\x85", " ", " ", "\t"])
def test_render_rules_skips_control_char_paths(ch):
    evil = Path(f"/tmp/x{ch}-w /etc/shadow -p rwa -k credwatch")
    out = render_rules([evil, Path("/ok")])
    assert out.skipped == (evil,)
    assert out.text.count("-w ") == 1


def test_install_rules_idempotent(tmp_path):
    rules = tmp_path / "credwatch.rules"
    runner = FakeRunner({("auditctl", "-s"): [(0, "enabled 1\n", "")]})
    assert install_rules([Path("/a")], rules, runner=runner) is True
    assert install_rules([Path("/a")], rules, runner=runner) is False
    assert runner.count(("augenrules", "--load")) == 1
    assert stat.S_IMODE(rules.stat().st_mode) == 0o640
    assert list(tmp_path.iterdir()) == [rules]


def test_install_rules_immutable_raises(tmp_path):
    rules = tmp_path / "credwatch.rules"
    runner = FakeRunner({("auditctl", "-s"): [(0, "enabled 2\n", "")]})
    with pytest.raises(BackendError, match="immutable"):
        install_rules([Path("/a")], rules, runner=runner)
    assert not rules.exists()
    assert runner.count(("augenrules",)) == 0


def test_install_rules_augenrules_failure_raises(tmp_path):
    runner = FakeRunner({("augenrules",): [(1, "", "boom")]})
    with pytest.raises(BackendError, match="boom"):
        install_rules([Path("/a")], tmp_path / "r", runner=runner)


def test_ensure_auditd_failure_includes_stderr():
    with pytest.raises(BackendError, match="no unit"):
        ensure_auditd(FakeRunner({("systemctl",): [(1, "", "no unit")]}))
    ensure_auditd(FakeRunner())


def test_count_loaded_rules():
    out = "-w /a -p rwa -k credwatch\n-w /b -p rwa -k other\n-w /c -p rwa -k credwatch\n"
    assert count_loaded_rules(FakeRunner({("auditctl", "-l"): [(0, out, "")]})) == 2
    with pytest.raises(BackendError):
        count_loaded_rules(FakeRunner({("auditctl", "-l"): [(1, "", "denied")]}))


def make_backend(tmp_path, runner, expected=2, **kw):
    return LinuxAuditBackend(tmp_path / "audit.log", expected, runner, tmp_path / "ckpt", **kw)


def test_health_reports_missing_rules(tmp_path):
    runner = FakeRunner({("auditctl", "-l"): [(0, "-w /a -p rwa -k credwatch\n", "")]})
    assert make_backend(tmp_path, runner).health() == (
        "loaded credwatch audit rules: 1, expected 2",
    )


def test_health_ok_and_error(tmp_path):
    ok = FakeRunner({("auditctl", "-l"): [(0, "-w /a -k credwatch\n-w /b -k credwatch\n", "")]})
    assert make_backend(tmp_path, ok).health() == ()
    bad = FakeRunner({("auditctl", "-l"): [(1, "", "denied")]})
    assert "denied" in make_backend(tmp_path, bad).health()[0]


def test_export_no_matches_returns_none(tmp_path):
    runner = FakeRunner({("ausearch",): [(1, "", "<no matches>\n")]})
    assert make_backend(tmp_path, runner).export_native_log(tmp_path / "out") is None


def test_export_falls_back_when_checkpoint_invalid(tmp_path, caplog):
    (tmp_path / "ckpt").write_text("x")
    runner = FakeRunner({("ausearch",): [(10, "", "bad checkpoint"), (0, "type=SYSCALL x\n", "")]})
    out = make_backend(tmp_path, runner).export_native_log(tmp_path / "out")
    assert out is not None and out.read_text() == "type=SYSCALL x\n"
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert out.name.startswith("ausearch-") and out.suffix == ".txt"
    first, second = runner.calls
    assert first[-2:] == ("-ts", "checkpoint") and second[-2:] == ("-ts", "today")
    assert "--checkpoint" in first and str(tmp_path / "ckpt") in first
    assert "WARNING" in [r.levelname for r in caplog.records]


def test_export_uses_today_without_checkpoint_and_raises_on_failure(tmp_path):
    runner = FakeRunner({("ausearch",): [(2, "", "weird")]})
    with pytest.raises(BackendError, match="weird"):
        make_backend(tmp_path, runner).export_native_log(tmp_path / "out")
    assert runner.calls[0][-2:] == ("-ts", "today")


def test_backend_flushes_stale_group_without_new_lines(tmp_path):
    group = [
        ln for ln in (FIXTURES / "audit_enriched.log").read_text().split("\n")
        if "4567" in ln and "type=EOE" not in ln
    ]
    log = tmp_path / "audit.log"
    log.write_text("")
    backend = make_backend(tmp_path, FakeRunner(), flush_after=0.2)
    stop = threading.Event()
    got = []

    def consume():
        for ev in backend.events(stop):
            got.append(ev)
            stop.set()

    t = threading.Thread(target=consume)
    t.start()
    time.sleep(0.1)
    with open(log, "a") as fh:
        fh.write("\n".join(group) + "\n")
    t.join(timeout=5)
    stop.set()
    assert not t.is_alive()
    assert len(got) == 1
