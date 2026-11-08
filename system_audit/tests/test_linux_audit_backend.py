import stat
import subprocess
import threading
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
    caplog.set_level("WARNING")
    out = render_rules([Path("/ok"), Path("/has space/x")])
    assert out.skipped == (Path("/has space/x"),)
    assert "has space" not in out.text
    assert any(r.levelname == "WARNING" and "has space" in r.getMessage() for r in caplog.records)


@pytest.mark.parametrize("ch", ["\n", "\x00", "\x7f", "\x85", " ", " ", "\t"])
def test_render_rules_skips_control_char_paths(ch):
    evil = Path(f"/tmp/x{ch}-w /etc/shadow -p rwa -k credwatch")
    out = render_rules([evil, Path("/ok")])
    assert out.skipped == (evil,)
    assert out.text.count("-w ") == 1


ONE_RULE = "-w /a -p rwa -k credwatch\n"


def test_install_rules_idempotent(tmp_path):
    rules = tmp_path / "credwatch.rules"
    runner = FakeRunner({
        ("auditctl", "-s"): [(0, "enabled 1\n", "")],
        ("auditctl", "-l"): [(0, ONE_RULE, "")],
    })
    assert install_rules([Path("/a")], rules, runner=runner) is True
    assert install_rules([Path("/a")], rules, runner=runner) is False
    assert runner.count(("augenrules", "--load")) == 1
    assert stat.S_IMODE(rules.stat().st_mode) == 0o640
    assert list(tmp_path.iterdir()) == [rules]


def test_reload_when_file_current_but_kernel_flushed(tmp_path):
    rules = tmp_path / "credwatch.rules"
    rules.write_text(render_rules([Path("/a")]).text)
    runner = FakeRunner({("auditctl", "-l"): [(0, "", ""), (0, ONE_RULE, "")]})
    assert install_rules([Path("/a")], rules, runner=runner) is True
    assert runner.count(("augenrules", "--load")) == 1


def test_rerun_after_failed_augenrules_reloads(tmp_path):
    rules = tmp_path / "credwatch.rules"
    runner = FakeRunner({
        ("augenrules",): [(1, "", "boom"), (0, "", "")],
        ("auditctl", "-l"): [(0, "", ""), (0, ONE_RULE, "")],
    })
    with pytest.raises(BackendError, match="boom"):
        install_rules([Path("/a")], rules, runner=runner)
    assert install_rules([Path("/a")], rules, runner=runner) is True
    assert runner.count(("augenrules", "--load")) == 2


def test_post_load_count_mismatch_raises(tmp_path):
    runner = FakeRunner({("auditctl", "-l"): [(0, "", "")]})
    with pytest.raises(BackendError, match="loaded 0 credwatch rules, expected 1"):
        install_rules([Path("/a")], tmp_path / "r", runner=runner)


def test_install_rules_immutable_raises(tmp_path):
    rules = tmp_path / "credwatch.rules"
    runner = FakeRunner({("auditctl", "-s"): [(0, "enabled 2\n", "")]})
    with pytest.raises(BackendError, match="immutable"):
        install_rules([Path("/a")], rules, runner=runner)
    assert not rules.exists()
    assert runner.count(("augenrules",)) == 0


def test_immutable_checked_on_reload_with_current_file(tmp_path):
    rules = tmp_path / "credwatch.rules"
    rules.write_text(render_rules([Path("/a")]).text)
    runner = FakeRunner({("auditctl", "-s"): [(0, "enabled 2\n", "")]})
    with pytest.raises(BackendError, match="immutable"):
        install_rules([Path("/a")], rules, runner=runner)


def test_auditctl_status_failure_warns(tmp_path, caplog):
    caplog.set_level("WARNING")
    runner = FakeRunner({
        ("auditctl", "-s"): [(1, "", "nope")],
        ("auditctl", "-l"): [(0, ONE_RULE, "")],
    })
    install_rules([Path("/a")], tmp_path / "r", runner=runner)
    assert any(r.levelname == "WARNING" and "auditctl -s" in r.getMessage() for r in caplog.records)


def test_install_rules_missing_parent_dir_raises_backend_error(tmp_path):
    with pytest.raises(BackendError, match="cannot write"):
        install_rules([Path("/a")], tmp_path / "nodir" / "r", runner=FakeRunner())


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


def test_export_write_failure_restores_checkpoint(tmp_path):
    ckpt = tmp_path / "ckpt"
    ckpt.write_bytes(b"old")

    class Advancing(FakeRunner):
        def run(self, argv, **kw):
            ckpt.write_bytes(b"new")
            return super().run(argv, **kw)

    runner = Advancing({("ausearch",): [(0, "data\n", "")]})
    blocker = tmp_path / "out"
    blocker.write_text("a file, not a dir")
    with pytest.raises(BackendError, match="could not write"):
        make_backend(tmp_path, runner).export_native_log(blocker)
    assert ckpt.read_bytes() == b"old"


def test_export_filenames_do_not_collide(tmp_path):
    runner = FakeRunner({("ausearch",): [(0, "d\n", "")]})
    backend = make_backend(tmp_path, runner)
    first = backend.export_native_log(tmp_path / "out")
    second = backend.export_native_log(tmp_path / "out")
    assert first != second


def test_export_uses_today_without_checkpoint_and_raises_on_failure(tmp_path):
    runner = FakeRunner({("ausearch",): [(2, "", "weird")]})
    with pytest.raises(BackendError, match="weird"):
        make_backend(tmp_path, runner).export_native_log(tmp_path / "out")
    assert runner.calls[0][-2:] == ("-ts", "today")


def test_backend_flushes_stale_group_without_new_lines(tmp_path, monkeypatch):
    import credwatch.backends.linux_audit as mod

    ready = threading.Event()
    real_follow = mod.follow

    def signalling_follow(*a, **kw):
        for line in real_follow(*a, **kw):
            ready.set()  # first yield means the file is open and positioned at the end
            yield line

    monkeypatch.setattr(mod, "follow", signalling_follow)
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
    assert ready.wait(timeout=5)
    with open(log, "a") as fh:
        fh.write("\n".join(group) + "\n")
    t.join(timeout=5)
    stop.set()
    assert not t.is_alive()
    assert len(got) == 1
