"""MacFsUsageBackend: pid resolution, process lifecycle, prefilter, export, health."""
import collections
import stat
import threading
import unicodedata
from pathlib import Path
from types import SimpleNamespace

import pytest

from credwatch.backends import get_backend
from credwatch.backends.base import BackendError
from credwatch.backends.macos_fsusage import (
    BACKEND_NAME,
    FS_USAGE_ARGV,
    STALE_OUTPUT_SECONDS,
    MISS_LOG_INTERVAL_SECONDS,
    UNKNOWN_PROC,
    MacFsUsageBackend,
    resolve_pid,
)
from credwatch.config import load_config
from credwatch.paths import WatchMatcher
from credwatch.platform_info import TargetUser
from _fsusage_support import (
    WATCHED,
    JOSE_NETRC,
    _lines,
    _line,
    matcher,
    _hits,
    _random_lines,
    _covered,
    FakeProc,
    FakePsutil,
    FakePopen,
    Clock,
    _backend,
    _drain,
    _TAIL_OK,
    _NETRCS,
    _CAFE_NFC,
    _CAFE_NFD,
)


def test_resolve_pid_tid_equal_to_pid_used():
    mod = FakePsutil([FakeProc(500, "cat"), FakeProc(501, "cat")])
    assert resolve_pid("cat", 500, psutil_mod=mod) == (500, (500,))


def test_resolve_pid_tid_of_other_process_name_not_used():
    mod = FakePsutil([FakeProc(500, "zsh"), FakeProc(77, "cat")])
    assert resolve_pid("cat", 500, psutil_mod=mod) == (77, (77,))


def test_resolve_pid_unique_name():
    mod = FakePsutil([FakeProc(77, "cat"), FakeProc(78, "zsh")])
    assert resolve_pid("cat", 9999999, psutil_mod=mod) == (77, (77,))


def test_resolve_pid_ambiguous_returns_candidates():
    mod = FakePsutil([FakeProc(77, "cat"), FakeProc(78, "cat"), FakeProc(79, "zsh")])
    assert resolve_pid("cat", 9999999, psutil_mod=mod) == (None, (77, 78))


def test_resolve_pid_none_alive():
    assert resolve_pid("cat", None, psutil_mod=FakePsutil([FakeProc(78, "zsh")])) == (None, ())


def test_resolve_pid_truncated_name_matches_prefix():
    mod = FakePsutil([FakeProc(90, "Google Chrome Helper")])
    assert resolve_pid("Google Chrome He", None, psutil_mod=mod) == (90, (90,))


def test_resolve_pid_short_name_is_not_prefix_matched():
    mod = FakePsutil([FakeProc(90, "catalogd")])
    assert resolve_pid("cat", None, psutil_mod=mod) == (None, ())


def test_resolve_pid_access_denied_on_tid_falls_back_to_name():
    mod = FakePsutil([FakeProc(500, "cat", deny=True), FakeProc(77, "cat")])
    pid, candidates = resolve_pid("cat", 500, psutil_mod=mod)
    assert (pid, candidates) == (None, (500, 77))


def test_resolve_pid_iter_failure_is_logged_not_raised(caplog):
    mod = FakePsutil([], iter_error=RuntimeError("boom"))
    assert resolve_pid("cat", None, psutil_mod=mod) == (None, ())
    assert "process scan failed" in caplog.text


def test_backend_spawns_fs_usage_with_pipes(tmp_path):
    popen = FakePopen([])
    _drain(_backend(tmp_path, popen))
    assert popen.argv == list(FS_USAGE_ARGV) == ["fs_usage", "-w", "-f", "filesys"]
    import subprocess
    assert popen.kwargs == dict(
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        text=True, errors="replace", bufsize=1,
    )


def test_backend_yields_events_with_exe_from_tid_pid(tmp_path):
    popen = FakePopen(_lines())
    events = _drain(_backend(tmp_path, popen))
    first = events[0]
    assert (first.path, first.pid, first.ppid, first.exe, first.comm) == (
        "/Users/alice/.aws/credentials", 2004211, 42, "/bin/cat", "cat",
    )
    assert first.backend == BACKEND_NAME
    assert first.success is True
    assert first.inode is None and first.dev is None
    assert first.timestamp.tzinfo is not None


def test_backend_unresolved_pid_has_no_exe_and_candidates_in_raw(tmp_path):
    mod = FakePsutil([FakeProc(1, "aws"), FakeProc(2, "aws")])
    events = _drain(_backend(tmp_path, FakePopen([_line("open_nocancel")]), mod=mod))
    assert len(events) == 1
    ev = events[0]
    assert ev.pid is None and ev.exe is None and ev.ppid is None
    assert "pid candidates: 1, 2" in ev.raw


@pytest.mark.parametrize("lines", [
    # a CR or LF inside the process name splits the line in two (universal newlines)
    ["23:59:58.102100  open  F=3  (R_____)  /Users/alice/.aws/credentials   0.000021   ca",
     "t.2004211"],
    ["23:59:58.102100  open  F=3  (R_____)  /Users/alice/.aws/credentials   0.000021   ca\r",
     "t.2004211"],
])
def test_name_with_cr_or_lf_split_line_still_flagged(tmp_path, caplog, lines):
    events = _drain(_backend(tmp_path, FakePopen(lines)))
    assert len(events) == 1
    ev = events[0]
    assert (ev.path, ev.pid, ev.exe, ev.comm) == ("/Users/alice/.aws/credentials", None, None, None)
    assert "process unknown" in ev.raw
    assert "fs_usage parse miss" in caplog.text


def test_watched_line_without_tid_event_has_no_exe(tmp_path):
    line = "23:59:58.100000  open  F=3  (R_____)  /Users/alice/.netrc      0.000010   cat"
    (ev,) = _drain(_backend(tmp_path, FakePopen([line])))
    assert ev.exe is None and ev.pid is None


def test_parse_miss_warnings_rate_limited(tmp_path, caplog):
    line = "23:59:58.100000  open  F=3  (R_____)  /Users/alice/.netrc      0.000010   cat"
    clock = Clock()
    backend = _backend(tmp_path, FakePopen([line] * 3), clock=clock)
    _drain(backend)
    warnings = [r for r in caplog.records if "parse miss" in r.getMessage()]
    assert len(warnings) == 1 and warnings[0].levelname == "WARNING"
    clock.t += MISS_LOG_INTERVAL_SECONDS + 1
    backend._popen = FakePopen([line])
    _drain(backend)
    warnings = [r.getMessage() for r in caplog.records if "parse miss" in r.getMessage()]
    assert len(warnings) == 2 and "2 similar suppressed" in warnings[1]


def test_name_only_exe_not_trusted_by_default(tmp_path):
    mod = FakePsutil([FakeProc(5, "aws", exe="/usr/local/bin/aws", ppid=9)])
    (ev,) = _drain(_backend(tmp_path, FakePopen([_line("open_nocancel")]), mod=mod))
    assert (ev.pid, ev.ppid, ev.exe) == (5, 9, None)
    assert "exe resolved by name only: /usr/local/bin/aws" in ev.raw


def test_name_only_exe_trusted_when_opted_in(tmp_path):
    mod = FakePsutil([FakeProc(5, "aws", exe="/usr/local/bin/aws")])
    (ev,) = _drain(_backend(tmp_path, FakePopen([_line("open_nocancel")]), mod=mod, trust=True))
    assert ev.exe == "/usr/local/bin/aws"
    assert "resolved by name only" not in ev.raw


def test_tid_pid_exe_kept_without_opt_in(tmp_path):
    (ev,) = _drain(_backend(tmp_path, FakePopen([_line("(R_____)  /Users/alice/.aws/credentials")])))
    assert ev.exe == "/bin/cat" and "name only" not in ev.raw


def test_backend_exe_access_denied_gives_none(tmp_path):
    mod = FakePsutil([FakeProc(5, "aws", deny=True)])
    events = _drain(_backend(tmp_path, FakePopen([_line("open_nocancel")]), mod=mod))
    assert events[0].pid == 5 and events[0].exe is None


def test_backend_failed_open_is_unsuccessful(tmp_path):
    events = _drain(_backend(tmp_path, FakePopen([_line("curl.2004400")])))
    assert events[0].success is False


def test_backend_appends_matched_lines_to_daily_export(tmp_path):
    line = _line("cat.2004211")
    matched = [ln for ln in _lines() if "/Users/alice/.aws/credentials " in ln][:1]
    backend = _backend(tmp_path, FakePopen([line, *matched, _line("TextEdit")]))
    _drain(backend)
    _drain(_backend(tmp_path, FakePopen(matched)))
    out = tmp_path / "audit-exports" / "fs_usage-20261108.log"
    assert out.read_text() == "".join(m + "\n" for m in matched) * 2
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert backend.export_native_log(tmp_path / "audit-exports") == out


def test_export_refuses_symlinked_daily_file(tmp_path, caplog):
    export = tmp_path / "audit-exports"
    export.mkdir()
    target = tmp_path / "elsewhere"
    target.write_text("")
    (export / "fs_usage-20261108.log").symlink_to(target)
    events = _drain(_backend(tmp_path, FakePopen([_line("(R_____)  /Users/alice/.aws/credentials")])))
    assert len(events) == 1  # the event still flows
    assert target.read_text() == ""
    assert "cannot append fs_usage export" in caplog.text


def test_export_native_log_none_without_file(tmp_path):
    backend = _backend(tmp_path, FakePopen([]))
    assert backend.export_native_log(tmp_path / "audit-exports") is None


def test_fs_usage_exit_reported_in_health(tmp_path):
    popen = FakePopen([], rc=1, stderr="fs_usage: must be run as root\n")
    backend = _backend(tmp_path, popen)
    with pytest.raises(BackendError, match=r"fs_usage exited \(rc=1\)"):
        list(backend.events(threading.Event()))
    (problem,) = backend.health()
    assert problem.startswith("fs_usage exited (rc=1)")
    assert "must be run as root" in problem


def test_spawn_failure_reported(tmp_path):
    def boom(argv, **kw):
        raise FileNotFoundError(2, "No such file", "fs_usage")

    backend = _backend(tmp_path, boom)
    with pytest.raises(BackendError, match="cannot start fs_usage"):
        list(backend.events(threading.Event()))
    assert "cannot start fs_usage" in backend.health()[0]


def test_health_reports_stale_output(tmp_path):
    block = threading.Event()
    clock = Clock()
    popen = FakePopen([_line("TextEdit")], block=block)
    backend = _backend(tmp_path, popen, clock=clock)
    stop = threading.Event()
    gen = backend.events(stop)
    reader = threading.Thread(target=lambda: list(gen), daemon=True)
    reader.start()
    try:
        for _ in range(100):
            if backend._last_line_at is not None:
                break
            threading.Event().wait(0.01)
        assert backend.health() == ()
        clock.t += STALE_OUTPUT_SECONDS + 1
        assert backend.health() == (f"no fs_usage output for {STALE_OUTPUT_SECONDS} s",)
    finally:
        stop.set()
        reader.join(5)
    assert popen.terminated
    assert not reader.is_alive()


def test_health_never_started_is_empty(tmp_path):
    assert _backend(tmp_path, FakePopen([])).health() == ()


def test_stop_ends_stream_quietly(tmp_path):
    stop = threading.Event()
    stop.set()
    popen = FakePopen(_lines())
    assert list(_backend(tmp_path, popen).events(stop)) == []
    assert popen.terminated


def test_stop_kills_when_terminate_ignored(tmp_path):
    import subprocess

    class Stubborn(FakePopen):
        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            if timeout is not None and not self.killed:
                raise subprocess.TimeoutExpired("fs_usage", timeout)
            self.returncode = -9
            return -9

    stop = threading.Event()
    stop.set()
    popen = Stubborn([])
    list(_backend(tmp_path, popen).events(stop))
    assert popen.terminated and popen.killed


# --- get_backend ------------------------------------------------------------------


def test_get_backend_darwin_returns_fsusage_backend(tmp_path):
    cfg = load_config(tmp_path / "missing.yaml", "darwin", TargetUser("u", 1, 1, Path("/h")))
    backend = get_backend(cfg, [Path("/h/.aws/credentials")], runner=SimpleNamespace())
    assert isinstance(backend, MacFsUsageBackend)
    assert backend._export_dir == cfg.data_dir / "audit-exports"
    assert backend._matcher.matches("/H/.AWS/credentials")
    assert backend._trust_names is False


def test_get_backend_passes_name_trust_opt_in(tmp_path):
    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text("darwin_trust_name_resolution: true\n")
    cfg = load_config(cfg_file, "darwin", TargetUser("u", 1, 1, Path("/h")))
    assert get_backend(cfg, [], runner=SimpleNamespace())._trust_names is True


def test_pipes_closed_after_stream(tmp_path):
    popen = FakePopen([])
    _drain(_backend(tmp_path, popen))
    assert popen.stdout.closed and popen.stderr.closed


@pytest.mark.parametrize("seed", range(5))
def test_random_attacker_names_never_hidden_by_backend_prefilter(tmp_path, matcher, seed):
    """Same generator, pushed through the real stream: prefilter + parse + events."""
    pairs = list(_random_lines(seed))
    events = _drain(_backend(tmp_path, FakePopen([line for line, _ in pairs])))
    by_line = collections.defaultdict(list)
    for ev in events:
        by_line[ev.raw.split("\n")[0]].append((ev.path, ev.comm or UNKNOWN_PROC))
        assert matcher.matches(ev.path), ev.raw
    for line, target in pairs:
        assert _covered(target, by_line[line]), line


@pytest.mark.parametrize("printed,expected", [
    ("/Users/alice/./.netrc", "/Users/alice/.netrc"),
    ("//Users//alice/.netrc", "/Users/alice/.netrc"),
    ("/Users/alice/./.aws/credentials", "/Users/alice/.aws/credentials"),
    ("/Users/bob/../alice/.ssh/id", "/Users/alice/.ssh/id"),
    ("/USERS/alice/.SSH/./id", "/USERS/alice/.SSH/id"),
    (unicodedata.normalize("NFD", JOSE_NETRC), JOSE_NETRC),
    (unicodedata.normalize("NFD", "/Users/JOSÉ/./.NETRC"), "/Users/JOSÉ/.NETRC"),
])
@pytest.mark.parametrize("tail", [_TAIL_OK, "      0.000010   a 1.1 cat.42"])
def test_backend_path_variants_survive_prefilter(tmp_path, printed, expected, tail):
    line = f"23:59:58.100000  open  F=3  (R_____)  {printed}{tail}"
    backend = _backend(tmp_path, FakePopen([line]))
    events = _drain(backend)
    assert [(ev.path, ev.exe) for ev in events] == [(expected, None)]  # exe unknown: flagged
    assert events[0].raw.split("\n")[0] == line  # original spelling kept as evidence
    export = (tmp_path / "audit-exports" / "fs_usage-20261108.log").read_text("utf-8")
    assert export == line + "\n"


def test_prefilter_still_drops_unrelated_lines(tmp_path):
    backend = _backend(tmp_path, FakePopen([]))
    assert not backend._prefiltered(_line("/usr/lib/libSystem.B.dylib"))
    assert not backend._prefiltered(_line("/Users/alice/Documents/notes.txt"))
    assert backend._prefiltered("x  open  /Users/bob/../alice/.SSH/id  0.1  cat.1")


def test_prefilter_keys_are_watched_final_components(tmp_path):
    backend = _backend(tmp_path, FakePopen([]))
    assert set(backend._prefilter) == {
        "credentials", "config", ".ssh", ".netrc", "config.json", "canary",
    }


def test_nfd_line_through_backend_gives_event(tmp_path):
    nfd = unicodedata.normalize("NFD", JOSE_NETRC)
    line = f"23:59:58.100000  open  F=3  (R_____)  {nfd}{_TAIL_OK}"
    (ev,) = _drain(_backend(tmp_path, FakePopen([line])))
    assert ev.path == JOSE_NETRC and ev.comm == "cat"
    assert ev.raw.split("\n")[0] == line


@pytest.mark.parametrize("printed,expected", [
    ("/Users/alice/x  y/../.netrc", _NETRCS),
    ("/Users/alice/x /../.netrc", _NETRCS),
    ("/Users/alice/a\tb/../.ssh/id", {"/Users/alice/.ssh"}),
    ("/Users/bob/  /../../alice/.netrc", _NETRCS),
])
def test_whitespace_component_removed_by_dotdot_fails_closed(tmp_path, caplog, printed, expected):
    line = f"23:59:58.100000  open  F=3  (R_____)  {printed}{_TAIL_OK}"
    hits, miss = _hits(line, WatchMatcher(WATCHED, case_insensitive=True))
    assert {h.path for h in hits} == expected
    assert all((h.proc_name, h.tid) == (UNKNOWN_PROC, None) for h in hits)
    assert miss == "unresolvable '..' path; attributed to watched path by component name"
    events = _drain(_backend(tmp_path, FakePopen([line])))
    assert {ev.path for ev in events} == expected
    assert all((ev.pid, ev.exe, ev.comm) == (None, None, None) for ev in events)
    assert all(ev.raw.split("\n")[0] == line for ev in events)
    assert "unresolvable '..' path" in caplog.text


def test_resolve_pid_canonically_equivalent_names_are_ambiguous():
    mod = FakePsutil([FakeProc(10, _CAFE_NFC), FakeProc(11, _CAFE_NFD)])
    assert resolve_pid(_CAFE_NFC, None, psutil_mod=mod) == (None, (10, 11))
    assert resolve_pid(_CAFE_NFD, None, psutil_mod=mod) == (None, (10, 11))


def test_resolve_pid_nfd_reported_name_matches_nfc_process():
    mod = FakePsutil([FakeProc(10, _CAFE_NFC)])
    assert resolve_pid(_CAFE_NFD, None, psutil_mod=mod) == (10, (10,))
    assert resolve_pid(_CAFE_NFD, 10, psutil_mod=mod) == (10, (10,))


def test_backend_resolves_original_name_against_both_spellings(tmp_path):
    line = f"23:59:58.100000  open  F=3  (R_____)  /Users/alice/.netrc      0.000010   {_CAFE_NFD}.42"
    mod = FakePsutil([FakeProc(10, _CAFE_NFC), FakeProc(11, _CAFE_NFD)])
    (ev,) = _drain(_backend(tmp_path, FakePopen([line]), mod=mod))
    assert (ev.pid, ev.exe, ev.comm) == (None, None, _CAFE_NFD)
    assert "pid candidates: 10, 11" in ev.raw
