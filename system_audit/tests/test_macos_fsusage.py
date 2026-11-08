import io
import stat
import threading
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import psutil
import pytest

from credwatch.backends import get_backend
from credwatch.backends.base import BackendError
from credwatch.backends.macos_fsusage import (
    BACKEND_NAME,
    FS_USAGE_ARGV,
    STALE_OUTPUT_SECONDS,
    MISS_LOG_INTERVAL_SECONDS,
    FsUsageHit,
    MacFsUsageBackend,
    parse_fs_usage_line,
    parse_fs_usage_line_detail,
    resolve_pid,
)
from credwatch.config import load_config
from credwatch.paths import WatchMatcher
from credwatch.platform_info import TargetUser

FIXTURE = Path(__file__).parent / "fixtures" / "fs_usage_sample.txt"
TZ = timezone(timedelta(hours=2))
TODAY = date(2026, 11, 8)
NOW = datetime(2026, 11, 8, 23, 59, 59, 500000, tzinfo=TZ)
WATCHED = (
    Path("/Users/alice/.aws/credentials"),
    Path("/Users/alice/.aws/config"),
    Path("/Users/alice/.ssh"),
    Path("/Users/alice/.netrc"),
    Path("/Users/alice/.kube/config"),
    Path("/Users/alice/.docker/config.json"),
    Path("/Library/Application Support/credwatch/canary"),
)


def _lines() -> list[str]:
    return [ln for ln in FIXTURE.read_text().splitlines() if ln and not ln.startswith("#")]


def _line(fragment: str) -> str:
    return next(ln for ln in _lines() if fragment in ln)


@pytest.fixture
def matcher():
    return WatchMatcher(WATCHED, case_insensitive=True)


def _parse(line, matcher, now=NOW):
    return parse_fs_usage_line(line, matcher, now.date(), now)


# --- parser -----------------------------------------------------------------------


def test_open_of_watched_path_parsed(matcher):
    line = _line("open              F=3        (R_____)  /Users/alice/.aws/credentials")
    hit = _parse(line, matcher)
    assert hit == FsUsageHit(
        timestamp=datetime(2026, 11, 8, 23, 59, 58, 102100, tzinfo=TZ).astimezone(timezone.utc),
        op="open", path="/Users/alice/.aws/credentials", proc_name="cat", tid=2004211,
        raw=line, errno=None,
    )


def test_unwatched_path_ignored(matcher):
    assert _parse(_line("/Users/alice/Documents/notes.txt"), matcher) is None
    assert _parse(_line("/usr/lib/libSystem.B.dylib"), matcher) is None


def test_sibling_with_watched_prefix_ignored(matcher):
    assert _parse(_line("/Users/alice/.aws/credentials-backup/x"), matcher) is None


def test_fd_only_read_line_ignored(matcher):
    read = _line("read              F=3    B=0x74")
    assert _parse(read, matcher) is None
    assert _parse(_line("close             F=3                 "), matcher) is None


def test_non_access_op_on_watched_path_ignored(matcher):
    assert _parse(_line("stat64                               /Users/alice/.aws"), matcher) is None
    assert _parse(_line("getattrlist"), matcher) is None


@pytest.mark.parametrize(
    "fragment,op,path",
    [
        ("open_nocancel", "open_nocancel", "/Users/alice/.aws/config"),
        ("openat ", "openat", "/Users/alice/.ssh/id_ed25519"),
        ("rename ", "rename", "/Users/alice/.kube/config.tmp"),
        ("unlink ", "unlink", "/Users/alice/.kube/config.lock"),
        ("open_dprotected_np", "open_dprotected_np", "/Users/alice/.docker/config.json"),
    ],
)
def test_relevant_ops_parsed(matcher, fragment, op, path):
    m = WatchMatcher((*WATCHED, Path("/Users/alice/.kube")), case_insensitive=True)
    hit = _parse(_line(fragment), m)
    assert hit is not None and (hit.op, hit.path) == (op, path)


def test_wait_marker_before_process_name(matcher):
    hit = _parse(_line("/Users/alice/.ssh/id_ed25519"), matcher)
    assert (hit.proc_name, hit.tid) == ("ssh", 2004500)


def test_path_with_spaces_and_dotted_process_name(matcher):
    hit = _parse(_line("credwatch/canary"), matcher)
    assert hit.path == "/Library/Application Support/credwatch/canary"
    assert (hit.proc_name, hit.tid) == ("python3.12", 2004800)


def test_process_name_with_spaces(matcher):
    hit = _parse(_line("Google Chrome He"), matcher)
    assert hit.proc_name == "Google Chrome He"


def test_case_insensitive_match_keeps_reported_path(matcher):
    hit = _parse(_line("/Users/alice/.AWS/Credentials"), matcher)
    assert hit is not None and hit.path == "/Users/alice/.AWS/Credentials"


def test_failed_open_records_errno(matcher):
    hit = _parse(_line("/Users/alice/.netrc"), matcher)
    assert hit.errno == 2


def test_midnight_rollover_uses_previous_day(matcher):
    now = datetime(2026, 11, 9, 0, 0, 1, tzinfo=TZ)
    hit = _parse(_line("open_nocancel"), matcher, now=now)  # 23:59:58 seen just after midnight
    assert hit.timestamp == datetime(2026, 11, 8, 23, 59, 58, 110100, tzinfo=TZ).astimezone(
        timezone.utc
    )
    after = _parse(_line("cat.2005400"), matcher, now=now)
    assert after.timestamp.astimezone(TZ).date() == date(2026, 11, 9)


def test_small_clock_skew_keeps_today(matcher):
    now = datetime(2026, 11, 8, 23, 59, 30, tzinfo=TZ)  # line is 28 s "in the future"
    hit = _parse(_line("open_nocancel"), matcher, now=now)
    assert hit.timestamp.astimezone(TZ).date() == TODAY


@pytest.mark.parametrize(
    "line",
    ["", "garbage", "99:99:99.000000  open  F=3 (R_____)  /Users/alice/.netrc  0.1  cat.1",
     "23:59:58.1  open  F=3 (R_____)  relative/.netrc  0.1  cat.1",
     "23:59:58.1  open  F=3 (R_____)  /Users/alice/.netrc-old  0.1  noTid",
     "23:59:58.1  stat64  /Users/alice/.netrc  0.1  noTid"],
)
def test_malformed_lines_ignored(matcher, line):
    assert _parse(line, matcher) is None


def test_path_containing_float_token_parsed_from_the_right():
    m = WatchMatcher([Path("/Users/alice/v 1.5 x")], case_insensitive=True)
    line = ("23:59:58.100000  open  F=3  (R_____)  /Users/alice/v 1.5 x/creds"
            "      0.000010   cat.4242")
    hit = _parse(line, m)
    assert (hit.path, hit.proc_name, hit.tid) == ("/Users/alice/v 1.5 x/creds", "cat", 4242)


def test_process_name_longer_than_maxcomlen_falls_back_to_unknown(matcher):
    line = ("23:59:58.100000  open  F=3  (R_____)  /Users/alice/.netrc"
            "      0.000010   averyveryverylongname.4242")
    hit = _parse(line, matcher)
    assert (hit.path, hit.proc_name, hit.tid) == ("/Users/alice/.netrc", "?", None)


def test_watched_line_without_tid_still_flagged(matcher):
    line = "23:59:58.100000  open  F=3  (R_____)  /Users/alice/.netrc      0.000010   cat"
    hit, miss = parse_fs_usage_line_detail(line, matcher, TODAY, NOW)
    assert (hit.path, hit.proc_name, hit.tid) == ("/Users/alice/.netrc", "?", None)
    assert miss is not None
    bare = "23:59:58.100000  open  F=3  (R_____)  /Users/alice/.ssh/id_rsa"
    assert _parse(bare, matcher).path == "/Users/alice/.ssh/id_rsa"


def test_unparseable_timestamp_on_watched_path_is_a_miss(matcher):
    line = "99:99:99.000000  open  F=3 (R_____)  /Users/alice/.netrc  0.1  cat.1"
    assert parse_fs_usage_line_detail(line, matcher, TODAY, NOW) == (
        None, "unparseable timestamp on a watched path",
    )


# --- pid resolution ---------------------------------------------------------------


class FakeProc:
    def __init__(self, pid, name, exe="/usr/bin/x", ppid=1, deny=False):
        self.pid, self._name, self._exe, self._ppid, self._deny = pid, name, exe, ppid, deny
        self.info = {"pid": pid, "name": name}

    def name(self):
        if self._deny:
            raise psutil.AccessDenied(self.pid)
        return self._name

    def exe(self):
        if self._deny:
            raise psutil.AccessDenied(self.pid)
        return self._exe

    def ppid(self):
        return self._ppid


class FakePsutil:
    NoSuchProcess = psutil.NoSuchProcess
    AccessDenied = psutil.AccessDenied
    ZombieProcess = psutil.ZombieProcess
    Error = psutil.Error

    def __init__(self, procs, iter_error=None):
        self.procs = {p.pid: p for p in procs}
        self.iter_error = iter_error

    def Process(self, pid):
        if pid not in self.procs:
            raise psutil.NoSuchProcess(pid)
        return self.procs[pid]

    def process_iter(self, attrs=None):
        if self.iter_error:
            raise self.iter_error
        return iter(list(self.procs.values()))


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


# --- backend ----------------------------------------------------------------------


class FakePopen:
    """Popen stand-in fed from a list of stdout lines, then exits with `rc`."""

    instances: list["FakePopen"] = []

    def __init__(self, lines, rc=0, stderr="", block=None):
        self._lines, self._rc, self._stderr, self._block = lines, rc, stderr, block
        self.argv = None
        self.kwargs = None
        self.returncode = None
        self.terminated = False
        self.killed = False

    def __call__(self, argv, **kwargs):
        self.argv, self.kwargs = argv, kwargs
        self.stdout = _BlockingLines(self._lines, self._block)
        self.stderr = io.StringIO(self._stderr)
        return self

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            self.returncode = self._rc
        return self.returncode

    def terminate(self):
        self.terminated = True
        if self._block is not None:
            self._block.set()
        self.returncode = -15

    def kill(self):
        self.killed = True


class _BlockingLines:
    def __init__(self, lines, block):
        self._it = iter([ln + "\n" for ln in lines])
        self._block = block

    def __iter__(self):
        return self

    def __next__(self):
        try:
            return next(self._it)
        except StopIteration:
            if self._block is not None:
                self._block.wait(5)
            raise

    closed = False

    def close(self):
        self.closed = True


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def _backend(tmp_path, popen, mod=None, clock=None, now=NOW, trust=False):
    export = tmp_path / "audit-exports"
    export.mkdir(exist_ok=True)
    return MacFsUsageBackend(
        WATCHED, runner_popen=popen, export_dir=export,
        psutil_mod=mod or FakePsutil([FakeProc(2004211, "cat", exe="/bin/cat", ppid=42)]),
        clock=clock or Clock(), now_fn=lambda: now, trust_name_resolution=trust,
    )


def _drain(backend, stop=None):
    out = []
    with pytest.raises(BackendError):
        for ev in backend.events(stop or threading.Event()):
            out.append(ev)
    return out


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
