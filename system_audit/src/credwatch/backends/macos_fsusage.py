"""macOS backend: parse `fs_usage -w -f filesys`, resolve the process, emit events.

fs_usage reports only a process name and a thread id, so pid/exe are resolved
best-effort with psutil (see resolve_pid). inode/dev are never known, so the
correlator falls back to the lexical path. The parser is built against a
hand-written fixture; see docs/macos-verification.md.
"""
from __future__ import annotations

import collections
import errno as errno_mod
import logging
import os
import re
import subprocess
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import psutil

from credwatch.backends.base import Backend, BackendError
from credwatch.models import FileAccessEvent
from credwatch.paths import WatchMatcher

logger = logging.getLogger(__name__)

BACKEND_NAME = "macos-fsusage"
FS_USAGE_ARGV = ("fs_usage", "-w", "-f", "filesys")
RELEVANT_OPS = frozenset({
    "open", "open_nocancel", "openat", "openat_nocancel", "open_dprotected_np",
    "rename", "renameat", "unlink", "unlinkat",
})
STALE_OUTPUT_SECONDS = 60
ROLLOVER_TOLERANCE = timedelta(seconds=60)
MAXCOMLEN = 16  # kernel p_comm length; longer names arrive truncated
STDERR_TAIL_LINES = 20
TERMINATE_WAIT_SECONDS = 5
STOP_POLL_SECONDS = 0.5
EXPORT_FILE_MODE = 0o600
EXPORT_NAME = "fs_usage-{day}.log"
_EXPORT_FLAGS = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC

UNKNOWN_PROC = "?"
MISS_LOG_INTERVAL_SECONDS = 60

_HEAD = re.compile(r"^(?P<ts>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?P<op>\S+)\s+(?P<rest>.*)$")
# Anchored from the right: the greedy `mid` makes `elapsed` the LAST float, and the
# name is bounded to MAXCOMLEN, so " 1.5 " inside a path cannot end the path early.
_TAIL = re.compile(
    rf"^(?P<mid>.*)\s+\d+\.\d+(?:\s+W)?\s+(?P<proc>.{{1,{MAXCOMLEN}}})\.(?P<tid>\d+)\s*$"
)
_PATH = re.compile(r"(?:^|\s)(/.*)$")
_ERRNO = re.compile(r"\[\s*(\d+)\]")


@dataclass(frozen=True)
class FsUsageHit:
    timestamp: datetime  # tz-aware UTC
    op: str
    path: str
    proc_name: str  # UNKNOWN_PROC when the name.tid tail could not be parsed
    tid: int | None
    raw: str
    errno: int | None = None  # set when fs_usage shows `[ N]` (the call failed)


def _timestamp(text: str, today: date, now: datetime) -> datetime | None:
    try:
        parsed = datetime.strptime(text, "%H:%M:%S.%f" if "." in text else "%H:%M:%S")
    except ValueError:
        return None
    local = datetime.combine(today, parsed.time(), tzinfo=now.tzinfo)
    if local - now > ROLLOVER_TOLERANCE:
        local -= timedelta(days=1)  # line from just before midnight, read just after
    return local.astimezone(timezone.utc)


def _watched_needles(matcher: WatchMatcher) -> tuple[frozenset[str], bool]:
    """The matcher's normalised watched paths and whether they are casefolded.

    WatchMatcher exposes no public accessor; reading its private fields keeps
    the loose search and the matcher on exactly the same normalisation.
    """
    return matcher._exact, matcher._fold  # noqa: SLF001


def _extend(rest: str, start: int, end: int, matcher: WatchMatcher) -> str | None:
    """Longest watched path starting at rest[start:end] (an occurrence of a watched path)."""
    n = len(rest)
    if end < n and not (rest[end].isspace() or rest[end] == "/"):
        return None  # a sibling such as `.netrc-old`, not the watched path
    best = rest[start:end]
    e = end
    while e < n and not rest[e].isspace():
        e += 1
    if matcher.matches(rest[start:e]):
        best = rest[start:e]
        # Cross single spaces (paths may contain them) while the result is still
        # watched; a token starting with '/' is a second path (rename), so stop.
        while e + 1 < n and rest[e] == " " and not rest[e + 1].isspace() and rest[e + 1] != "/":
            f = e + 1
            while f < n and not rest[f].isspace():
                f += 1
            if not matcher.matches(rest[start:f]):
                break
            best, e = rest[start:f], f
    return best if matcher.matches(best) else None


def _loose_paths(rest: str, matcher: WatchMatcher) -> tuple[tuple[str, int], ...]:
    """Every watched path occurring in rest at a path boundary: ((path, offset), ...)."""
    needles, fold = _watched_needles(matcher)
    haystack = rest.casefold() if fold else rest
    if len(haystack) != len(rest):  # casefold changed lengths: offsets would not line up
        haystack = rest
    found: dict[str, int] = {}
    for needle in needles:
        i = haystack.find(needle)
        while i != -1:
            if i == 0 or rest[i - 1].isspace():
                path = _extend(rest, i, i + len(needle), matcher)
                if path is not None:
                    found.setdefault(path, i)
            i = haystack.find(needle, i + 1)
    # Drop paths that are strict prefixes of another found path at the same offset.
    kept = {
        p: i for p, i in found.items()
        if not any(q != p and j == i and q.startswith(p) for q, j in found.items())
    }
    return tuple(sorted(kept.items(), key=lambda item: (item[1], item[0])))


def _strict(rest: str, matcher: WatchMatcher) -> tuple[str, str, int, int] | None:
    """(path, proc_name, tid, path offset) from the right-anchored tail, if it parses."""
    tail = _TAIL.match(rest)
    if tail is None:
        return None
    found = _PATH.search(tail.group("mid"))
    if found is None:
        return None
    return found.group(1).rstrip(), tail.group("proc").strip(), int(tail.group("tid")), found.start(1)


def parse_fs_usage_hits(
    line: str, matcher: WatchMatcher, today: date, now: datetime
) -> tuple[tuple[FsUsageHit, ...], str | None]:
    """(hits, miss) for one fs_usage line; one hit per distinct watched path.

    Invariant: a relevant-op line in which a watched path occurs at a path
    boundary always yields at least one hit. The strict parse (path, name.tid)
    is used only when its path agrees with the watched paths found by a plain
    search of the line; otherwise every found path is reported with
    proc_name=UNKNOWN_PROC and tid=None (flagged), and `miss` says why.
    """
    text = line.rstrip("\r\n")
    head = _HEAD.match(text)
    if head is None or head.group("op") not in RELEVANT_OPS:
        return (), None
    rest = head.group("rest")
    strict = _strict(rest, matcher)
    loose = _loose_paths(rest, matcher)
    loose_paths = {p for p, _ in loose}
    miss: str | None = None
    if strict is not None and matcher.matches(strict[0]) and loose_paths <= {strict[0]}:
        path, proc, tid, offset = strict
        located: tuple[tuple[str, int], ...] = ((path, offset),)
    elif loose:
        proc, tid, located = UNKNOWN_PROC, None, loose
        miss = (
            "name.tid tail split disagrees with the watched path(s); flagged"
            if strict is not None else "unparseable name.tid tail; flagged"
        )
    elif strict is not None:
        return (), None  # fully parsed; no watched path on this line
    else:
        return (), "relevant op with unparseable tail and no watched path"
    timestamp = _timestamp(head.group("ts"), today, now)
    if timestamp is None:
        timestamp = now.astimezone(timezone.utc)
        miss = "unparseable timestamp; used read time"
    hits = []
    for path, offset in located:
        err = _ERRNO.search(rest[:offset])
        hits.append(FsUsageHit(
            timestamp=timestamp, op=head.group("op"), path=path, proc_name=proc, tid=tid,
            raw=text, errno=int(err.group(1)) if err else None,
        ))
    return tuple(hits), miss


def parse_fs_usage_line(
    line: str, matcher: WatchMatcher, today: date, now: datetime
) -> FsUsageHit | None:
    """First hit of parse_fs_usage_hits, or None. `now` is tz-aware local time."""
    hits, _ = parse_fs_usage_hits(line, matcher, today, now)
    return hits[0] if hits else None


# --- pid resolution ---------------------------------------------------------------


def _name_matches(reported: str, actual: str | None) -> bool:
    if not actual:
        return False
    if actual == reported:
        return True
    return len(reported) >= MAXCOMLEN - 1 and actual.startswith(reported)


def _tid_is_pid(proc_name: str, tid: int, mod: Any) -> bool:
    try:
        return _name_matches(proc_name, mod.Process(tid).name())
    except (mod.NoSuchProcess, mod.AccessDenied, mod.ZombieProcess) as exc:
        logger.debug("tid %s is not a readable pid: %s", tid, type(exc).__name__)
        return False


@dataclass(frozen=True)
class PidResolution:
    pid: int | None
    candidates: tuple[int, ...]
    by_tid: bool  # True only when the tid itself is a live pid with a matching name


def resolve_pid_detail(proc_name: str, tid: int | None, psutil_mod: Any = psutil) -> PidResolution:
    mod = psutil_mod
    if proc_name == UNKNOWN_PROC:
        return PidResolution(None, (), False)
    if tid is not None and _tid_is_pid(proc_name, tid, mod):
        return PidResolution(tid, (tid,), True)
    try:
        candidates = tuple(
            p.info["pid"] for p in mod.process_iter(["pid", "name"])
            if _name_matches(proc_name, p.info.get("name"))
        )
    except Exception:
        logger.exception("process scan failed while resolving %r", proc_name)
        return PidResolution(None, (), False)
    return PidResolution(candidates[0] if len(candidates) == 1 else None, candidates, False)


def resolve_pid(
    proc_name: str, tid: int | None, psutil_mod: Any = psutil
) -> tuple[int | None, tuple[int, ...]]:
    """(pid, candidates) for an fs_usage `name.tid` suffix. Never raises.

    The suffix is a thread id. It is used as the pid only if a live process
    with that pid has a matching name; otherwise a unique live process with
    that name is used; otherwise (None, candidates).
    """
    res = resolve_pid_detail(proc_name, tid, psutil_mod)
    return res.pid, res.candidates


def _process_details(pid: int, mod: Any) -> tuple[int | None, str | None]:
    """(ppid, exe) of pid; None for anything unreadable (exe=None is flagged by design)."""
    try:
        proc = mod.Process(pid)
    except (mod.NoSuchProcess, mod.AccessDenied, mod.ZombieProcess) as exc:
        logger.info("pid %s unreadable (%s); exe unknown", pid, type(exc).__name__)
        return None, None
    values: list[Any] = []
    for getter in (proc.ppid, proc.exe):
        try:
            values.append(getter() or None)
        except (mod.NoSuchProcess, mod.AccessDenied, mod.ZombieProcess) as exc:
            logger.info("pid %s: %s failed (%s)", pid, getter.__name__, type(exc).__name__)
            values.append(None)
    return values[0], values[1]


# --- backend ----------------------------------------------------------------------


def _local_now() -> datetime:
    return datetime.now().astimezone()


class MacFsUsageBackend(Backend):
    name = BACKEND_NAME

    def __init__(
        self,
        watch_paths: Iterable[Path],
        runner_popen: Callable[..., Any] = subprocess.Popen,
        *,
        export_dir: Path,
        psutil_mod: Any = psutil,
        clock: Callable[[], float] = time.monotonic,
        now_fn: Callable[[], datetime] = _local_now,
        trust_name_resolution: bool = False,
    ) -> None:
        paths = tuple(watch_paths)
        self._matcher = WatchMatcher(paths, case_insensitive=True)  # APFS default
        self._prefilter = tuple(os.path.normpath(str(p)).casefold() for p in paths)
        self._popen = runner_popen
        self._export_dir = export_dir
        self._psutil = psutil_mod
        self._clock = clock
        self._now = now_fn
        self._lock = threading.Lock()
        self._proc: Any = None
        self._exit_problem: str | None = None
        self._last_line_at: float | None = None
        self._trust_names = trust_name_resolution
        self._miss_logged_at: float | None = None
        self._misses_suppressed = 0

    # -- health / export --

    def health(self) -> tuple[str, ...]:
        with self._lock:
            if self._exit_problem is not None:
                return (self._exit_problem,)
            running = self._proc is not None
            last = self._last_line_at
        if running and last is not None and self._clock() - last > STALE_OUTPUT_SECONDS:
            return (f"no fs_usage output for {STALE_OUTPUT_SECONDS} s",)
        return ()

    def _export_path(self, day: date) -> Path:
        return self._export_dir / EXPORT_NAME.format(day=day.strftime("%Y%m%d"))

    def export_native_log(self, dest_dir: Path) -> Path | None:
        """The matched lines are appended as they arrive; return today's file."""
        path = self._export_path(self._now().date())
        return path if path.is_file() and not path.is_symlink() else None

    def _append_export(self, raw: str, day: date) -> None:
        path = self._export_path(day)
        try:
            fd = os.open(path, _EXPORT_FLAGS, EXPORT_FILE_MODE)
            try:
                os.write(fd, (raw + "\n").encode("utf-8", errors="replace"))
            finally:
                os.close(fd)
        except OSError as exc:
            reason = "it is a symlink" if exc.errno == errno_mod.ELOOP else exc.strerror
            logger.warning("cannot append fs_usage export %s: %s", path, reason)

    # -- event stream --

    def _prefiltered(self, line: str) -> bool:
        folded = line.casefold()
        return any(p in folded for p in self._prefilter)

    def _note_miss(self, reason: str, line: str) -> None:
        """WARNING per parse miss, at most once per MISS_LOG_INTERVAL_SECONDS."""
        now = self._clock()
        last = self._miss_logged_at
        if last is not None and now - last < MISS_LOG_INTERVAL_SECONDS:
            self._misses_suppressed += 1
            return
        suppressed, self._misses_suppressed, self._miss_logged_at = self._misses_suppressed, 0, now
        logger.warning("fs_usage parse miss (%s; %d similar suppressed): %r",
                       reason, suppressed, line.rstrip("\r\n"))

    def _to_event(self, hit: FsUsageHit) -> FileAccessEvent:
        res = resolve_pid_detail(hit.proc_name, hit.tid, self._psutil)
        ppid, exe = (
            _process_details(res.pid, self._psutil) if res.pid is not None else (None, None)
        )
        notes: list[str] = []
        if hit.proc_name == UNKNOWN_PROC:
            notes.append("process unknown: fs_usage name.tid tail unparseable")
        elif res.pid is None:
            notes.append(
                "pid candidates: " + (", ".join(str(c) for c in res.candidates) or "none alive")
            )
        if exe is not None and not res.by_tid and not self._trust_names:
            notes.append(f"exe resolved by name only: {exe}")
            exe = None  # spoofable: fail closed unless darwin_trust_name_resolution
        raw = "\n".join((hit.raw, *notes))
        return FileAccessEvent(
            timestamp=hit.timestamp, path=hit.path, pid=res.pid, ppid=ppid, exe=exe,
            comm=None if hit.proc_name == UNKNOWN_PROC else hit.proc_name,
            success=hit.errno is None, backend=BACKEND_NAME, raw=raw,
        )

    def _spawn(self) -> Any:
        try:
            proc = self._popen(
                list(FS_USAGE_ARGV), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, errors="replace", bufsize=1,
            )
        except OSError as exc:
            problem = f"cannot start fs_usage: {exc}"
            with self._lock:
                self._exit_problem = problem
            raise BackendError(problem) from exc
        with self._lock:
            self._proc, self._exit_problem = proc, None
            self._last_line_at = self._clock()
        return proc

    def events(self, stop: threading.Event) -> Iterator[FileAccessEvent]:
        proc = self._spawn()
        tail: collections.deque[str] = collections.deque(maxlen=STDERR_TAIL_LINES)
        done = threading.Event()
        helpers = (
            threading.Thread(target=_drain_stderr, args=(proc, tail, done), daemon=True,
                             name="credwatch-fs_usage-stderr"),
            threading.Thread(target=self._stop_watcher, args=(proc, stop, done), daemon=True,
                             name="credwatch-fs_usage-stop"),
        )
        for t in helpers:
            t.start()
        eof = False
        try:
            for line in proc.stdout:
                if stop.is_set():
                    break
                with self._lock:
                    self._last_line_at = self._clock()
                if not self._prefiltered(line):
                    continue
                now = self._now()
                hits, miss = parse_fs_usage_hits(line, self._matcher, now.date(), now)
                if miss is not None:
                    self._note_miss(miss, line)
                if hits:
                    self._append_export(hits[0].raw, now.date())
                for hit in hits:
                    yield self._to_event(hit)
            else:
                eof = not stop.is_set()
        finally:
            done.set()
            _finish(proc, eof)
            _close_pipes(proc)
            helpers[0].join(1)
            with self._lock:
                self._proc = None
        if stop.is_set():
            return
        problem = f"fs_usage exited (rc={proc.returncode})"
        detail = " ".join(s.strip() for s in tuple(tail) if s.strip())
        if detail:
            problem = f"{problem}: {detail}"
        with self._lock:
            self._exit_problem = problem
        raise BackendError(problem)

    @staticmethod
    def _stop_watcher(proc: Any, stop: threading.Event, done: threading.Event) -> None:
        """Unblock a reader stuck in readline when stop is requested."""
        while not done.is_set():
            if stop.wait(STOP_POLL_SECONDS):
                _reap(proc)
                return


def _drain_stderr(proc: Any, tail: collections.deque[str], done: threading.Event) -> None:
    """Keep stderr flowing (a full pipe would block fs_usage) and remember its tail."""
    try:
        for line in proc.stderr:
            tail.append(line)
    except (OSError, ValueError):
        if done.is_set():  # pipe closed during teardown: a normal exit
            logger.debug("fs_usage stderr closed during teardown")
        else:
            logger.warning("could not read fs_usage stderr", exc_info=True)


def _close_pipes(proc: Any) -> None:
    for pipe in (proc.stdout, proc.stderr):
        try:
            if pipe is not None:
                pipe.close()
        except (OSError, ValueError):
            logger.warning("could not close fs_usage pipe", exc_info=True)


def _finish(proc: Any, eof: bool) -> None:
    """After EOF fs_usage has exited (or is exiting): collect its real exit code."""
    if eof:
        try:
            proc.wait(timeout=TERMINATE_WAIT_SECONDS)
            return
        except subprocess.TimeoutExpired:
            logger.warning("fs_usage closed stdout but did not exit")
    _reap(proc)


def _reap(proc: Any) -> None:
    """Ensure fs_usage is gone: terminate, then kill if it ignores SIGTERM."""
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=TERMINATE_WAIT_SECONDS)
    except subprocess.TimeoutExpired:
        logger.warning("fs_usage ignored terminate; killing")
        proc.kill()
        proc.wait()
    except OSError:
        logger.warning("could not terminate fs_usage", exc_info=True)
