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

_LINE = re.compile(
    r"^(?P<ts>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?P<op>\S+)\s+(?P<mid>.*?)"
    r"\s+\d+\.\d+(?:\s+W)?\s+(?P<proc>.+)\.(?P<tid>\d+)\s*$"
)
_PATH = re.compile(r"(?:^|\s)(/.*)$")
_ERRNO = re.compile(r"\[\s*(\d+)\]")


@dataclass(frozen=True)
class FsUsageHit:
    timestamp: datetime  # tz-aware UTC
    op: str
    path: str
    proc_name: str
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


def parse_fs_usage_line(
    line: str, matcher: WatchMatcher, today: date, now: datetime
) -> FsUsageHit | None:
    """One fs_usage line -> hit if it is a relevant op on a watched path, else None.

    `now` must be tz-aware local time (fs_usage prints local wall-clock times).
    """
    match = _LINE.match(line.rstrip("\r\n"))
    if match is None or match.group("op") not in RELEVANT_OPS:
        return None
    mid = match.group("mid")
    path_match = _PATH.search(mid)
    if path_match is None:
        return None
    path = path_match.group(1).rstrip()
    if not matcher.matches(path):
        return None
    timestamp = _timestamp(match.group("ts"), today, now)
    if timestamp is None:
        return None
    err = _ERRNO.search(mid[: path_match.start(1)])
    return FsUsageHit(
        timestamp=timestamp,
        op=match.group("op"),
        path=path,
        proc_name=match.group("proc").strip(),
        tid=int(match.group("tid")),
        raw=line.rstrip("\r\n"),
        errno=int(err.group(1)) if err else None,
    )


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


def resolve_pid(
    proc_name: str, tid: int | None, psutil_mod: Any = psutil
) -> tuple[int | None, tuple[int, ...]]:
    """(pid, candidates) for an fs_usage `name.tid` suffix. Never raises.

    The suffix is a thread id. It is used as the pid only if a live process
    with that pid has a matching name; otherwise a unique live process with
    that name is used; otherwise (None, candidates).
    """
    mod = psutil_mod
    if tid is not None and _tid_is_pid(proc_name, tid, mod):
        return tid, (tid,)
    try:
        candidates = tuple(
            p.info["pid"] for p in mod.process_iter(["pid", "name"])
            if _name_matches(proc_name, p.info.get("name"))
        )
    except Exception:
        logger.exception("process scan failed while resolving %r", proc_name)
        return None, ()
    return (candidates[0] if len(candidates) == 1 else None), candidates


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

    def _to_event(self, hit: FsUsageHit) -> FileAccessEvent:
        pid, candidates = resolve_pid(hit.proc_name, hit.tid, self._psutil)
        ppid, exe = _process_details(pid, self._psutil) if pid is not None else (None, None)
        raw = hit.raw
        if pid is None:
            listed = ", ".join(str(c) for c in candidates) or "none alive"
            raw = f"{raw}\npid candidates: {listed}"
        return FileAccessEvent(
            timestamp=hit.timestamp, path=hit.path, pid=pid, ppid=ppid, exe=exe,
            comm=hit.proc_name, success=hit.errno is None, backend=BACKEND_NAME, raw=raw,
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
            threading.Thread(target=_drain_stderr, args=(proc, tail), daemon=True,
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
                hit = parse_fs_usage_line(line, self._matcher, now.date(), now)
                if hit is None:
                    continue
                self._append_export(hit.raw, now.date())
                yield self._to_event(hit)
            else:
                eof = not stop.is_set()
        finally:
            done.set()
            _finish(proc, eof)
            helpers[0].join(1)
            with self._lock:
                self._proc = None
        if stop.is_set():
            return
        problem = f"fs_usage exited (rc={proc.returncode})"
        detail = " ".join(s.strip() for s in tail if s.strip())
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


def _drain_stderr(proc: Any, tail: collections.deque[str]) -> None:
    """Keep stderr flowing (a full pipe would block fs_usage) and remember its tail."""
    try:
        for line in proc.stderr:
            tail.append(line)
    except (OSError, ValueError):
        logger.warning("could not read fs_usage stderr", exc_info=True)


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
