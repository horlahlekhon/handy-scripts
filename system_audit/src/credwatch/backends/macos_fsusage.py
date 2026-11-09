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
import unicodedata
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import psutil

from credwatch.backends.base import Backend, BackendError
from credwatch.models import FileAccessEvent
from credwatch.paths import WatchMatcher, canonical_caseless

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
DOTDOT_MISS = "unresolvable '..' path; attributed to watched path by component name"
NON_ASCII_MISS = "non-ASCII line without an exact watched-path match; attributed by component name"
MISS_LOG_INTERVAL_SECONDS = 60

_HEAD = re.compile(r"^(?P<ts>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+(?P<op>\S+)\s+(?P<rest>.*)$")
# Anchored from the right: the greedy `mid` makes `elapsed` the LAST float, and the
# name is bounded to MAXCOMLEN, so " 1.5 " inside a path cannot end the path early.
_TAIL = re.compile(
    rf"^(?P<mid>.*)\s+\d+\.\d+(?:\s+W)?\s+(?P<proc>.{{1,{MAXCOMLEN}}})\.(?P<tid>\d+)\s*$"
)
_PATH = re.compile(r"(?:^|[\s\]])(/.*)$")  # same path starts as _candidate_starts
_ERRNO = re.compile(r"\[\s*(\d+)\]")
_DOTDOT = re.compile(r"/\.\.(?=/|\s|$)")


@dataclass(frozen=True)
class FsUsageHit:
    timestamp: datetime  # tz-aware UTC
    op: str
    path: str
    proc_name: str  # UNKNOWN_PROC when the name.tid tail could not be parsed
    tid: int | None
    raw: str
    errno: int | None = None  # set when fs_usage shows `[ N]` (the call failed)


def _nfc(text: str) -> str:
    """NFC form (APFS treats NFC/NFD spellings as one name); ASCII is returned as is."""
    return text if text.isascii() else unicodedata.normalize("NFC", text)


def _component_key(watch_path: str, matcher: WatchMatcher) -> str:
    """Final component of a watched path, in the matcher's comparison form."""
    return matcher.normalize(watch_path).rsplit("/", 1)[-1]


def prefilter_keys(matcher: WatchMatcher) -> frozenset[str]:
    """Final component of every watched path, as the matcher normalizes it.

    Any line holding a path that matches a watched path W (after ./, //, ..,
    case and canonical normalization) contains W's last component literally
    once the line is put through fold_line: normpath only drops components,
    never builds new ones, and '/' (a starter) bounds canonical reordering.
    For a watched directory this is the directory's own name, so files below
    it pass too.
    """
    return frozenset(_component_key(p, matcher) for p in matcher.watch_paths())


def fold_line(text: str, matcher: WatchMatcher) -> str:
    """text in the form prefilter keys are compared against (same as matcher.normalize):
    canonical caseless NFD(casefold(NFD(.))) when insensitive, else NFC."""
    return canonical_caseless(text) if matcher.case_insensitive else _nfc(text)


def _timestamp(text: str, today: date, now: datetime) -> datetime | None:
    try:
        parsed = datetime.strptime(text, "%H:%M:%S.%f" if "." in text else "%H:%M:%S")
    except ValueError:
        return None
    local = datetime.combine(today, parsed.time(), tzinfo=now.tzinfo)
    if local - now > ROLLOVER_TOLERANCE:
        local -= timedelta(days=1)  # line from just before midnight, read just after
    return local.astimezone(timezone.utc)


_CANDIDATE_LEFT = frozenset("]")
_PATH_CHARS = frozenset("/._-~")


def _normalize(path: str) -> str:
    """normpath, plus POSIX's preserved leading '//' collapsed to '/'."""
    normed = os.path.normpath(path)
    return "/" + normed.lstrip("/") if normed.startswith("//") else normed


def _watched(path: str, matcher: WatchMatcher) -> bool:
    return matcher.matches(_normalize(path))


def _token_end(rest: str, i: int) -> int:
    n = len(rest)
    while i < n and not rest[i].isspace():
        i += 1
    return i


def _longest_watched(rest: str, start: int, first_end: int, matcher: WatchMatcher) -> int | None:
    """End of the longest watched path starting at `start`.

    Candidates are the token rest[start:first_end'] (extended to the next
    whitespace) and its extensions across single spaces (paths may contain
    them). A token starting with '/' begins a second path (rename): stop.
    """
    n = len(rest)
    end = _token_end(rest, first_end)
    best = end if _watched(rest[start:end], matcher) else None
    while end + 1 < n and rest[end] == " " and not rest[end + 1].isspace() and rest[end + 1] != "/":
        end = _token_end(rest, end + 1)
        if _watched(rest[start:end], matcher):
            best = end
    return best


def _candidate_starts(rest: str) -> list[int]:
    """'/' positions that begin a path: at the start, or after whitespace or ']'."""
    return [
        i for i, ch in enumerate(rest)
        if ch == "/" and (i == 0 or rest[i - 1].isspace() or rest[i - 1] in _CANDIDATE_LEFT)
    ]


def _fold_with_offsets(text: str) -> tuple[str, list[int]]:
    """Canonical caseless fold char by char; offsets[k] is the original index of folded char k.

    Per character, NFD(casefold(NFD(c))) equals the whole-string fold except
    where canonical reordering moves combining marks across characters; such
    lines produce no needle hit and reach the non-ASCII component fallback.
    """
    folded: list[str] = []
    offsets: list[int] = []
    for i, ch in enumerate(text):
        piece = canonical_caseless(ch)
        folded.append(piece)
        offsets.extend([i] * len(piece))
    offsets.append(len(text))
    return "".join(folded), offsets


def _needles(matcher: WatchMatcher) -> tuple[str, ...]:
    """Each watched path in the matcher's comparison form.

    Insensitive: canonical caseless NFD(casefold(NFD(p))), the same form as the
    haystack (built char by char by _fold_with_offsets) and the prefilter, so
    e.g. U+01F0 and every case/composition spelling of U+0390 meet in one form.
    """
    if matcher.case_insensitive:
        return matcher.normalized_watch_paths()
    return matcher.watch_paths()


def _needle_starts(rest: str, matcher: WatchMatcher) -> list[tuple[int, int]]:
    """(start, end) in rest of every watched path occurring at a left path boundary.

    `rest` is already NFC. Needle and haystack use one form (see _needles).
    """
    if matcher.case_insensitive:
        haystack, offsets = _fold_with_offsets(rest)
    else:
        haystack, offsets = rest, list(range(len(rest) + 1))
    found = []
    for needle in _needles(matcher):
        k = haystack.find(needle)
        while k != -1:
            j = k + len(needle)
            aligned = (k == 0 or offsets[k - 1] != offsets[k]) and (
                j == len(haystack) or offsets[j - 1] != offsets[j]
            )
            start, end = offsets[k], offsets[j - 1] + 1
            left_ok = start == 0 or not (rest[start - 1].isalnum() or rest[start - 1] in _PATH_CHARS)
            if aligned and left_ok:
                found.append((start, end))
            k = haystack.find(needle, k + 1)
    return found


Found = tuple[tuple[str, int], ...]  # (normalized watched path, start offset in rest)
Spans = tuple[tuple[int, int], ...]  # (start, end) in rest of every exact match


def _loose_spans(rest: str, matcher: WatchMatcher) -> tuple[Found, Spans]:
    """(every watched path in rest as (normalized path, start offset), one per start;
    the (start, end) span of every exact match, duplicates included).

    Two independent searches: '/'-starting candidates (handles ./, //, `[ 2]/x`)
    and watched-path needles (casefolded with an offset map, so names that
    change length under casefold cannot misalign the search).
    """
    spans: dict[int, int] = {}
    for start in _candidate_starts(rest):
        end = _longest_watched(rest, start, start + 1, matcher)
        if end is not None:
            spans[start] = max(end, spans.get(start, end))
    for start, end in _needle_starts(rest, matcher):
        if end < len(rest) and not (rest[end].isspace() or rest[end] == "/"):
            continue  # a sibling such as `.netrc-old`
        longest = _longest_watched(rest, start, end, matcher)
        if longest is not None:
            spans[start] = max(longest, spans.get(start, longest))
    seen: set[str] = set()
    out = []
    for start in sorted(spans):
        path = _normalize(rest[start:spans[start]])
        key = matcher.normalize(path)
        if key not in seen:
            seen.add(key)
            out.append((path, start))
    return tuple(out), tuple(sorted(spans.items()))


def _strict(rest: str) -> tuple[str, str, int, int] | None:
    """(path, proc_name, tid, path offset) from the right-anchored tail, if it parses."""
    tail = _TAIL.match(rest)
    if tail is None:
        return None
    found = _PATH.search(tail.group("mid"))
    if found is None:
        return None
    return found.group(1).rstrip(), tail.group("proc").strip(), int(tail.group("tid")), found.start(1)


def _original_name(raw: str) -> tuple[str, int] | None:
    """(proc_name, tid) as printed in the ORIGINAL (un-normalized) line."""
    head = _HEAD.match(raw)
    tail = _TAIL.match(head.group("rest")) if head is not None else None
    return (tail.group("proc").strip(), int(tail.group("tid"))) if tail is not None else None


def _component_fallback(rest: str, matcher: WatchMatcher) -> Found:
    """Fail closed where the exact searches may be blind (`..`, canonical reordering).

    Each watched path whose final component occurs in the line is reported as
    itself (offset: the line's first '/', for the errno lookup).
    """
    folded, first = fold_line(rest, matcher), rest.find("/")
    return tuple(
        (p, first) for p in matcher.watch_paths() if _component_key(p, matcher) in folded
    )


def _strict_watched(rest: str, matcher: WatchMatcher) -> Found:
    """The strict parse's path, normalized (it resolves `..` itself), if watched."""
    strict = _strict(rest)
    if strict is None or not _watched(strict[0], matcher):
        return ()
    return ((_normalize(strict[0]), strict[3]),)


def _covers(watched: str, found: str, matcher: WatchMatcher) -> bool:
    w, f = matcher.normalize(watched), matcher.normalize(found)
    return f == w or f.startswith(w.rstrip("/") + "/")


def _watched_root(path: str, matcher: WatchMatcher) -> str | None:
    return next((w for w in matcher.watch_paths() if _covers(w, path, matcher)), None)


def _component_outside(path: str, rest: str, spans: Spans, matcher: WatchMatcher) -> bool:
    """True if `path`'s final component occurs in rest outside every exact-match span.

    An occurrence the per-character fold cannot locate (canonical reordering)
    counts as outside: fail closed.
    """
    key = _component_key(path, matcher)
    if matcher.case_insensitive:
        haystack, offsets = _fold_with_offsets(rest)
    else:
        haystack, offsets = rest, list(range(len(rest) + 1))
    k = haystack.find(key)
    if k == -1:
        return key in fold_line(rest, matcher)
    while k != -1:
        if not any(s <= offsets[k] < e for s, e in spans):
            return True
        k = haystack.find(key, k + 1)
    return False


def _hidden_extra(rest: str, found: Found, spans: Spans, matcher: WatchMatcher) -> Found:
    """Watched paths a `/..` (I3) or canonical reordering may hide from the exact searches.

    - the strict parse's target (it resolves `..` itself), when found paths exist
      and it lies in a different watched root than all of them;
    - every watched path whose final component occurs outside the found spans,
      unless something already reported lies at or below it.
    """
    extra: list[tuple[str, int]] = []
    if found:
        roots = {_watched_root(p, matcher) for p, _ in found}
        extra.extend(
            (path, offset) for path, offset in _strict_watched(rest, matcher)
            if _watched_root(path, matcher) not in roots
        )
    for path, offset in _component_fallback(rest, matcher):
        reported = (*found, *extra)
        if any(_covers(path, f, matcher) for f, _ in reported):
            continue
        if _component_outside(path, rest, spans, matcher):
            extra.append((path, offset))
    return tuple(extra)


def _attribution(
    rest: str, raw: str, loose: tuple[tuple[str, int], ...], matcher: WatchMatcher
) -> tuple[str, int | None, str | None]:
    """(proc_name, tid, miss): the strict name.tid only if it provably names `loose`."""
    strict = _strict(rest)
    if strict is None:
        return UNKNOWN_PROC, None, "unparseable name.tid tail; flagged"
    path, proc, tid, offset = strict
    agrees = (
        len(loose) == 1 and loose[0][1] == offset
        and _watched(path, matcher) and _normalize(path) == loose[0][0]
    )
    if not agrees:
        return UNKNOWN_PROC, None, "name.tid tail split disagrees with the watched path(s); flagged"
    original = _original_name(raw)
    if original is None or original[1] != tid or _nfc(original[0]) != proc:
        return UNKNOWN_PROC, None, "name.tid tail differs in the original line; flagged"
    return original[0], tid, None


def _found_paths(rest: str, matcher: WatchMatcher) -> tuple[Found, str | None]:
    """(watched paths, reason they cannot be attributed or None).

    Exact searches first. A `/..` (I3) or non-ASCII text (canonical
    reordering can blind the per-character offset map) adds the strict
    target and the component fallback; any addition fails closed.
    """
    found, spans = _loose_spans(rest, matcher)
    dotdot = _DOTDOT.search(rest) is not None
    if not dotdot and rest.isascii():
        return found, None
    extra = _hidden_extra(rest, found, spans, matcher)
    if not extra:
        return found, None
    return (*found, *extra), DOTDOT_MISS if dotdot else NON_ASCII_MISS


def parse_fs_usage_hits(
    line: str, matcher: WatchMatcher, today: date, now: datetime
) -> tuple[tuple[FsUsageHit, ...], str | None]:
    """(hits, miss) for one fs_usage line; one hit per distinct watched path.

    Invariant: ((), None) only when no candidate path and no watched-path
    needle in the line is watched, and (if the line has a `/..` segment or
    non-ASCII text) no watched path's final component occurs in it. A `/..`
    line also reports every watched path named by component or by the strict
    parse that no found path covers, all flagged. The strict parse (path,
    name.tid) is used only when its path is watched AND is exactly the single
    watched path the loose search found at the same place; otherwise every
    found path is reported with proc_name=UNKNOWN_PROC, tid=None (flagged),
    and `miss` says why. proc_name is spelled as in the original line.
    """
    raw = line.rstrip("\r\n")  # original spelling, kept as evidence
    text = _nfc(raw)  # paths are matched and reported in NFC form
    head = _HEAD.match(text)
    if head is None or head.group("op") not in RELEVANT_OPS:
        return (), None
    rest = head.group("rest")
    loose, unsure = _found_paths(rest, matcher)
    if not loose:
        return (), None  # no watched path anywhere in the line
    if unsure is not None:
        proc, tid, miss = UNKNOWN_PROC, None, unsure
    else:
        proc, tid, miss = _attribution(rest, raw, loose, matcher)
    timestamp = _timestamp(head.group("ts"), today, now)
    if timestamp is None:
        timestamp = now.astimezone(timezone.utc)
        miss = "unparseable timestamp; used read time"
    hits = []
    for path, offset in loose:
        err = _ERRNO.search(rest[:offset])
        hits.append(FsUsageHit(
            timestamp=timestamp, op=head.group("op"), path=path, proc_name=proc, tid=tid,
            raw=raw, errno=int(err.group(1)) if err else None,
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
    """Compared in NFC on both sides: canonically equivalent spellings all match,
    so they surface as several candidates rather than one false unique match."""
    if not actual:
        return False
    reported, actual = _nfc(reported), _nfc(actual)
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
        self._prefilter = tuple(sorted(prefilter_keys(self._matcher)))
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
        """Cheap, coarse pre-check: does the line hold a watched final component?

        Must never reject a line the parser would report (see prefilter_keys);
        false positives only cost a full parse.
        """
        folded = fold_line(line, self._matcher)
        return any(k in folded for k in self._prefilter)

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
