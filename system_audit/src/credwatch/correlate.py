"""Flagged-event correlation: verify the path, run the allowlist, snapshot the process."""
from __future__ import annotations

import logging
import os
import stat as stat_mod
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

import psutil

from credwatch.allowlist import Allowlist
from credwatch.installer.common import CANARY_BODY
from credwatch.models import (
    Connection,
    FileAccessEvent,
    NetworkSnapshot,
    ProcessedEvent,
    ProcessInfo,
    Verdict,
)

logger = logging.getLogger(__name__)

MAX_ANCESTRY = 5
CANARY_RETRY_SECONDS = 60
CANARY_PROBLEM = "canary file replaced or missing; re-run credwatch install"
CANARY_RULE = "credwatch-canary"
# R55: a location-only (O_PATH) open cannot read contents; recorded, never flagged.
PATH_ONLY_RULE = "o-path (no read access)"
_ERR_EXITED = "process exited before snapshot"
# R54: names the syscall itself created/removed; verifiable through their parent dir.
_PARENT_VERIFIABLE_NAMETYPES = frozenset({"CREATE", "DELETE"})


def _endpoint(addr: Any) -> str | None:
    if not addr:
        return None
    return f"{addr.ip}:{addr.port}"


def _name(value: Any) -> str:
    return str(getattr(value, "name", value))


def _to_connection(c: Any) -> Connection:
    return Connection(
        family=_name(c.family), type=_name(c.type), laddr=_endpoint(c.laddr) or "",
        raddr=_endpoint(c.raddr), status=str(c.status),
    )


def _guarded(call: Callable[[], Any], mod: Any, errors: list[str], pid: int) -> Any:
    """Run an ancestor psutil call; return None and record the outcome on failure."""
    try:
        return call()
    except mod.AccessDenied:
        errors.append("access denied: ancestry")
    except (mod.NoSuchProcess, mod.ZombieProcess):
        logger.debug("ancestor %s vanished while reading", pid)
    except Exception:
        logger.exception("unexpected error reading ancestor %s", pid)
        errors.append("unexpected error: ancestry")
    return None


def _process_info(proc: Any, mod: Any, errors: list[str]) -> ProcessInfo:
    """Gather exe and cmdline of proc; each field guarded separately."""
    exe = _guarded(proc.exe, mod, errors, proc.pid) or None
    cmdline = tuple(_guarded(proc.cmdline, mod, errors, proc.pid) or ())
    return ProcessInfo(pid=proc.pid, exe=exe, cmdline=cmdline)


def _walk_ancestry(proc: Any, mod: Any, errors: list[str]) -> tuple[ProcessInfo, ...]:
    out: list[ProcessInfo] = []
    current = proc
    for _ in range(MAX_ANCESTRY):
        try:
            current = current.parent()
        except mod.AccessDenied:
            errors.append("access denied: ancestry")
            break
        except (mod.NoSuchProcess, mod.ZombieProcess):
            logger.debug("parent vanished during ancestry walk")
            break
        except Exception:
            logger.exception("unexpected error walking ancestry")
            errors.append("unexpected error: ancestry")
            break
        if current is None:
            break
        out.append(_process_info(current, mod, errors))
    return tuple(out)


def snapshot_process(pid: int | None, now: datetime, *, psutil_mod: Any = psutil) -> NetworkSnapshot:
    """Capture inet connections and ancestry for pid. Never raises."""
    def result(alive: bool, conns=(), ancestry=(), error: str | None = None) -> NetworkSnapshot:
        return NetworkSnapshot(pid=pid, taken_at=now, alive=alive, connections=tuple(conns),
                               ancestry=tuple(ancestry), error=error)

    if pid is None:
        return result(False, error="pid unknown")
    mod = psutil_mod
    try:
        proc = mod.Process(pid)
    except mod.ZombieProcess:  # subclass of NoSuchProcess: must come first
        return result(False, error="zombie process")
    except mod.NoSuchProcess:
        return result(False, error=_ERR_EXITED)
    except mod.AccessDenied:
        return result(True, error="access denied: process")
    except Exception:
        logger.exception("unexpected error opening pid %s", pid)
        return result(False, error="unexpected error: process")

    errors: list[str] = []
    conns: list[Connection] = []
    try:
        conns = [_to_connection(c) for c in proc.net_connections(kind="inet")]
    except mod.ZombieProcess:  # subclass of NoSuchProcess: must come first
        errors.append("zombie process: connections")
    except mod.NoSuchProcess:
        return result(False, error=_ERR_EXITED)
    except mod.AccessDenied:
        errors.append("access denied: connections")
    except Exception:
        logger.exception("unexpected error reading connections of pid %s", pid)
        errors.append("unexpected error: connections")
    ancestry = _walk_ancestry(proc, mod, errors)
    return result(True, conns, ancestry, "; ".join(errors) or None)


def read_canary_identity(path: str, owner_uid: int = 0) -> tuple[int, int] | None:
    """(st_ino, st_dev) of the canary, or None unless it is exactly what install wrote.

    Opened O_NOFOLLOW|O_NONBLOCK (a FIFO must not hang us), then fstat: regular file,
    owned by `owner_uid`, one link, body equal to the installer's CANARY_BODY.
    """
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        logger.warning("cannot open canary %s for identity: %s", path, exc.strerror)
        return None
    try:
        st = os.fstat(fd)
        if not stat_mod.S_ISREG(st.st_mode) or st.st_nlink != 1 or st.st_uid != owner_uid:
            logger.warning(
                "canary %s is not a root-owned regular file with a single link; no exemption", path
            )
            return None
        body = os.read(fd, len(CANARY_BODY) + 1)
    except OSError as exc:
        logger.warning("cannot read canary %s: %s", path, exc.strerror)
        return None
    finally:
        os.close(fd)
    if body != CANARY_BODY.encode():
        logger.warning("canary %s content differs from the installed body; no exemption", path)
        return None
    return (st.st_ino, st.st_dev)


@dataclass(frozen=True)
class _Resolution:
    allow_event: FileAccessEvent
    canonical: str | None
    verified: bool


class Correlator:
    """Verify event paths, apply the allowlist, snapshot flagged processes.

    Thread-safety: the Correlator and Allowlist are used ONLY on the backend
    reader thread; no locking is needed.
    """

    def __init__(
        self,
        allowlist: Allowlist,
        *,
        self_pid: int,
        canary_path: str,
        snapshot: Callable[[int | None, datetime], NetworkSnapshot] = snapshot_process,
        clock: Callable[[], datetime] = lambda: datetime.now(UTC),
        stat_fn: Callable[[str], Any] = os.stat,
        realpath_fn: Callable[[str], str] = os.path.realpath,
        canary_identity_fn: Callable[[str], tuple[int, int] | None] | None = None,
        canary_stat_fn: Callable[[str], Any] = os.stat,
        canary_owner_uid: int = 0,
    ) -> None:
        self._allowlist = allowlist
        self._self_pid = self_pid
        self._canary = os.path.normpath(canary_path)
        self._snapshot = snapshot
        self._clock = clock
        self._stat = stat_fn
        self._realpath = realpath_fn
        self._canary_stat = canary_stat_fn
        self._identity_fn = canary_identity_fn or (
            lambda p: read_canary_identity(p, canary_owner_uid)
        )
        # R52: pinned once at start; events never refresh it (a swapped canary stays refused).
        self._identity = self._identity_fn(self._canary)
        self._next_retry = self._clock().timestamp() + CANARY_RETRY_SECONDS
        self._canary_problem = False

    @property
    def canary_problem(self) -> str | None:
        """Health problem text once the pinned canary was seen replaced or missing."""
        return CANARY_PROBLEM if self._canary_problem else None

    def _pinned(self) -> tuple[int, int] | None:
        if self._identity is None:
            now = self._clock().timestamp()
            if now >= self._next_retry:  # at most once per CANARY_RETRY_SECONDS
                self._next_retry = now + CANARY_RETRY_SECONDS
                self._identity = self._identity_fn(self._canary)
        return self._identity

    def _canary_intact(self, pinned: tuple[int, int]) -> bool:
        try:
            st = self._canary_stat(self._canary)
            intact = (st.st_ino, st.st_dev) == pinned
        except OSError:
            intact = False
        if not intact:
            logger.error("canary %s no longer has its pinned identity", self._canary)
            self._canary_problem = True
        return intact

    def _is_canary_event(self, event: FileAccessEvent) -> str | None:
        """R51/R52: exemption by pinned file identity only, never by the path string.

        Returns the canonical path ("" when none was needed) on a match, else None.
        """
        pinned = self._pinned()
        if pinned is None:
            return None
        if event.inode is not None and event.dev is not None:
            # (a) Linux: kernel-reported inode/dev, whatever the path says.
            if (event.inode, event.dev) == pinned and self._canary_intact(pinned):
                return ""
            return None
        if event.inode is None and event.dev is None:
            # (b) macOS: canonical path must equal the canary AND stat identity must match.
            # Residual race: the path can be swapped between realpath and stat.
            canonical = self._canonical(event.path)
            if canonical is None or os.path.normpath(canonical) != self._canary:
                return None
            try:
                st = self._stat(canonical)
            except OSError:
                return None
            if (st.st_ino, st.st_dev) == pinned and self._canary_intact(pinned):
                return canonical
        return None

    def process(self, event: FileAccessEvent) -> ProcessedEvent:
        # (c) self_pid adds nothing on its own: only (a)/(b) identity matches exempt.
        canary = self._is_canary_event(event)
        if canary is not None:
            return ProcessedEvent(
                event, Verdict(True, CANARY_RULE), None, canonical_path=canary or None
            )
        res = self._resolve(event)
        if event.path_only:
            return ProcessedEvent(
                event, Verdict(True, PATH_ONLY_RULE), None, canonical_path=res.canonical
            )
        verdict = self._judge(res)
        snap = None if verdict.allowed else self._safe_snapshot(event.pid)
        return ProcessedEvent(event, verdict, snap, canonical_path=res.canonical)

    def _safe_snapshot(self, pid: int | None) -> NetworkSnapshot:
        now = self._clock()
        try:
            return self._snapshot(pid, now)
        except Exception as exc:
            logger.exception("snapshot failed for pid %s", pid)
            return NetworkSnapshot(pid=pid, taken_at=now, alive=False, connections=(),
                                   ancestry=(), error=f"snapshot failed: {type(exc).__name__}")

    def _canonical(self, path: str) -> str | None:
        try:
            return self._realpath(path)
        except (OSError, ValueError):
            logger.warning("realpath failed for %s", path, exc_info=True)
            return None

    def _resolve(self, event: FileAccessEvent) -> _Resolution:
        canonical = self._canonical(event.path)
        if event.inode is None and event.dev is None:
            return _Resolution(event, canonical, True)

        def unverified(reason: str) -> _Resolution:
            logger.info("unverified path %s: %s", event.path, reason)
            return _Resolution(event, None, False)

        if event.inode is None or event.dev is None:
            return unverified("partial inode/dev")
        try:
            if canonical is None:
                raise OSError("no canonical path")
            st = self._stat(canonical)
        except FileNotFoundError:
            via_parent = self._resolve_via_parent(event)
            return via_parent or unverified("stat failed")
        except OSError:
            return unverified("stat failed")
        if (st.st_ino, st.st_dev) != (event.inode, event.dev):
            return unverified("inode/dev mismatch")
        return _Resolution(replace(event, path=canonical), canonical, True)

    def _resolve_via_parent(self, event: FileAccessEvent) -> _Resolution | None:
        """Verify a vanished file through the directory it was created in or removed from.

        Lock and temp files are often gone before we can stat them. When the syscall
        itself created or deleted the name (so no symlink was followed for it) and the
        resolved parent directory still has the audited inode/dev, the file is
        `<resolved parent>/<name>`. Anything else returns None and stays unverified.
        """
        if event.nametype not in _PARENT_VERIFIABLE_NAMETYPES:
            return None
        if event.parent_inode is None or event.parent_dev is None:
            return None
        parent, name = os.path.split(event.path)
        if name in ("", ".", ".."):
            return None
        canonical_parent = self._canonical(parent)
        if canonical_parent is None:
            return None
        try:
            st = self._stat(canonical_parent)
        except OSError:
            return None
        if (st.st_ino, st.st_dev) != (event.parent_inode, event.parent_dev):
            return None
        path = os.path.join(canonical_parent, name)
        logger.debug("path %s verified through its parent directory", path)
        return _Resolution(replace(event, path=path), path, True)

    def _judge(self, res: _Resolution) -> Verdict:
        if not res.verified:
            return Verdict(False, None)
        return self._allowlist.check(res.allow_event)
