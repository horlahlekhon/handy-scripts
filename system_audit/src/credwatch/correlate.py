"""Flagged-event correlation: verify the path, run the allowlist, snapshot the process."""
from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from typing import Any

import psutil

from credwatch.allowlist import Allowlist
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
CANARY_RULE = "credwatch-canary"
_ERR_EXITED = "process exited before snapshot"


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


def _process_info(proc: Any, mod: Any, errors: list[str]) -> ProcessInfo:
    """Gather exe/cmdline of proc; each field guarded, failures recorded."""
    exe: str | None = None
    cmdline: tuple[str, ...] = ()
    try:
        exe = proc.exe() or None
        cmdline = tuple(proc.cmdline())
    except mod.AccessDenied:
        errors.append("access denied: ancestry")
    except (mod.NoSuchProcess, mod.ZombieProcess):
        logger.debug("ancestor %s vanished while reading", proc.pid)
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
    ) -> None:
        self._allowlist = allowlist
        self._self_pid = self_pid
        self._canary = os.path.normpath(canary_path)
        self._snapshot = snapshot
        self._clock = clock
        self._stat = stat_fn
        self._realpath = realpath_fn

    def process(self, event: FileAccessEvent) -> ProcessedEvent:
        if event.pid == self._self_pid and os.path.normpath(event.path) == self._canary:
            return ProcessedEvent(event, Verdict(True, CANARY_RULE), None)
        res = self._resolve(event)
        verdict = self._judge(res)
        snap = None if verdict.allowed else self._snapshot(event.pid, self._clock())
        return ProcessedEvent(event, verdict, snap, canonical_path=res.canonical)

    def _canonical(self, path: str) -> str | None:
        try:
            return self._realpath(path)
        except (OSError, ValueError):
            logger.warning("realpath failed for %s", path, exc_info=True)
            return None

    def _resolve(self, event: FileAccessEvent) -> _Resolution:
        canonical = self._canonical(event.path)
        if event.inode is None or event.dev is None:
            return _Resolution(event, canonical, True)
        try:
            if canonical is None:
                raise OSError("no canonical path")
            st = self._stat(canonical)
        except OSError:
            logger.info("unverified path %s: stat failed", event.path)
            return _Resolution(event, canonical, False)
        if (st.st_ino, st.st_dev) != (event.inode, event.dev):
            logger.info("unverified path %s: inode/dev mismatch", event.path)
            return _Resolution(event, canonical, False)
        return _Resolution(replace(event, path=canonical), canonical, True)

    def _judge(self, res: _Resolution) -> Verdict:
        if not res.verified:
            return Verdict(False, None)
        return self._allowlist.check(res.allow_event)
