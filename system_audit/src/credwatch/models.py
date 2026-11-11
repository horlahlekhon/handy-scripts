"""Immutable value types shared across credwatch."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True)
class FileAccessEvent:
    timestamp: datetime  # tz-aware UTC
    path: str
    pid: int | None
    ppid: int | None
    exe: str | None
    comm: str | None
    success: bool | None
    backend: str
    raw: str
    inode: int | None = None
    dev: int | None = None
    # Linux audit only: the PATH record's nametype (NORMAL/CREATE/DELETE/...) and the
    # identity of the directory the name was created in or removed from (its PARENT record).
    nametype: str | None = None
    parent_inode: int | None = None
    parent_dev: int | None = None
    # Linux audit only: the open asked for a location-only (O_PATH) handle, which cannot
    # read contents or list a directory. False whenever the flags are unknown.
    path_only: bool = False


@dataclass(frozen=True)
class Connection:
    family: str
    type: str
    laddr: str
    raddr: str | None
    status: str


@dataclass(frozen=True)
class ProcessInfo:
    pid: int
    exe: str | None
    cmdline: tuple[str, ...]


@dataclass(frozen=True)
class NetworkSnapshot:
    pid: int | None
    taken_at: datetime
    alive: bool
    connections: tuple[Connection, ...]
    ancestry: tuple[ProcessInfo, ...]
    error: str | None


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    matched_rule: str | None


@dataclass(frozen=True)
class ProcessedEvent:
    event: FileAccessEvent
    verdict: Verdict
    snapshot: NetworkSnapshot | None
    canonical_path: str | None = None
