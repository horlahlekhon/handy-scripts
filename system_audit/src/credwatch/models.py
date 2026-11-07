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
