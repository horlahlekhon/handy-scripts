"""Linux auditd: record parser and event assembler."""
from __future__ import annotations

import logging
import math
import os
import posixpath
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from types import MappingProxyType

from credwatch.models import FileAccessEvent

logger = logging.getLogger(__name__)

BACKEND_NAME = "linux-audit"
_GS = "\x1d"
_KEY_SEPARATOR = "\x01"
_HEX_FIELDS = frozenset({"name", "cwd", "exe", "comm", "proctitle", "key"})
_HEADER = re.compile(r"^type=(\S+) msg=audit\((\d+(?:\.\d+)?):(\d+)\):\s?(.*)$", re.DOTALL)
_FIELD = re.compile(r'(?<![^\s])([A-Za-z0-9_-]+)=("[^"]*"|\S*)')
_HEX = re.compile(r"^(?:[0-9A-Fa-f]{2})+$")


@dataclass(frozen=True)
class AuditRecord:
    type: str
    serial: str
    epoch: float
    fields: Mapping[str, str | None]


def _decode_value(name: str, raw: str) -> str | None:
    if raw == "(null)":
        return None
    if len(raw) >= 2 and raw[0] == '"' and raw[-1] == '"':
        return raw[1:-1]
    if name in _HEX_FIELDS and _HEX.match(raw):
        return bytes.fromhex(raw).decode("utf-8", errors="replace")
    return raw


def parse_record(line: str) -> AuditRecord | None:
    """Parse one auditd line (enriched suffix after 0x1d ignored); None if not a record."""
    try:
        match = _HEADER.match(line.split(_GS, 1)[0].rstrip("\r\n"))
        if match is None:
            return None
        rtype, epoch_text, serial, body = match.groups()
        epoch = float(epoch_text)
        if not math.isfinite(epoch):
            return None
        datetime.fromtimestamp(epoch, tz=timezone.utc)  # reject unrepresentable epochs
        fields = {k: _decode_value(k, v) for k, v in _FIELD.findall(body)}
        return AuditRecord(rtype, serial, epoch, MappingProxyType(fields))
    except (ValueError, OverflowError, OSError):
        return None


@dataclass
class _Group:
    first_seen: float
    lines: list[str]
    records: list[AuditRecord]


def _to_int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def _parse_dev(value: str | None) -> int | None:
    """Convert auditd's hex "MAJ:MIN" into a dev_t; None if missing or malformed."""
    if not value:
        return None
    major, sep, minor = value.partition(":")
    if not sep:
        return None
    try:
        maj, mnr = int(major, 16), int(minor, 16)
        if maj < 0 or mnr < 0:
            return None
        return os.makedev(maj, mnr)
    except (ValueError, OverflowError, OSError):
        return None


def _build_events(group: _Group, key: str) -> list[FileAccessEvent]:
    syscall = next((r for r in group.records if r.type == "SYSCALL"), None)
    if syscall is None:
        logger.debug("audit group has no SYSCALL record; dropped: %s", group.lines)
        return []
    keys = (syscall.fields.get("key") or "").split(_KEY_SEPARATOR)
    if key not in keys:
        return []
    cwd_rec = next((r for r in group.records if r.type == "CWD"), None)
    cwd = cwd_rec.fields.get("cwd") if cwd_rec else None
    raw = "\n".join(group.lines)
    timestamp = datetime.fromtimestamp(syscall.epoch, tz=timezone.utc)
    events = []
    for rec in group.records:
        if rec.type != "PATH" or rec.fields.get("nametype") == "PARENT":
            continue
        name = rec.fields.get("name")
        if name is None:
            logger.debug("PATH record has null name; skipped: %s", rec.fields)
            continue
        if cwd and not name.startswith("/"):
            name = posixpath.normpath(posixpath.join(cwd, name))
        events.append(
            FileAccessEvent(
                timestamp=timestamp,
                path=name,
                pid=_to_int(syscall.fields.get("pid")),
                ppid=_to_int(syscall.fields.get("ppid")),
                exe=syscall.fields.get("exe"),
                comm=syscall.fields.get("comm"),
                success=syscall.fields.get("success") == "yes",
                backend=BACKEND_NAME,
                raw=raw,
                inode=_to_int(rec.fields.get("inode")),
                dev=_parse_dev(rec.fields.get("dev")),
            )
        )
    return events


class AuditAssembler:
    """Groups audit records by serial and emits events for the configured key.

    Callers must send periodic ticks via ``feed("", now)`` so stale groups
    (those that never receive an EOE record) get flushed.
    """

    def __init__(self, key: str = "credwatch", flush_after: float = 2.0) -> None:
        self._key = key
        self._flush_after = flush_after
        self._groups: dict[str, _Group] = {}

    def feed(self, line: str, now: float) -> list[FileAccessEvent]:
        events: list[FileAccessEvent] = []
        rec = parse_record(line)
        if rec is not None:
            group = self._groups.setdefault(rec.serial, _Group(now, [], []))
            group.lines.append(line.rstrip("\r\n"))
            group.records.append(rec)
            if rec.type == "EOE":
                events.extend(self._build(rec.serial))
        stale = [s for s, g in self._groups.items() if now - g.first_seen >= self._flush_after]
        for serial in stale:
            events.extend(self._build(serial))
        return events

    def _build(self, serial: str) -> list[FileAccessEvent]:
        group = self._groups.pop(serial)
        try:
            return _build_events(group, self._key)
        except (ValueError, OverflowError, OSError):
            logger.warning("dropping audit group serial=%s: build failed", serial, exc_info=True)
            return []
