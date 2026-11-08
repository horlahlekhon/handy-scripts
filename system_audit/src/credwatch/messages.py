"""Pure formatting of alert, digest and health emails (plain text)."""
from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone, tzinfo
from pathlib import Path

from credwatch.models import ProcessedEvent
from credwatch.store import DailySummary, EventRow

SUBJECT_MAX = 200
_SUBJECT_STRIP = {0x7F, 0x85, 0x2028, 0x2029}
_NAMED_ESCAPES = {"\n": "\\n", "\r": "\\r", "\t": "\\t"}


def _is_control(ch: str) -> bool:
    return ord(ch) < 0x20 or ord(ch) in _SUBJECT_STRIP


def _subject_safe(text: str) -> str:
    """Remove line-breaking/control chars (header injection) and cap length."""
    return "".join(c for c in text if not _is_control(c))[:SUBJECT_MAX]


def _esc(value: object) -> str:
    """Render untrusted text with control characters shown as escapes."""
    out = []
    for ch in str(value):
        if ch in _NAMED_ESCAPES:
            out.append(_NAMED_ESCAPES[ch])
        elif _is_control(ch):
            out.append(f"\\x{ord(ch):02x}" if ord(ch) <= 0xFF else f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    return "".join(out)


def _times(ts: datetime, tz: tzinfo | None) -> str:
    utc = ts.astimezone(timezone.utc)
    return f"{utc.isoformat(timespec='seconds')} (local {_local(ts, tz)})"


def _local(ts: datetime, tz: tzinfo | None) -> str:
    return ts.astimezone(tz).strftime("%Y-%m-%d %H:%M:%S %Z%z").strip()


def _event_block(pe: ProcessedEvent, tz: tzinfo | None) -> list[str]:
    ev = pe.event
    lines = [
        f"Time:     {_times(ev.timestamp, tz)}",
        f"Path:     {_esc(ev.path)}",
    ]
    if pe.canonical_path is not None:
        lines.append(f"canonical path: {_esc(pe.canonical_path)}")
    elif ev.inode is not None:
        lines.append("canonical path: UNVERIFIED path (could not be resolved)")
    lines += [
        f"Rule:     {_esc(pe.verdict.matched_rule)}",
        f"PID/PPID: {ev.pid}/{ev.ppid}",
        f"Exe:      {_esc(ev.exe)}  (comm: {_esc(ev.comm)})",
        f"Success:  {ev.success}",
    ]
    snap = pe.snapshot
    if snap is None:
        lines.append("Connections: no snapshot taken")
        return lines
    if snap.error:
        lines.append(f"Connections: unavailable ({_esc(snap.error)})")
    elif not snap.connections:
        lines.append("Connections: none")
    else:
        lines.append("Connections:")
        lines += [
            f"  {_esc(c.laddr)} -> {_esc(c.raddr)} {_esc(c.status)} ({_esc(c.type)})"
            for c in snap.connections
        ]
    if snap.ancestry:
        lines.append("Ancestry:")
        lines += [
            f"  [{p.pid}] {_esc(p.exe)} {_esc(' '.join(p.cmdline))}" for p in snap.ancestry
        ]
    return lines


def format_flagged_alert(
    events: Sequence[ProcessedEvent],
    hostname: str,
    *,
    data_dir: Path,
    rotate_seconds: int,
    tz: tzinfo | None = None,
) -> tuple[str, str]:
    first = events[0].event if events else None
    proc = (first.exe or first.comm) if first else None
    n_paths = len({pe.event.path for pe in events})
    subject = _subject_safe(
        f"[credwatch][{hostname}] FLAGGED: {proc or 'unknown'} accessed {n_paths} credential path(s)"
    )
    lines = [f"Host: {_esc(hostname)}", f"Flagged events: {len(events)}", ""]
    for i, pe in enumerate(events, 1):
        lines.append(f"--- Event {i} ---")
        lines += _event_block(pe, tz)
        lines.append("")
    lines.append("Where to look")
    lines += [
        f"  Event DB:      {data_dir / 'events.db'}",
        f"  Captures:      {data_dir / 'captures'}",
        f"  Audit exports: {data_dir / 'audit-exports'}",
        f"  Logs:          {data_dir / 'logs'}",
        f"  Pcap files are named credwatch-YYYYmmdd-HHMMSS.pcap (local time) and rotate "
        f"every {rotate_seconds}s from capture start.",
    ]
    for i, pe in enumerate(events, 1):
        lines.append(
            f"  Event {i}: the pcap whose start time is the latest one before "
            f"{pe.event.timestamp.astimezone(tz).strftime('%Y-%m-%d %H:%M:%S')} (local)"
        )
    return subject, "\n".join(lines) + "\n"


def format_digest(
    summary: DailySummary,
    flagged: Sequence[EventRow],
    health: Sequence[str],
    hostname: str,
    *,
    tz: tzinfo | None = None,
) -> tuple[str, str]:
    subject = _subject_safe(
        f"[credwatch][{hostname}] Daily digest {summary.day}: "
        f"{summary.flagged} flagged / {summary.total} total"
    )
    lines = [
        f"Host: {_esc(hostname)}",
        f"Day: {summary.day}",
        f"Total events: {summary.total}",
        f"Flagged events: {summary.flagged}",
        "",
        "Health:",
    ]
    lines += [f"  {_esc(h)}" for h in health] or ["  OK"]
    lines += ["", "Top processes:"]
    lines += [f"  {_esc(name)}: {count}" for name, count in summary.by_process] or ["  (none)"]
    lines += ["", "Top paths:"]
    lines += [f"  {_esc(path)}: {count}" for path, count in summary.by_path] or ["  (none)"]
    lines += ["", "Flagged events:"]
    lines += [
        f"  {_times(r.ts, tz)} {_esc(r.exe or r.comm)} pid={r.pid} {_esc(r.canonical_path or r.path)}"
        for r in flagged
    ] or ["  (none)"]
    return subject, "\n".join(lines) + "\n"


def format_health_alert(problems: Sequence[str], hostname: str) -> tuple[str, str]:
    head = problems[0] if problems else "unknown problem"
    subject = _subject_safe(f"[credwatch][{hostname}] DEGRADED: {head}")
    lines = [f"Host: {_esc(hostname)}", "credwatch is degraded:", ""]
    lines += [f"  - {_esc(p)}" for p in problems]
    return subject, "\n".join(lines) + "\n"
