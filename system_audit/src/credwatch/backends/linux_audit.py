"""Linux auditd: record parser and event assembler."""
from __future__ import annotations

import logging
import math
import os
import posixpath
import re
import subprocess
import tempfile
import threading
import time
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from types import MappingProxyType

from credwatch.backends.base import Backend, BackendError
from credwatch.models import FileAccessEvent
from credwatch.paths import has_control_chars
from credwatch.proc import Runner
from credwatch.tail import follow

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


# ---------------------------------------------------------------------------
# Rules management
# ---------------------------------------------------------------------------

DEFAULT_RULES_FILE = Path("/etc/audit/rules.d/credwatch.rules")
RULES_FILE_MODE = 0o640
TICK_INTERVAL = 0.5
_ENABLED = re.compile(r"^enabled\s+(\d+)", re.MULTILINE)
_NO_MATCHES = "<no matches>"
_CHECKPOINT_ERRORS = frozenset({10, 11, 12})


@dataclass(frozen=True)
class RenderedRules:
    text: str
    skipped: tuple[Path, ...]


def _is_ruleable(path: Path) -> bool:
    text = str(path)
    return not has_control_chars(text) and not any(c.isspace() for c in text)


def render_rules(paths: Iterable[Path], key: str = "credwatch") -> RenderedRules:
    lines = ["# Managed by credwatch; do not edit."]
    skipped: list[Path] = []
    for path in paths:
        if not _is_ruleable(path):
            logger.warning("skipping unwatchable path (whitespace/control chars): %r", str(path))
            skipped.append(path)
            continue
        lines.append(f"-w {path} -p rwa -k {key}")
    return RenderedRules("\n".join(lines) + "\n", tuple(skipped))


def _write_atomic(target: Path, content: str) -> None:
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            os.fchmod(fh.fileno(), RULES_FILE_MODE)
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass
        raise


def _assert_not_immutable(runner: Runner) -> None:
    status = runner.run(["auditctl", "-s"])
    if status.returncode != 0:
        logger.warning(
            "auditctl -s failed (rc=%d): %s", status.returncode, (status.stderr or "").strip()
        )
    match = _ENABLED.search(status.stdout or "")
    if match and match.group(1) == "2":
        raise BackendError("audit rules are immutable (-e 2); reboot required to load credwatch rules")


def install_rules(
    paths: Iterable[Path],
    rules_file: Path = DEFAULT_RULES_FILE,
    *,
    runner: Runner,
    key: str = "credwatch",
) -> bool:
    """Make the file and the kernel state match. Returns True if written or reloaded.

    The file is only written when its content differs, but the loaded rule
    count is always verified so a re-run repairs a flushed or failed load.
    """
    text = render_rules(paths, key).text
    expected = sum(1 for line in text.splitlines() if line.startswith("-w "))
    try:
        try:
            current = rules_file.read_text(encoding="utf-8")
        except FileNotFoundError:
            current = None
        wrote = current != text
        if wrote:
            _assert_not_immutable(runner)
            _write_atomic(rules_file, text)
    except OSError as exc:
        raise BackendError(f"cannot write audit rules file {rules_file}: {exc}") from exc
    if not wrote and count_loaded_rules(runner, key) == expected:
        return False
    _assert_not_immutable(runner)
    result = runner.run(["augenrules", "--load"])
    if result.returncode != 0:
        raise BackendError(f"augenrules --load failed: {(result.stderr or '').strip()}")
    loaded = count_loaded_rules(runner, key)
    if loaded != expected:
        raise BackendError(
            f"loaded {loaded} credwatch rules, expected {expected} after augenrules --load"
        )
    return True


def ensure_auditd(runner: Runner) -> None:
    result = runner.run(["systemctl", "enable", "--now", "auditd"])
    if result.returncode != 0:
        raise BackendError(f"could not enable auditd: {(result.stderr or '').strip()}")


def count_loaded_rules(runner: Runner, key: str = "credwatch") -> int:
    result = runner.run(["auditctl", "-l"])
    if result.returncode != 0:
        raise BackendError(f"auditctl -l failed: {(result.stderr or '').strip()}")
    pattern = re.compile(rf"(?:-k\s+|key=){re.escape(key)}(?:\s|$)")
    return sum(1 for line in (result.stdout or "").splitlines() if pattern.search(line))


class LinuxAuditBackend(Backend):
    name = BACKEND_NAME

    def __init__(
        self,
        audit_log: Path,
        expected_rule_count: int,
        runner: Runner,
        export_checkpoint: Path,
        key: str = "credwatch",
        flush_after: float = 2.0,
    ) -> None:
        self._flush_after = flush_after
        self._audit_log = audit_log
        self._expected = expected_rule_count
        self._runner = runner
        self._checkpoint = export_checkpoint
        self._key = key

    def events(self, stop: threading.Event) -> Iterator[FileAccessEvent]:
        """Tail the audit log; follow() yields "" on idle polls, which tick the assembler."""
        assembler = AuditAssembler(self._key, self._flush_after)
        last_tick = time.monotonic()
        for line in follow(self._audit_log, stop):
            now = time.monotonic()
            if line:
                yield from assembler.feed(line, now)
                last_tick = now
            elif now - last_tick >= TICK_INTERVAL:
                yield from assembler.feed("", now)
                last_tick = now

    def health(self) -> tuple[str, ...]:
        try:
            loaded = count_loaded_rules(self._runner, self._key)
        except BackendError as exc:
            return (str(exc),)
        if loaded != self._expected:
            return (f"loaded credwatch audit rules: {loaded}, expected {self._expected}",)
        return ()

    def _ausearch(self, since: str) -> subprocess.CompletedProcess[str]:
        return self._runner.run(
            ["ausearch", "-k", self._key, "-i", "--checkpoint", str(self._checkpoint), "-ts", since],
            timeout=300,
        )

    def export_native_log(self, dest_dir: Path) -> Path | None:
        saved = self._checkpoint.read_bytes() if self._checkpoint.exists() else None
        result = self._ausearch("checkpoint" if saved is not None else "today")
        if result.returncode in _CHECKPOINT_ERRORS:
            logger.warning(
                "ausearch checkpoint unusable (rc=%d); retrying from today", result.returncode
            )
            result = self._ausearch("today")
        if result.returncode == 1 and _NO_MATCHES in (result.stdout or "") + (result.stderr or ""):
            return None
        if result.returncode != 0:
            raise BackendError(
                f"ausearch failed (rc={result.returncode}): {(result.stderr or '').strip()}"
            )
        if not (result.stdout or "").strip():
            return None
        out = dest_dir / f"ausearch-{datetime.now().strftime('%Y%m%dT%H%M%S%f')}.txt"
        try:
            dest_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(result.stdout)
        except OSError as exc:
            self._restore_checkpoint(saved)
            try:
                out.unlink(missing_ok=True)
            except OSError:
                logger.warning("could not remove partial export %s", out, exc_info=True)
            raise BackendError(f"could not write ausearch export {out}: {exc}") from exc
        return out

    def _restore_checkpoint(self, saved: bytes | None) -> None:
        """Undo ausearch's checkpoint advance so the next export retries the same events."""
        try:
            if saved is None:
                self._checkpoint.unlink(missing_ok=True)
            else:
                self._checkpoint.write_bytes(saved)
        except OSError:
            logger.exception(
                "export write failed and checkpoint %s could not be restored; "
                "events since the previous checkpoint were not exported",
                self._checkpoint,
            )
