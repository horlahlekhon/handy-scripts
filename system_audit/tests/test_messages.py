from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from credwatch.messages import format_digest, format_flagged_alert, format_health_alert
from credwatch.models import (
    Connection,
    FileAccessEvent,
    NetworkSnapshot,
    ProcessedEvent,
    ProcessInfo,
    Verdict,
)
from credwatch.store import DailySummary, EventRow

TS = datetime(2026, 11, 7, 12, 30, 45, tzinfo=timezone.utc)
TZ = timezone(timedelta(hours=1))
DATA = Path("/var/lib/credwatch")


def _event(path="/root/.aws/credentials", exe="/usr/bin/curl", comm="curl",
           snapshot="default", canonical="/root/.aws/credentials", inode=5):
    if snapshot == "default":
        snapshot = NetworkSnapshot(
            pid=42, taken_at=TS, alive=True,
            connections=(Connection("inet", "tcp", "10.0.0.1:5555", "1.2.3.4:443", "ESTABLISHED"),),
            ancestry=(ProcessInfo(42, exe, ("curl", "x")), ProcessInfo(1, "/sbin/init", ("init",))),
            error=None,
        )
    ev = FileAccessEvent(TS, path, 42, 1, exe, comm, True, "linux_audit", "raw", inode=inode, dev=1)
    return ProcessedEvent(ev, Verdict(False, None), snapshot, canonical)


def _alert(events, host="h1"):
    return format_flagged_alert(events, host, data_dir=DATA, rotate_seconds=300, tz=TZ)


def test_flagged_subject_names_process_and_count():
    subject, body = _alert([_event(), _event(path="/root/.ssh/id_rsa")])
    assert subject == "[credwatch][h1] FLAGGED: /usr/bin/curl accessed 2 credential path(s)"
    assert "2026-11-07T12:30:45" in body
    assert "13:30:45" in body  # local time in injected tz
    assert "1.2.3.4:443" in body
    assert "/sbin/init" in body
    assert "canonical path" in body
    assert str(DATA / "events.db") in body
    for sub in ("captures", "audit-exports", "logs"):
        assert str(DATA / sub) in body
    assert "latest one before 2026-11-07 13:30:45" in body


def test_body_shows_snapshot_error_when_process_gone():
    snap = NetworkSnapshot(42, TS, False, (), (), "process gone")
    _, body = _alert([_event(snapshot=snap)])
    assert "process gone" in body


def test_body_handles_missing_snapshot():
    _, body = _alert([_event(snapshot=None)])
    assert "no snapshot" in body


def test_unverified_path_marked():
    _, body = _alert([_event(canonical=None)])
    assert "UNVERIFIED path" in body
    _, body = _alert([_event(canonical=None, inode=None)])
    assert "UNVERIFIED path" not in body


def test_matched_rule_shown():
    ev = _event()
    ev = ProcessedEvent(ev.event, Verdict(False, "rule-x"), ev.snapshot, ev.canonical_path)
    _, body = _alert([ev])
    assert "rule-x" in body


def test_subject_strips_crlf_injection():
    ev = _event(exe=None, comm="x\r\nBcc: evil@x")
    subject, _ = _alert([ev], host="h\n1")
    assert "\r" not in subject and "\n" not in subject
    assert "\x85" not in format_health_alert(["a\x85b c"], "h")[0]
    long_subject, _ = format_health_alert(["p" * 500], "h")
    assert len(long_subject) <= 200


def test_body_escapes_control_chars():
    ev = _event(path="/root/a\nb", exe="/x\rinj", comm="c\x00d")
    _, body = _alert([ev])
    assert "a\\nb" in body
    assert "/x\\rinj" in body
    assert "c\\x00d" in body
    assert "a\nb" not in body


def _summary(total=0, flagged=0):
    return DailySummary(date(2026, 11, 7), total, flagged, (), ())


def test_digest_zero_events_still_renders():
    subject, body = format_digest(_summary(), [], [], "h1")
    assert subject == "[credwatch][h1] Daily digest 2026-11-07: 0 flagged / 0 total"
    assert body.strip()


def test_digest_lists_flagged_health_and_top():
    row = EventRow(1, TS, "/root/.aws/credentials", 42, 1, "/usr/bin/curl", "curl", True,
                   "linux_audit", False, None, "raw", None)
    summ = DailySummary(date(2026, 11, 7), 10, 1, (("curl", 3),), (("/root/.aws/credentials", 3),))
    _, body = format_digest(summ, [row], ["tcpdump down"], "h1")
    assert "tcpdump down" in body and "curl" in body and "/root/.aws/credentials" in body


def test_health_subject():
    subject, body = format_health_alert(["auditd stopped", "disk full"], "h1")
    assert subject == "[credwatch][h1] DEGRADED: auditd stopped"
    assert "disk full" in body
