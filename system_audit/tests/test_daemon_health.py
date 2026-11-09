"""Daemon health checks and de-duplication, broken store, export, heartbeat and digest."""
from __future__ import annotations

import json
import logging
import os
import threading
from datetime import UTC, date, datetime, timedelta
from zoneinfo import ZoneInfo

import pytest

from credwatch import daemon as daemon_mod
from credwatch.models import ProcessedEvent, Verdict
from _daemon_support import (
    BASE_TIME,
    FakeClock,
    FakeBackend,
    FakeDispatcher,
    FakeCapture,
    ev,
    data_dir,
    make_config,
    config,
    store,
    make_daemon,
    Harness,
    stored,
    _health_cycle,
    LOW_DISK,
)


def test_health_problems_deduplicated_for_6h_across_restart(config, store):
    clock = FakeClock()
    backend = FakeBackend(health=("rules missing",))
    capture = FakeCapture(running=False, last_error="tcpdump exited 1")
    dispatcher = FakeDispatcher()

    def daemon():
        return make_daemon(config, store, backend=backend, dispatcher=dispatcher,
                           capture=capture, clock=clock)

    def alerts():
        return [b for b in dispatcher.bodies("DEGRADED") if "packet capture not running" in b]

    with Harness(daemon()) as h:
        h.step()
        _health_cycle(h, clock)
    assert len(alerts()) == 1
    assert "rules missing" in alerts()[0]
    assert "packet capture not running: tcpdump exited 1" in alerts()[0]

    with Harness(daemon()) as h:
        h.step()
    assert len(alerts()) == 1  # restart within 6 h: suppressed via persisted state

    clock.advance(daemon_mod.HEALTH_DEDUP_SECONDS)
    with Harness(daemon()) as h:
        h.step()
    assert len(alerts()) == 2

    backend.health_result = ("something else",)
    with Harness(daemon()) as h:
        h.step()
    assert len(alerts()) == 3
    assert json.loads(store.get_meta("last_health_alert"))["problems"] == [
        "packet capture not running: tcpdump exited 1", "something else",
    ]


def test_cleared_problem_recurring_within_6h_is_realerted(config, store):
    clock = FakeClock()
    backend = FakeBackend(health=("A",))
    dispatcher = FakeDispatcher()
    with Harness(make_daemon(config, store, backend=backend, dispatcher=dispatcher,
                             clock=clock)) as h:
        h.step()
        backend.health_result = ()
        _health_cycle(h, clock)
        backend.health_result = ("A",)
        _health_cycle(h, clock)

    assert len([b for b in dispatcher.bodies("DEGRADED") if "  - A\n" in b]) == 2


def test_superset_after_partial_clear_is_realerted(config, store):
    clock = FakeClock()
    backend = FakeBackend(health=("A", "B"))
    dispatcher = FakeDispatcher()
    with Harness(make_daemon(config, store, backend=backend, dispatcher=dispatcher,
                             clock=clock)) as h:
        h.step()
        backend.health_result = ("A",)
        _health_cycle(h, clock)
        backend.health_result = ("A", "B")
        _health_cycle(h, clock)

    sent = [b for b in dispatcher.bodies("DEGRADED") if "  - A\n" in b]
    assert len(sent) == 3
    assert "  - B\n" in sent[0] and "  - B\n" not in sent[1] and "  - B\n" in sent[2]


def test_capture_disabled_is_not_a_health_problem(tmp_path, data_dir, store):
    config = make_config(tmp_path, data_dir, capture_enabled=False)
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, dispatcher=dispatcher, capture=FakeCapture(running=False))
    with Harness(d) as h:
        h.step()

    assert dispatcher.subjects("DEGRADED") == []


@pytest.mark.parametrize("capture_enabled", [True, False])
def test_low_disk_space_is_a_health_problem(tmp_path, data_dir, store, capture_enabled):
    config = make_config(tmp_path, data_dir, capture_enabled=capture_enabled)
    dispatcher = FakeDispatcher()
    capture = FakeCapture(running=False, paused=True, disk_problem=LOW_DISK)
    d = make_daemon(config, store, dispatcher=dispatcher, capture=capture)
    with Harness(d) as h:
        h.step()

    assert capture.disk_checks == 1
    body = dispatcher.bodies("DEGRADED")[0]
    assert LOW_DISK in body
    assert "packet capture not running" not in body  # paused on purpose, said once


def test_disk_space_recovery_clears_health_problem(config, store):
    dispatcher = FakeDispatcher()
    clock = FakeClock()
    capture = FakeCapture(running=False, paused=True, disk_problem=LOW_DISK)
    d = make_daemon(config, store, dispatcher=dispatcher, capture=capture, clock=clock)
    with Harness(d) as h:
        h.step()
        capture.disk_problem, capture.paused, capture.running = None, False, True
        clock.advance(daemon_mod.HEALTH_INTERVAL_SECONDS)
        h.step()

    assert d._health_problems == ()
    assert len(dispatcher.bodies("DEGRADED")) == 1


def test_disk_space_check_error_is_a_health_problem(config, store):
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, dispatcher=dispatcher,
                    capture=FakeCapture(disk_error=RuntimeError("statvfs broke")))
    with Harness(d) as h:
        h.step()

    body = dispatcher.bodies("DEGRADED")[0]
    assert "disk space check failed: RuntimeError: statvfs broke" in body


def test_capture_status_error_still_reports_backend_problems(config, store):
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, dispatcher=dispatcher,
                    backend=FakeBackend(health=("rules missing",)),
                    capture=FakeCapture(status_error=RuntimeError("ps broke")))
    with Harness(d) as h:
        h.step()

    body = dispatcher.bodies("DEGRADED")[0]
    assert "rules missing" in body and "capture status check failed: RuntimeError: ps broke" in body


def test_dead_reader_thread_is_a_health_problem(config, store):
    clock = FakeClock()
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, dispatcher=dispatcher, clock=clock)
    with Harness(d) as h:
        h.step()
        real_reader, d._reader = d._reader, threading.Thread(target=lambda: None)
        _health_cycle(h, clock)
        d._reader = real_reader

    assert "backend reader thread not running" in dispatcher.bodies("DEGRADED")[0]


def test_queue_backlog_warning_runs_every_tick_rate_limited(config, store, caplog, monkeypatch):
    clock = FakeClock()
    d = make_daemon(config, store, clock=clock)
    monkeypatch.setattr(d._queue, "qsize", lambda: daemon_mod.QUEUE_BACKLOG_WARN + 1)

    with caplog.at_level(logging.WARNING, logger="credwatch.daemon"), Harness(d) as h:
        h.step()
        clock.advance(30)  # no health job due: warning still checked, but rate-limited
        h.step()
        clock.advance(daemon_mod.QUEUE_BACKLOG_WARN_INTERVAL_SECONDS - 30)
        h.step()

    assert len([r for r in caplog.records if "backlog" in r.getMessage()]) == 2


def test_reported_problem_and_alert_error_written_by_main_loop(config, store):
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, dispatcher=dispatcher)
    with Harness(d) as h:
        for target, arg in ((d.report_alert_error, "smtp down"),
                            (d.report_problem, "tcpdump crashed")):
            t = threading.Thread(target=target, args=(arg,))
            t.start()
            t.join()
        h.until(d._queue.empty)

    assert store.get_meta("last_alert_error").endswith("smtp down")
    assert dispatcher.subjects("tcpdump crashed")


# --- broken store -----------------------------------------------------------------


def test_store_write_failure_sends_health_alert(config, store):
    backend = FakeBackend()
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, backend=backend, dispatcher=dispatcher)

    def store_alerts():
        return dispatcher.bodies("event store write failed: OperationalError")

    with Harness(d) as h:
        h.settle()
        store.fail_record = True
        for _ in range(3):
            backend.feed(ev())
        h.until(lambda: d._failed_writes == 2)  # first counted into the alert, then 2 more
        assert len(store_alerts()) == 1
        assert "Failed event-store writes since last report: 1" in store_alerts()[0]

        store.fail_record = False
        backend.feed(ev())
        h.until(lambda: len(stored(store)) == 1)  # success clears the store problem
        store.fail_record = True
        backend.feed(ev())
        h.until(lambda: len(store_alerts()) == 2)

    assert "Failed event-store writes since last report: 3" in store_alerts()[1]


def test_digest_not_resent_when_meta_write_fails(config, store):
    store.fail_meta = frozenset({"last_digest_day"})
    clock = FakeClock(datetime(2026, 11, 8, 9, 0, tzinfo=UTC).timestamp())
    dispatcher = FakeDispatcher()
    with Harness(make_daemon(config, store, dispatcher=dispatcher, clock=clock)) as h:
        h.step(5)

    assert len(dispatcher.subjects("Daily digest")) == 1


# --- export, heartbeat, digest ------------------------------------------------------


def test_heartbeat_and_native_export_with_pruning(config, store, data_dir):
    clock = FakeClock()
    backend = FakeBackend()
    exports = data_dir / "audit-exports"
    exports.mkdir(mode=0o700)
    old = exports / "ausearch-old.txt"
    old.write_text("x")
    stale = BASE_TIME - timedelta(days=config.audit_export.retention_days + 1).total_seconds()
    os.utime(old, (stale, stale))
    fresh = exports / "ausearch-new.txt"
    fresh.write_text("y")
    os.utime(fresh, (BASE_TIME, BASE_TIME))
    with Harness(make_daemon(config, store, backend=backend, clock=clock)) as h:
        h.step()
        assert len(backend.exports) == 1
        assert store.get_meta("heartbeat") == datetime.fromtimestamp(BASE_TIME, UTC).isoformat()
        clock.advance(config.audit_export.interval_minutes * 60)
        h.step()
        assert len(backend.exports) == 2
        assert store.get_meta("heartbeat") == datetime.fromtimestamp(clock(), UTC).isoformat()

    assert backend.exports[0] == exports
    assert not old.exists() and fresh.exists()


def test_digest_sent_once_per_day_across_restart(config, store):
    yesterday = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
    store.record(ProcessedEvent(ev(comm="evil", ts=yesterday), Verdict(False, None), None))
    store.record(ProcessedEvent(ev(comm="ssh", ts=yesterday), Verdict(True, "r"), None))
    today = datetime(2026, 11, 8, 8, 30, tzinfo=UTC)
    store.record(ProcessedEvent(ev(comm="evil", ts=today), Verdict(False, None), None))
    clock = FakeClock(datetime(2026, 11, 8, 9, 0, tzinfo=UTC).timestamp())
    dispatcher = FakeDispatcher()

    def daemon():
        return make_daemon(config, store, dispatcher=dispatcher, clock=clock)

    with Harness(daemon()) as h:
        h.step(3)
    with Harness(daemon()) as h:
        h.step(3)

    assert dispatcher.subjects("Daily digest") == [
        "[credwatch][host1] Daily digest 2026-11-07: 1 flagged / 2 total"
    ]
    body = dispatcher.bodies("Daily digest")[0]
    assert "2026-11-07" in body.split("Flagged events:\n")[1]
    assert "2026-11-08" not in body.split("Flagged events:\n")[1]  # R34: today excluded
    assert store.get_meta("last_digest_day") == "2026-11-08"
    assert store.get_daily_summary(date(2026, 11, 7)).total == 2

    clock.advance(timedelta(days=1).total_seconds())
    with Harness(daemon()) as h:
        h.step()
    assert len(dispatcher.subjects("Daily digest")) == 2
    assert store.get_meta("last_digest_day") == "2026-11-09"


def test_digest_day_bounds_follow_dst(config, store):
    london = ZoneInfo("Europe/London")  # BST ends 2026-10-25 02:00 -> 25-hour day
    for ts in ("2026-10-24T22:30:00+00:00",   # Oct 24 23:30 BST: excluded
               "2026-10-24T23:30:00+00:00",   # Oct 25 00:30 BST: included
               "2026-10-25T23:30:00+00:00"):  # Oct 25 23:30 GMT: included
        store.record(ProcessedEvent(ev(comm="evil", ts=datetime.fromisoformat(ts)),
                                    Verdict(False, None), None))
    clock = FakeClock(datetime(2026, 10, 26, 9, 0, tzinfo=london).timestamp())
    dispatcher = FakeDispatcher()
    with Harness(make_daemon(config, store, dispatcher=dispatcher, clock=clock, tz=london)) as h:
        h.step()

    assert dispatcher.subjects("Daily digest") == [
        "[credwatch][host1] Daily digest 2026-10-25: 2 flagged / 2 total"
    ]
    flagged_section = dispatcher.bodies("Daily digest")[0].split("Flagged events:\n")[1]
    assert len(flagged_section.strip().splitlines()) == 2


def test_no_digest_before_digest_hour(config, store):
    dispatcher = FakeDispatcher()
    with Harness(make_daemon(config, store, dispatcher=dispatcher)) as h:  # 07:00 < 08:00
        h.step()

    assert dispatcher.subjects("Daily digest") == []
    assert store.get_meta("last_digest_day") is None


def test_system_zone_prefers_tz_env(monkeypatch):
    monkeypatch.setenv("TZ", "Europe/London")
    assert daemon_mod.system_zone() == ZoneInfo("Europe/London")
    monkeypatch.setenv("TZ", "Not/AZone")
    monkeypatch.setattr(daemon_mod, "LOCALTIME_PATH", "/nonexistent/localtime")
    assert daemon_mod.system_zone() is None
