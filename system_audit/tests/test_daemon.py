from __future__ import annotations

import json
import logging
import os
import signal
import sqlite3
import threading
import time
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest
import yaml

from credwatch import daemon as daemon_mod
from credwatch.backends.base import Backend
from credwatch.capture import CaptureStatus
from credwatch.config import load_config
from credwatch.correlate import Correlator
from credwatch.daemon import Daemon, build_correlator, run_forever
from credwatch.models import FileAccessEvent, ProcessedEvent, Verdict
from credwatch.platform_info import TargetUser
from credwatch.store import Store

BASE_TIME = datetime(2026, 11, 8, 7, 0, tzinfo=UTC).timestamp()  # before digest_hour 8
STEP_TIMEOUT = 2.0
EPOCH = datetime(2000, 1, 1, tzinfo=UTC)


class FakeClock:
    def __init__(self, t: float = BASE_TIME):
        self._t = t
        self._lock = threading.Lock()

    def __call__(self) -> float:
        with self._lock:
            return self._t

    def advance(self, seconds: float) -> None:
        with self._lock:
            self._t += seconds


class FakeBackend(Backend):
    """Each run is a list of events/exceptions; after the last run it streams fed events."""

    name = "fake"

    def __init__(self, runs=(), health=()):
        self._runs = [list(r) for r in runs]
        self.calls = 0
        self.health_result = tuple(health)
        self.exports: list[Path] = []
        self.live = threading.Event()
        self._feed: list[FileAccessEvent] = []
        self._feed_cv = threading.Condition()

    def feed(self, ev: FileAccessEvent) -> None:
        with self._feed_cv:
            self._feed.append(ev)
            self._feed_cv.notify_all()

    def events(self, stop):
        idx = self.calls
        self.calls += 1
        if idx < len(self._runs):
            for item in self._runs[idx]:
                if isinstance(item, BaseException):
                    raise item
                yield item
            if idx < len(self._runs) - 1:
                return  # ends unexpectedly -> daemon restarts
        self.live.set()
        while not stop.is_set():
            with self._feed_cv:
                if not self._feed:
                    self._feed_cv.wait(0.01)
                pending, self._feed = self._feed, []
            yield from pending

    def export_native_log(self, dest_dir: Path):
        self.exports.append(dest_dir)
        return None

    def health(self):
        return self.health_result


class FakeCorrelator:
    """Flags any event whose comm is 'evil'; 'boom' raises."""

    def __init__(self, on_process: Callable[[FileAccessEvent], None] | None = None):
        self._on_process = on_process

    def process(self, ev: FileAccessEvent) -> ProcessedEvent:
        if self._on_process is not None:
            self._on_process(ev)
        if ev.comm == "boom":
            raise RuntimeError("correlator exploded")
        allowed = ev.comm != "evil"
        return ProcessedEvent(ev, Verdict(allowed, None if not allowed else "rule"), None)


class FakeDispatcher:
    def __init__(self, log: list | None = None, fail_on: str | None = None):
        self.sent: list[tuple[str, str]] = []
        self.log = log if log is not None else []
        self.fail_on = fail_on
        self._lock = threading.Lock()
        self.started = False

    def start(self):
        self.started = True

    def submit(self, subject, body):
        if self.fail_on and self.fail_on in subject:
            raise RuntimeError("submit failed")
        with self._lock:
            self.sent.append((subject, body))
            self.log.append(("submit", subject))

    def stop(self, timeout=10.0):
        self.log.append(("dispatcher.stop", None))

    def subjects(self, needle: str) -> list[str]:
        with self._lock:
            return [s for s, _ in self.sent if needle in s]

    def bodies(self, needle: str) -> list[str]:
        with self._lock:
            return [b for s, b in self.sent if needle in s]


class FakeCapture:
    def __init__(self, log: list | None = None, running=True, last_error=None,
                 start_error=None, status_error=None):
        self.log = log if log is not None else []
        self.running = running
        self.last_error = last_error
        self.start_error = start_error
        self.status_error = status_error

    def start(self):
        if self.start_error:
            raise self.start_error

    def stop(self, timeout=10):
        self.log.append(("capture.stop", None))

    def status(self):
        if self.status_error:
            raise self.status_error
        return CaptureStatus(self.running, 0, self.last_error, None)


class FlakyStore(Store):
    """Real Store whose writes can be made to fail."""

    fail_record = False
    fail_meta: frozenset[str] = frozenset()

    def record(self, pe):
        if self.fail_record:
            raise sqlite3.OperationalError("disk I/O error")
        return super().record(pe)

    def set_meta(self, key, value):
        if key in self.fail_meta:
            raise sqlite3.OperationalError("attempt to write a readonly database")
        super().set_meta(key, value)


def ev(path="/home/alice/.ssh/id_ed25519", comm="ssh", ts=None, pid=4242) -> FileAccessEvent:
    return FileAccessEvent(
        timestamp=ts or datetime.fromtimestamp(BASE_TIME, UTC),
        path=path, pid=pid, ppid=1, exe=f"/usr/bin/{comm}", comm=comm,
        success=True, backend="fake", raw="raw",
    )


@pytest.fixture
def data_dir(tmp_path) -> Path:
    d = tmp_path / "data"
    d.mkdir(mode=0o700)
    (d / "canary").write_text("credwatch canary\n")
    return d


def make_config(tmp_path, data_dir, capture_enabled=True, **email):
    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(yaml.safe_dump({
        "data_dir": str(data_dir), "email": email, "capture": {"enabled": capture_enabled},
    }))
    target = TargetUser(name="alice", uid=1000, gid=1000, home=tmp_path / "home")
    return load_config(cfg_file, "linux", target)


@pytest.fixture
def config(tmp_path, data_dir):
    return make_config(tmp_path, data_dir)


@pytest.fixture
def store(data_dir):
    s = FlakyStore(data_dir / "events.db")
    yield s
    s.close()


def make_daemon(config, store, backend=None, correlator=None, dispatcher=None, capture=None,
                clock=None, sleep=None, tz=UTC):
    return Daemon(
        config, backend or FakeBackend(), store, correlator or FakeCorrelator(),
        dispatcher or FakeDispatcher(), capture or FakeCapture(),
        clock=clock or FakeClock(), hostname="host1", tz=tz,
        sleep=sleep or (lambda s: None), poll_seconds=0.005,
    )


class Harness:
    """Drives the daemon's main loop step by step on the test thread (Store is same-thread)."""

    def __init__(self, d: Daemon):
        self.d = d
        self.stop = threading.Event()

    def __enter__(self) -> Harness:
        self.d._start(self.stop)
        return self

    def __exit__(self, *exc) -> None:
        self.d._shutdown()

    def step(self, n: int = 1) -> None:
        for _ in range(n):
            self.d._step()

    def until(self, pred: Callable[[], object], timeout: float = STEP_TIMEOUT) -> None:
        deadline = time.monotonic() + timeout
        while not pred():
            if time.monotonic() > deadline:
                raise AssertionError("condition not reached")
            self.d._step()

    def settle(self) -> None:
        """Process everything the scripted backend runs produced."""
        self.until(self.d._backend.live.is_set)
        self.until(self.d._queue.empty)
        self.step()

    def boot_canary(self, clock: FakeClock) -> None:
        self.settle()
        clock.advance(daemon_mod.CANARY_STARTUP_DELAY_SECONDS)
        self.step()
        assert self.d._canary_deadline is not None


def stored(store) -> list:
    return store.events_since(EPOCH)


# --- events and flagged alerts -----------------------------------------------------


def test_every_event_stored_allowed_and_flagged(config, store):
    backend = FakeBackend(runs=[[ev(comm="ssh"), ev(comm="evil"), ev(comm="git")]])
    dispatcher = FakeDispatcher()
    with Harness(make_daemon(config, store, backend=backend, dispatcher=dispatcher)) as h:
        h.settle()

    rows = stored(store)
    assert [r.comm for r in rows] == ["ssh", "evil", "git"]
    assert [r.allowed for r in rows] == [True, False, True]
    assert len(dispatcher.subjects("FLAGGED")) == 1
    assert dispatcher.started


def test_flagged_event_dispatched_once_per_window(config, store):
    clock = FakeClock()
    backend = FakeBackend(runs=[[ev(comm="evil"), ev(comm="evil"), ev(comm="evil")]])
    dispatcher = FakeDispatcher()
    with Harness(make_daemon(config, store, backend=backend, dispatcher=dispatcher,
                             clock=clock)) as h:
        h.settle()
        assert len(dispatcher.subjects("FLAGGED")) == 1  # clock unchanged: nothing else due
        clock.advance(config.email.coalesce_seconds + 1)
        h.step()
        assert len(dispatcher.subjects("FLAGGED")) == 2

    bodies = dispatcher.bodies("FLAGGED")
    assert "Flagged events: 1" in bodies[0]
    assert "Flagged events: 2" in bodies[1]


def test_flagged_not_emailed_when_send_immediately_off(tmp_path, data_dir, store):
    config = make_config(tmp_path, data_dir, send_immediately=False)
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, backend=FakeBackend(runs=[[ev(comm="evil")]]),
                    dispatcher=dispatcher)
    with Harness(d) as h:
        h.settle()

    assert store.flagged_events()[0].comm == "evil"
    assert dispatcher.subjects("FLAGGED") == []


def test_correlator_error_stores_event_as_flagged(config, store):
    with Harness(make_daemon(config, store, backend=FakeBackend(runs=[[ev(comm="boom")]]))) as h:
        h.settle()

    row = store.flagged_events()[0]
    assert row.comm == "boom" and not row.allowed


# --- backend restart ----------------------------------------------------------------


def test_backend_crash_triggers_health_alert_and_restart(config, store):
    sleeps: list[float] = []
    backend = FakeBackend(runs=[[ev(comm="ssh"), RuntimeError("boom")], [ev(comm="git")]])
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, backend=backend, dispatcher=dispatcher, sleep=sleeps.append)
    with Harness(d) as h:
        h.settle()

    assert backend.calls == 2
    assert sleeps == [daemon_mod.BACKEND_BACKOFF_BASE_SECONDS]
    assert "boom" in dispatcher.bodies("DEGRADED")[0]
    assert [r.comm for r in stored(store)] == ["ssh", "git"]


def test_backend_backoff_doubles_up_to_cap_and_alerts_once(config, store, caplog):
    sleeps: list[float] = []
    backend = FakeBackend(runs=[[RuntimeError("down")] for _ in range(8)] + [[]])
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, backend=backend, dispatcher=dispatcher, sleep=sleeps.append)
    with caplog.at_level("CRITICAL", logger="credwatch.daemon"), Harness(d) as h:
        h.settle()

    assert sleeps == [5, 10, 20, 40, 80, 160, 300, 300]
    assert len(dispatcher.subjects("DEGRADED")) == 1  # no recovery in between: de-duplicated
    crit = [r for r in caplog.records if r.levelname == "CRITICAL"]
    assert crit and crit[0].exc_info is not None


def test_second_backend_crash_after_recovery_is_alerted(config, store):
    backend = FakeBackend(runs=[[RuntimeError("x")], [ev(), RuntimeError("x")], []])
    dispatcher = FakeDispatcher()
    with Harness(make_daemon(config, store, backend=backend, dispatcher=dispatcher)) as h:
        h.settle()

    alerts = [b for b in dispatcher.bodies("DEGRADED") if "RuntimeError: x" in b]
    assert len(alerts) == 2


def test_backend_stream_ending_is_restarted(config, store):
    sleeps: list[float] = []
    backend = FakeBackend(runs=[[ev()], [ev()]])
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, backend=backend, dispatcher=dispatcher, sleep=sleeps.append)
    with Harness(d) as h:
        h.settle()

    assert len(stored(store)) == 2
    assert sleeps == [5]  # reset to base: the run produced events
    assert "ended unexpectedly" in dispatcher.bodies("DEGRADED")[0]


# --- canary ------------------------------------------------------------------------


def test_canary_not_probed_until_backend_running_plus_delay(config, store):
    clock = FakeClock()
    d = make_daemon(config, store, clock=clock)
    with Harness(d) as h:
        h.settle()
        assert d._canary_deadline is None
        clock.advance(daemon_mod.CANARY_STARTUP_DELAY_SECONDS)
        h.step()
        assert d._canary_deadline == clock() + daemon_mod.CANARY_TIMEOUT_SECONDS


def test_canary_timeout_sends_health_alert(config, store, data_dir):
    clock = FakeClock()
    dispatcher = FakeDispatcher()
    with Harness(make_daemon(config, store, dispatcher=dispatcher, clock=clock)) as h:
        h.boot_canary(clock)
        clock.advance(daemon_mod.CANARY_TIMEOUT_SECONDS)
        h.step()

    canary = str(data_dir / "canary")
    assert dispatcher.subjects("canary")[0].endswith(
        f"canary probe failed: no audit event within 60 s for {canary}"
    )
    assert store.get_meta("last_canary_ok") is None


def test_canary_event_marks_probe_ok_and_clears_failure(config, store, data_dir):
    clock = FakeClock()
    backend = FakeBackend()
    dispatcher = FakeDispatcher()
    canary = str(data_dir / "canary")
    with Harness(make_daemon(config, store, backend=backend, dispatcher=dispatcher,
                             clock=clock)) as h:
        h.boot_canary(clock)
        clock.advance(daemon_mod.CANARY_TIMEOUT_SECONDS)
        h.step()  # first probe fails
        clock.advance(daemon_mod.CANARY_INTERVAL_SECONDS)
        h.step()  # second probe starts
        backend.feed(ev(path=canary, comm="credwatch", pid=os.getpid()))
        h.until(lambda: store.get_meta("last_canary_ok"))
        clock.advance(daemon_mod.CANARY_INTERVAL_SECONDS)
        h.step()
        clock.advance(daemon_mod.CANARY_TIMEOUT_SECONDS)
        h.step()  # third probe fails again within 6 h: re-alerted after the clear

    assert store.get_meta("last_canary_ok") == datetime.fromtimestamp(
        BASE_TIME + 5 + 60 + 3600, UTC).isoformat()
    assert len(dispatcher.subjects("canary probe failed")) == 2


def test_unreadable_canary_sends_health_alert(config, store, data_dir):
    (data_dir / "canary").unlink()
    clock = FakeClock()
    dispatcher = FakeDispatcher()
    with Harness(make_daemon(config, store, dispatcher=dispatcher, clock=clock)) as h:
        h.settle()
        clock.advance(daemon_mod.CANARY_STARTUP_DELAY_SECONDS)
        h.step()

    assert "cannot read" in dispatcher.subjects("canary probe failed")[0]


# --- health checks and de-duplication ---------------------------------------------


def _health_cycle(h: Harness, clock: FakeClock) -> None:
    clock.advance(daemon_mod.HEALTH_INTERVAL_SECONDS)
    h.step()


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


def test_queue_backlog_warning_is_rate_limited(config, store, caplog, monkeypatch):
    clock = FakeClock()
    d = make_daemon(config, store, clock=clock)
    monkeypatch.setattr(d._queue, "qsize", lambda: daemon_mod.QUEUE_BACKLOG_WARN + 1)

    with caplog.at_level(logging.WARNING, logger="credwatch.daemon"):
        d._check_health(clock())
        d._check_health(clock() + 30)
        d._check_health(clock() + daemon_mod.QUEUE_BACKLOG_WARN_INTERVAL_SECONDS)

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


# --- lifecycle -------------------------------------------------------------------


def test_shutdown_drains_queue(config, store):
    log: list = []
    stop = threading.Event()
    n = 20
    events = [ev(comm="evil" if i == n - 1 else "ssh") for i in range(n)]
    correlator = FakeCorrelator(on_process=lambda e: stop.set())
    dispatcher = FakeDispatcher(log)
    d = make_daemon(config, store, backend=FakeBackend(runs=[events]), correlator=correlator,
                    dispatcher=dispatcher, capture=FakeCapture(log))

    d.run(stop)

    assert len(stored(store)) == n
    kinds = [k for k, _ in log]
    assert kinds.index("capture.stop") < kinds.index("dispatcher.stop")
    assert ("submit", dispatcher.subjects("FLAGGED")[0]) in log
    assert kinds[-1] == "dispatcher.stop"


def test_shutdown_flushes_pending_coalesced_batch(config, store):
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, dispatcher=dispatcher,
                    backend=FakeBackend(runs=[[ev(comm="evil"), ev(comm="evil")]]))
    with Harness(d) as h:
        h.settle()
        assert len(dispatcher.subjects("FLAGGED")) == 1

    assert len(dispatcher.subjects("FLAGGED")) == 2


def test_shutdown_flush_error_still_stops_dispatcher(config, store):
    log: list = []
    dispatcher = FakeDispatcher(log, fail_on="FLAGGED")
    d = make_daemon(config, store, dispatcher=dispatcher,
                    backend=FakeBackend(runs=[[ev(comm="evil"), ev(comm="evil")]]))
    with Harness(d) as h:
        h.settle()

    assert log[-1] == ("dispatcher.stop", None)
    assert len(stored(store)) == 2


def test_capture_start_failure_stops_dispatcher(config, store):
    log: list = []
    d = make_daemon(config, store, dispatcher=FakeDispatcher(log),
                    capture=FakeCapture(log, start_error=RuntimeError("no tcpdump")))

    with pytest.raises(RuntimeError, match="no tcpdump"):
        d.run(threading.Event())

    assert ("dispatcher.stop", None) in log


def test_run_forever_stops_on_sigterm(config, store):
    backend = FakeBackend()
    d = make_daemon(config, store, backend=backend)
    previous = signal.getsignal(signal.SIGTERM)

    def send_sigterm():
        backend.live.wait(STEP_TIMEOUT)
        os.kill(os.getpid(), signal.SIGTERM)

    t = threading.Thread(target=send_sigterm)
    t.start()
    run_forever(d)
    t.join()

    assert signal.getsignal(signal.SIGTERM) is previous


def test_build_correlator_wires_allowlist(config):
    corr = build_correlator(config)

    assert isinstance(corr, Correlator)
    assert corr._allowlist.os_name == "linux"
    assert len(corr._allowlist.rules) == len(config.allowlist)
    assert corr._self_pid == os.getpid()
    assert corr._canary == str(config.data_dir / "canary")
