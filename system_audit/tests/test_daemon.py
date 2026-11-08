from __future__ import annotations

import json
import os
import signal
import sqlite3
import threading
import time
from collections.abc import Callable
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import pytest

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
SCENARIO_TIMEOUT = 2.0


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
    """Flags any event whose comm is 'evil'."""

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
    def __init__(self, log: list | None = None):
        self.sent: list[tuple[str, str]] = []
        self.log = log if log is not None else []
        self._lock = threading.Lock()
        self.started = False

    def start(self):
        self.started = True

    def submit(self, subject, body):
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
    def __init__(self, log: list | None = None, running=True, last_error=None):
        self.log = log if log is not None else []
        self.running = running
        self.last_error = last_error
        self.started = False

    def start(self):
        self.started = True

    def stop(self, timeout=10):
        self.log.append(("capture.stop", None))

    def status(self):
        return CaptureStatus(self.running, 0, self.last_error, None)


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


def make_config(tmp_path, data_dir, **email):
    import yaml

    cfg_file = tmp_path / "config.yaml"
    cfg_file.write_text(yaml.safe_dump({
        "data_dir": str(data_dir),
        "email": email,
        "capture": {"enabled": True},
    }))
    target = TargetUser(name="alice", uid=1000, gid=1000, home=tmp_path / "home")
    return load_config(cfg_file, "linux", target)


@pytest.fixture
def config(tmp_path, data_dir):
    return make_config(tmp_path, data_dir)


@pytest.fixture
def store(data_dir):
    s = Store(data_dir / "events.db")
    yield s
    s.close()


def meta(data_dir: Path, key: str) -> str | None:
    """Read meta from another thread via a separate connection (Store is main-thread only)."""
    conn = sqlite3.connect(data_dir / "events.db")
    try:
        row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return None if row is None else row[0]
    except sqlite3.OperationalError:
        return None
    finally:
        conn.close()


def stored_count(data_dir: Path) -> int:
    conn = sqlite3.connect(data_dir / "events.db")
    try:
        return conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
    finally:
        conn.close()


def wait_for(pred: Callable[[], bool], timeout: float = SCENARIO_TIMEOUT) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.005)
    return pred()


def run_scenario(d: Daemon, scenario: Callable[[], None], stop: threading.Event | None = None):
    """Run the daemon on this thread (Store is single-thread) while `scenario` drives it."""
    stop = stop or threading.Event()
    errors: list[BaseException] = []

    def drive():
        try:
            scenario()
        except BaseException as exc:  # surfaced on the main thread below
            errors.append(exc)
        finally:
            stop.set()

    t = threading.Thread(target=drive)
    t.start()
    d.run(stop)
    t.join()
    if errors:
        raise errors[0]


def make_daemon(config, store, backend=None, correlator=None, dispatcher=None, capture=None,
                clock=None, sleep=None):
    return Daemon(
        config, backend or FakeBackend(), store, correlator or FakeCorrelator(),
        dispatcher or FakeDispatcher(), capture or FakeCapture(),
        clock=clock or FakeClock(), hostname="host1", tz=UTC,
        sleep=sleep or (lambda s: None), poll_seconds=0.005,
    )


def heartbeat_written(data_dir):
    return lambda: meta(data_dir, "heartbeat") is not None


# --- tests -----------------------------------------------------------------


def test_every_event_stored_allowed_and_flagged(config, store, data_dir):
    backend = FakeBackend(runs=[[ev(comm="ssh"), ev(comm="evil"), ev(comm="git")]])
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, backend=backend, dispatcher=dispatcher)

    run_scenario(d, lambda: wait_for(lambda: stored_count(data_dir) == 3))

    rows = store.events_since(datetime(2000, 1, 1, tzinfo=UTC))
    assert [r.comm for r in rows] == ["ssh", "evil", "git"]
    assert [r.allowed for r in rows] == [True, False, True]
    assert len(dispatcher.subjects("FLAGGED")) == 1
    assert dispatcher.started


def test_flagged_event_dispatched_once_per_window(config, store, data_dir):
    clock = FakeClock()
    backend = FakeBackend(runs=[[ev(comm="evil"), ev(comm="evil"), ev(comm="evil")]])
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, backend=backend, dispatcher=dispatcher, clock=clock)

    def scenario():
        assert wait_for(lambda: stored_count(data_dir) == 3)
        time.sleep(0.05)
        assert len(dispatcher.subjects("FLAGGED")) == 1
        clock.advance(config.email.coalesce_seconds + 1)
        assert wait_for(lambda: len(dispatcher.subjects("FLAGGED")) == 2)

    run_scenario(d, scenario)

    bodies = dispatcher.bodies("FLAGGED")
    assert "Flagged events: 1" in bodies[0]
    assert "Flagged events: 2" in bodies[1]


def test_flagged_not_emailed_when_send_immediately_off(tmp_path, data_dir, store):
    config = make_config(tmp_path, data_dir, send_immediately=False)
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, backend=FakeBackend(runs=[[ev(comm="evil")]]),
                    dispatcher=dispatcher)

    run_scenario(d, lambda: wait_for(lambda: stored_count(data_dir) == 1))

    assert store.flagged_events()[0].comm == "evil"
    assert dispatcher.subjects("FLAGGED") == []


def test_backend_crash_triggers_health_alert_and_restart(config, store, data_dir):
    sleeps: list[float] = []
    backend = FakeBackend(runs=[[ev(comm="ssh"), RuntimeError("boom")], [ev(comm="git")]])
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, backend=backend, dispatcher=dispatcher, sleep=sleeps.append)

    run_scenario(d, lambda: wait_for(lambda: stored_count(data_dir) == 2
                                     and dispatcher.subjects("DEGRADED")))

    assert backend.calls == 2
    assert sleeps == [daemon_mod.BACKEND_BACKOFF_BASE_SECONDS]
    assert "boom" in dispatcher.bodies("DEGRADED")[0]
    assert [r.comm for r in store.events_since(datetime(2000, 1, 1, tzinfo=UTC))] == ["ssh", "git"]


def test_backend_backoff_doubles_up_to_cap_and_alerts_once(config, store, data_dir, caplog):
    sleeps: list[float] = []
    runs = [[RuntimeError("down")] for _ in range(8)] + [[]]
    backend = FakeBackend(runs=runs)
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, backend=backend, dispatcher=dispatcher, sleep=sleeps.append)

    with caplog.at_level("CRITICAL", logger="credwatch.daemon"):
        run_scenario(d, lambda: wait_for(backend.live.is_set))

    assert sleeps == [5, 10, 20, 40, 80, 160, 300, 300]
    assert len(dispatcher.subjects("DEGRADED")) == 1  # same problem set de-duplicated
    crit = [r for r in caplog.records if r.levelname == "CRITICAL"]
    assert crit and crit[0].exc_info is not None


def test_backend_stream_ending_is_restarted(config, store, data_dir):
    sleeps: list[float] = []
    backend = FakeBackend(runs=[[ev()], [ev()]])
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, backend=backend, dispatcher=dispatcher, sleep=sleeps.append)

    run_scenario(d, lambda: wait_for(lambda: stored_count(data_dir) == 2))

    assert sleeps == [5]  # reset to base: the run produced events
    assert "ended unexpectedly" in dispatcher.bodies("DEGRADED")[0]


def test_correlator_error_stores_event_as_flagged(config, store, data_dir):
    d = make_daemon(config, store, backend=FakeBackend(runs=[[ev(comm="boom")]]))

    run_scenario(d, lambda: wait_for(lambda: stored_count(data_dir) == 1))

    row = store.flagged_events()[0]
    assert row.comm == "boom" and not row.allowed


def test_canary_timeout_sends_health_alert(config, store, data_dir):
    clock = FakeClock()
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, dispatcher=dispatcher, clock=clock)

    def scenario():
        assert wait_for(heartbeat_written(data_dir))
        clock.advance(daemon_mod.CANARY_TIMEOUT_SECONDS + 1)
        assert wait_for(lambda: dispatcher.subjects("canary probe failed"))

    run_scenario(d, scenario)

    canary = str(data_dir / "canary")
    assert dispatcher.subjects("canary")[0].endswith(
        f"canary probe failed: no audit event within 60 s for {canary}"
    )
    assert store.get_meta("last_canary_ok") is None


def test_canary_event_marks_probe_ok(config, store, data_dir):
    backend = FakeBackend()
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, backend=backend, dispatcher=dispatcher)
    canary = str(data_dir / "canary")

    def scenario():
        assert wait_for(heartbeat_written(data_dir))
        backend.feed(ev(path=canary, comm="credwatch", pid=os.getpid()))
        assert wait_for(lambda: meta(data_dir, "last_canary_ok") is not None)

    run_scenario(d, scenario)

    assert store.get_meta("last_canary_ok") == datetime.fromtimestamp(BASE_TIME, UTC).isoformat()
    assert dispatcher.subjects("canary") == []


def test_unreadable_canary_sends_health_alert(config, store, data_dir):
    (data_dir / "canary").unlink()
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, dispatcher=dispatcher)

    run_scenario(d, lambda: wait_for(lambda: dispatcher.subjects("canary probe failed")))

    assert "cannot read" in dispatcher.subjects("canary probe failed")[0]


def test_health_problems_deduplicated_for_6h_across_restart(config, store, data_dir):
    clock = FakeClock()
    backend = FakeBackend(health=("rules missing",))
    capture = FakeCapture(running=False, last_error="tcpdump exited 1")
    dispatcher = FakeDispatcher()

    def daemon():
        return make_daemon(config, store, backend=backend, dispatcher=dispatcher,
                           capture=capture, clock=clock)

    def health_alerts():  # canary timeouts also say DEGRADED; count only this problem set
        return [b for b in dispatcher.bodies("DEGRADED") if "packet capture not running" in b]

    def first():
        assert wait_for(health_alerts)
        clock.advance(daemon_mod.HEALTH_INTERVAL_SECONDS + 1)
        time.sleep(0.05)

    run_scenario(daemon(), first)
    assert len(health_alerts()) == 1
    body = health_alerts()[0]
    assert "rules missing" in body and "packet capture not running: tcpdump exited 1" in body

    run_scenario(daemon(), lambda: wait_for(heartbeat_written(data_dir)) and time.sleep(0.05))
    assert len(health_alerts()) == 1  # restart within 6 h: suppressed

    clock.advance(daemon_mod.HEALTH_DEDUP_SECONDS + 1)
    run_scenario(daemon(), lambda: wait_for(lambda: len(health_alerts()) == 2))

    backend.health_result = ("something else",)
    clock.advance(daemon_mod.HEALTH_INTERVAL_SECONDS + 1)
    run_scenario(daemon(), lambda: wait_for(lambda: len(health_alerts()) == 3))
    assert "something else" in health_alerts()[2]
    assert json.loads(store.get_meta("last_health_alert"))["problems"] == [
        "packet capture not running: tcpdump exited 1", "something else",
    ]


def test_capture_disabled_is_not_a_health_problem(tmp_path, data_dir, store):
    import yaml

    cfg_file = tmp_path / "c.yaml"
    cfg_file.write_text(yaml.safe_dump({"data_dir": str(data_dir), "capture": {"enabled": False}}))
    config = load_config(cfg_file, "linux", TargetUser("alice", 1000, 1000, tmp_path))
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, dispatcher=dispatcher, capture=FakeCapture(running=False))

    run_scenario(d, lambda: wait_for(heartbeat_written(data_dir)) and time.sleep(0.05))

    assert dispatcher.subjects("DEGRADED") == []


def test_reported_problem_and_alert_error_written_by_main_loop(config, store, data_dir):
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, dispatcher=dispatcher)

    def scenario():
        assert wait_for(heartbeat_written(data_dir))
        threading.Thread(target=d.report_alert_error, args=("smtp down",)).start()
        threading.Thread(target=d.report_problem, args=("tcpdump crashed",)).start()
        assert wait_for(lambda: meta(data_dir, "last_alert_error") is not None)
        assert wait_for(lambda: dispatcher.subjects("tcpdump crashed"))

    run_scenario(d, scenario)

    assert store.get_meta("last_alert_error").endswith("smtp down")


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
    d = make_daemon(config, store, backend=backend, clock=clock)

    def scenario():
        assert wait_for(lambda: len(backend.exports) == 1)
        clock.advance(config.audit_export.interval_minutes * 60)
        assert wait_for(lambda: len(backend.exports) == 2)
        assert wait_for(lambda: meta(data_dir, "heartbeat")
                        == datetime.fromtimestamp(clock(), UTC).isoformat())

    run_scenario(d, scenario)

    assert backend.exports[0] == exports
    assert not old.exists() and fresh.exists()


def test_digest_sent_once_per_day_across_restart(config, store, data_dir):
    yesterday = datetime(2026, 11, 7, 12, 0, tzinfo=UTC)
    store.record(ProcessedEvent(ev(comm="evil", ts=yesterday), Verdict(False, None), None))
    store.record(ProcessedEvent(ev(comm="ssh", ts=yesterday), Verdict(True, "r"), None))
    clock = FakeClock(datetime(2026, 11, 8, 9, 0, tzinfo=UTC).timestamp())
    dispatcher = FakeDispatcher()

    def daemon():
        return make_daemon(config, store, dispatcher=dispatcher, clock=clock)

    def ticked():
        assert wait_for(heartbeat_written(data_dir))
        time.sleep(0.05)

    run_scenario(daemon(), lambda: wait_for(lambda: dispatcher.subjects("Daily digest")))
    run_scenario(daemon(), ticked)

    digests = dispatcher.subjects("Daily digest")
    assert digests == ["[credwatch][host1] Daily digest 2026-11-07: 1 flagged / 2 total"]
    assert store.get_meta("last_digest_day") == "2026-11-08"
    assert store.get_daily_summary(date(2026, 11, 7)).total == 2

    clock.advance(timedelta(days=1).total_seconds())
    run_scenario(daemon(), lambda: wait_for(lambda: len(dispatcher.subjects("Daily digest")) == 2))
    assert store.get_meta("last_digest_day") == "2026-11-09"


def test_no_digest_before_digest_hour(config, store, data_dir):
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, dispatcher=dispatcher)  # 07:00 < 08:00

    run_scenario(d, lambda: wait_for(heartbeat_written(data_dir)) and time.sleep(0.05))

    assert dispatcher.subjects("Daily digest") == []
    assert store.get_meta("last_digest_day") is None


def test_shutdown_drains_queue(config, store, data_dir):
    log: list = []
    stop = threading.Event()
    n = 20
    events = [ev(comm="evil" if i == n - 1 else "ssh") for i in range(n)]
    backend = FakeBackend(runs=[events])
    correlator = FakeCorrelator(on_process=lambda e: stop.set())
    dispatcher = FakeDispatcher(log)
    capture = FakeCapture(log)
    d = make_daemon(config, store, backend=backend, correlator=correlator,
                    dispatcher=dispatcher, capture=capture)

    d.run(stop)

    assert len(store.events_since(datetime(2000, 1, 1, tzinfo=UTC))) == n
    kinds = [k for k, _ in log]
    assert kinds.index("capture.stop") < kinds.index("dispatcher.stop")
    assert ("submit", dispatcher.subjects("FLAGGED")[0]) in log
    assert kinds[-1] == "dispatcher.stop"


def test_shutdown_flushes_pending_coalesced_batch(config, store, data_dir):
    dispatcher = FakeDispatcher()
    d = make_daemon(config, store, dispatcher=dispatcher,
                    backend=FakeBackend(runs=[[ev(comm="evil"), ev(comm="evil")]]))

    run_scenario(d, lambda: wait_for(lambda: stored_count(data_dir) == 2))

    assert len(dispatcher.subjects("FLAGGED")) == 2


def test_run_forever_stops_on_sigterm(config, store, data_dir):
    d = make_daemon(config, store)
    previous = signal.getsignal(signal.SIGTERM)

    def scenario():
        assert wait_for(heartbeat_written(data_dir))
        os.kill(os.getpid(), signal.SIGTERM)

    t = threading.Thread(target=scenario)
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
