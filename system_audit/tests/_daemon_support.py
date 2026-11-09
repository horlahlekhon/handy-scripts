"""Shared fakes, fixtures and the step-by-step Harness for the daemon tests."""
from __future__ import annotations

import sqlite3
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

from credwatch import daemon as daemon_mod
from credwatch.backends.base import Backend
from credwatch.capture import CaptureStatus
from credwatch.config import load_config
from credwatch.daemon import Daemon
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
        if allowed and ev.path.endswith("/canary"):
            return ProcessedEvent(ev, Verdict(True, "credwatch-canary"), None)
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
                 start_error=None, status_error=None, disk_problem=None, disk_error=None,
                 paused=False):
        self.log = log if log is not None else []
        self.running = running
        self.last_error = last_error
        self.start_error = start_error
        self.status_error = status_error
        self.disk_problem = disk_problem
        self.disk_error = disk_error
        self.paused = paused
        self.disk_checks = 0

    def check_disk_space(self):
        self.disk_checks += 1
        if self.disk_error:
            raise self.disk_error
        return self.disk_problem

    def start(self):
        if self.start_error:
            raise self.start_error

    def stop(self, timeout=10):
        self.log.append(("capture.stop", None))

    def status(self):
        if self.status_error:
            raise self.status_error
        return CaptureStatus(self.running, 0, self.last_error, None, self.paused)


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


def _health_cycle(h: Harness, clock: FakeClock) -> None:
    clock.advance(daemon_mod.HEALTH_INTERVAL_SECONDS)
    h.step()


LOW_DISK = "low disk space on /d/captures: 100 MiB free (1.0%); packet capture paused"
