"""The credwatch daemon: backend reader thread, main store/alert loop, scheduled jobs.

Threads: the reader thread owns the Correlator (and its Allowlist); the thread
calling `Daemon.run` owns the Store. Other threads talk to the main loop only
through the internal queue (`report_problem`, `report_alert_error`).
"""
from __future__ import annotations

import json
import logging
import math
import os
import queue
import signal
import socket
import threading
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta, tzinfo
from datetime import time as dtime
from pathlib import Path

from credwatch import messages
from credwatch.alert import AlertCoalescer, AlertDispatcher
from credwatch.allowlist import Allowlist
from credwatch.backends.base import Backend
from credwatch.capture import CaptureSupervisor
from credwatch.config import Config
from credwatch.correlate import Correlator
from credwatch.models import FileAccessEvent, ProcessedEvent, Verdict
from credwatch.retention import prune_old_files
from credwatch.store import Store

logger = logging.getLogger(__name__)

HEARTBEAT_INTERVAL_SECONDS = 60
CANARY_INTERVAL_SECONDS = 3600
CANARY_TIMEOUT_SECONDS = 60
HEALTH_INTERVAL_SECONDS = 300
HEALTH_DEDUP_SECONDS = 6 * 3600
BACKEND_BACKOFF_BASE_SECONDS = 5
BACKEND_BACKOFF_MAX_SECONDS = 300
READER_JOIN_SECONDS = 5.0
POLL_SECONDS = 1.0
CANARY_READ_BYTES = 4096

META_HEARTBEAT = "heartbeat"
META_CANARY_OK = "last_canary_ok"
META_DIGEST_DAY = "last_digest_day"
META_ALERT_ERROR = "last_alert_error"
META_HEALTH_ALERT = "last_health_alert"
META_HEALTH_SENT = "health_alerts_sent"

_EVENT, _PROBLEM, _ALERT_ERROR = "event", "problem", "alert_error"
_CORRELATOR_FAILED_RULE = None  # fail closed: an event we could not judge is flagged


def build_correlator(config: Config) -> Correlator:
    allowlist = Allowlist(
        config.allowlist, trusted_dirs=config.allowlist_trusted_dirs, os_name=config.os_name
    )
    return Correlator(
        allowlist, self_pid=os.getpid(), canary_path=str(config.data_dir / "canary")
    )


class Daemon:
    def __init__(
        self,
        config: Config,
        backend: Backend,
        store: Store,
        correlator: Correlator,
        dispatcher: AlertDispatcher,
        capture: CaptureSupervisor,
        *,
        clock: Callable[[], float] = time.time,
        hostname: str | None = None,
        tz: tzinfo | None = None,
        sleep: Callable[[float], object] | None = None,
        poll_seconds: float = POLL_SECONDS,
    ) -> None:
        self._config = config
        self._backend = backend
        self._store = store
        self._correlator = correlator
        self._dispatcher = dispatcher
        self._capture = capture
        self._clock = clock
        self._hostname = hostname or socket.gethostname()
        self._tz = tz  # None = system local time
        self._sleep = sleep  # None = stop.wait (interruptible)
        self._poll = poll_seconds
        self._queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self._coalescer = AlertCoalescer(config.email.coalesce_seconds)
        self._canary = os.path.normpath(str(config.data_dir / "canary"))
        self._canary_deadline: float | None = None
        self._last_run: dict[str, float] = {}
        self._health_problems: tuple[str, ...] = ()
        self._health_sent: dict[tuple[str, ...], float] | None = None
        self._digest_day: str | None = None
        self._backend_name = getattr(backend, "name", type(backend).__name__)

    # --- thread-safe entry points for other threads -------------------------

    def report_problem(self, message: str) -> None:
        """Queue a health problem (e.g. capture on_failure); sent by the main loop."""
        self._queue.put((_PROBLEM, message))

    def report_alert_error(self, message: str) -> None:
        """Dispatcher on_error hook; the main loop persists it as last_alert_error."""
        self._queue.put((_ALERT_ERROR, message))

    # --- main loop ------------------------------------------------------------

    def run(self, stop: threading.Event) -> None:
        sleep = self._sleep or stop.wait
        self._dispatcher.start()
        self._capture.start()
        reader = threading.Thread(
            target=self._read_events, args=(stop, sleep), name="credwatch-backend", daemon=True
        )
        reader.start()
        try:
            while not stop.is_set():
                try:
                    item = self._queue.get(timeout=self._poll)
                except queue.Empty:
                    item = None
                if item is not None:
                    self._handle(item)
                self._run_due_jobs()
        finally:
            self._shutdown(stop, reader)

    def _shutdown(self, stop: threading.Event, reader: threading.Thread) -> None:
        stop.set()
        self._guarded("capture stop", self._capture.stop)
        reader.join(READER_JOIN_SECONDS)
        if reader.is_alive():
            logger.error("backend reader did not stop within %.0f s", READER_JOIN_SECONDS)
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            self._handle(item)
        if self._config.email.send_immediately:
            for batch in self._coalescer.drain_due(math.inf):
                self._submit_flagged(batch)
        self._dispatcher.stop()

    def _handle(self, item: tuple[str, object]) -> None:
        kind, payload = item
        if kind == _EVENT:
            self._guarded("event handling", lambda: self._on_event(payload))  # type: ignore[arg-type]
        elif kind == _PROBLEM:
            self._guarded("health alert", lambda: self._send_health((str(payload),)))
        elif kind == _ALERT_ERROR:
            value = f"{self._iso(self._clock())} {payload}"
            self._guarded("alert error meta", lambda: self._store.set_meta(META_ALERT_ERROR, value))

    def _on_event(self, pe: ProcessedEvent) -> None:
        now = self._clock()
        try:
            self._store.record(pe)
            stored = True
        except Exception:
            logger.exception("failed to store event for %s", pe.event.path)
            stored = False
        if stored and self._canary_deadline is not None and self._is_canary(pe):
            self._canary_deadline = None
            self._store.set_meta(META_CANARY_OK, self._iso(now))
            logger.info("canary probe ok")
        if not pe.verdict.allowed and self._config.email.send_immediately:
            batch = self._coalescer.add(pe, now)
            if batch:
                self._submit_flagged(batch)

    def _is_canary(self, pe: ProcessedEvent) -> bool:
        paths = (pe.event.path, pe.canonical_path)
        return any(p is not None and os.path.normpath(p) == self._canary for p in paths)

    def _submit_flagged(self, batch: Sequence[ProcessedEvent]) -> None:
        subject, body = messages.format_flagged_alert(
            batch, self._hostname, data_dir=self._config.data_dir,
            rotate_seconds=self._config.capture.rotate_seconds, tz=self._tz,
        )
        self._dispatcher.submit(subject, body)

    # --- backend reader thread --------------------------------------------------

    def _read_events(self, stop: threading.Event, sleep: Callable[[float], object]) -> None:
        delay = BACKEND_BACKOFF_BASE_SECONDS
        while not stop.is_set():
            produced = False
            try:
                for ev in self._backend.events(stop):
                    self._queue.put((_EVENT, self._correlate(ev)))
                    produced = True
                if stop.is_set():
                    return
                reason = "event stream ended unexpectedly"
                logger.critical("backend %s: %s", self._backend_name, reason)
            except Exception as exc:
                if stop.is_set():
                    logger.warning("backend %s raised during shutdown", self._backend_name,
                                   exc_info=True)
                    return
                reason = f"{type(exc).__name__}: {exc}"
                logger.critical("backend %s failed", self._backend_name, exc_info=True)
            if produced:
                delay = BACKEND_BACKOFF_BASE_SECONDS
            self.report_problem(f"backend {self._backend_name} stopped ({reason}); restarting")
            logger.warning("restarting backend %s in %d s", self._backend_name, delay)
            sleep(delay)
            delay = min(delay * 2, BACKEND_BACKOFF_MAX_SECONDS)

    def _correlate(self, ev: FileAccessEvent) -> ProcessedEvent:
        try:
            return self._correlator.process(ev)
        except Exception:
            logger.exception("correlator failed for %s; flagging event unjudged", ev.path)
            return ProcessedEvent(ev, Verdict(False, _CORRELATOR_FAILED_RULE), None)

    # --- scheduled jobs -----------------------------------------------------------

    def _run_due_jobs(self) -> None:
        now = self._clock()
        export_interval = self._config.audit_export.interval_minutes * 60
        if self._config.email.send_immediately:
            for batch in self._coalescer.drain_due(now):
                self._guarded("flagged alert", lambda b=batch: self._submit_flagged(b))
        self._guarded("canary check", lambda: self._check_canary_deadline(now))
        jobs = (
            ("canary", CANARY_INTERVAL_SECONDS, self._start_canary_probe),
            ("health", HEALTH_INTERVAL_SECONDS, self._check_health),
            ("export", export_interval, self._export_native_log),
            ("heartbeat", HEARTBEAT_INTERVAL_SECONDS, self._heartbeat),
        )
        for name, interval, job in jobs:
            last = self._last_run.get(name)
            # now < last: the wall clock jumped backwards; run rather than stall.
            if last is None or now - last >= interval or now < last:
                self._last_run[name] = now
                self._guarded(name, lambda j=job: j(now))
        self._guarded("digest", lambda: self._maybe_send_digest(now))

    @staticmethod
    def _guarded(what: str, fn: Callable[[], object]) -> None:
        try:
            fn()
        except Exception:
            logger.exception("%s failed", what)

    def _heartbeat(self, now: float) -> None:
        self._store.set_meta(META_HEARTBEAT, self._iso(now))

    def _start_canary_probe(self, now: float) -> None:
        if self._canary_deadline is not None:
            return
        try:
            fd = os.open(self._canary, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                os.read(fd, CANARY_READ_BYTES)
            finally:
                os.close(fd)
        except OSError as exc:
            logger.error("canary probe could not read %s: %s", self._canary, exc.strerror)
            self._send_health((f"canary probe failed: cannot read {self._canary} ({exc.strerror})",))
            return
        self._canary_deadline = now + CANARY_TIMEOUT_SECONDS

    def _check_canary_deadline(self, now: float) -> None:
        if self._canary_deadline is None or now < self._canary_deadline:
            return
        self._canary_deadline = None
        message = (
            f"canary probe failed: no audit event within {CANARY_TIMEOUT_SECONDS} s "
            f"for {self._canary}"
        )
        logger.error(message)
        self._send_health((message,))

    def _check_health(self, now: float) -> None:
        problems: list[str] = []
        try:
            problems.extend(self._backend.health())
        except Exception as exc:
            logger.exception("backend health check failed")
            problems.append(f"backend health check failed: {type(exc).__name__}: {exc}")
        if self._config.capture.enabled:
            status = self._capture.status()
            if not status.running:
                suffix = f": {status.last_error}" if status.last_error else ""
                problems.append(f"packet capture not running{suffix}")
        self._health_problems = tuple(problems)
        if problems:
            logger.warning("health problems: %s", "; ".join(problems))
        self._send_health(problems)

    def _send_health(self, problems: Sequence[str]) -> None:
        """Send unless this exact problem set was already sent within 6 h (persisted)."""
        key = tuple(sorted(set(problems)))
        if not key:
            return
        now = self._clock()
        recent = {
            k: t for k, t in self._load_health_sent().items()
            if 0 <= now - t < HEALTH_DEDUP_SECONDS
        }
        if key in recent:
            logger.info("health alert suppressed (same problems sent within 6 h)")
            return
        subject, body = messages.format_health_alert(key, self._hostname)
        self._dispatcher.submit(subject, body)
        self._health_sent = {**recent, key: now}
        sent = [{"problems": list(k), "sent_at": t} for k, t in self._health_sent.items()]
        self._store.set_meta(META_HEALTH_SENT, json.dumps(sent))
        self._store.set_meta(META_HEALTH_ALERT, json.dumps({"problems": list(key), "sent_at": now}))

    def _load_health_sent(self) -> dict[tuple[str, ...], float]:
        if self._health_sent is None:
            self._health_sent = {}
            raw = self._store.get_meta(META_HEALTH_SENT)
            if raw is not None:
                try:
                    self._health_sent = {
                        tuple(e["problems"]): float(e["sent_at"]) for e in json.loads(raw)
                    }
                except (ValueError, KeyError, TypeError):
                    logger.warning("ignoring malformed %s meta", META_HEALTH_SENT)
        return self._health_sent

    def _export_native_log(self, now: float) -> None:
        export_dir = self._config.data_dir / "audit-exports"
        try:
            path = self._backend.export_native_log(export_dir)
            if path is not None:
                logger.info("exported native audit log to %s", path)
        except Exception as exc:
            logger.exception("native audit export failed")
            self._send_health((f"native audit export failed: {type(exc).__name__}: {exc}",))
        prune_old_files(
            export_dir, "*", timedelta(days=self._config.audit_export.retention_days),
            datetime.fromtimestamp(now, UTC),
        )

    def _maybe_send_digest(self, now: float) -> None:
        local_now = self._local(now)
        if local_now.hour < self._config.email.digest_hour:
            return
        today = local_now.date().isoformat()
        if self._digest_day is None:
            self._digest_day = self._store.get_meta(META_DIGEST_DAY) or ""
        if self._digest_day == today:
            return
        yesterday = local_now.date() - timedelta(days=1)
        local_tz = local_now.tzinfo
        summary = self._store.compute_daily_summary(yesterday, local_tz)
        self._store.save_daily_summary(summary)
        flagged = self._store.flagged_events(
            since=datetime.combine(yesterday, dtime.min, tzinfo=local_tz)
        )
        subject, body = messages.format_digest(
            summary, flagged, self._health_problems, self._hostname, tz=self._tz
        )
        self._dispatcher.submit(subject, body)
        self._store.set_meta(META_DIGEST_DAY, today)
        self._digest_day = today
        logger.info("sent daily digest for %s", yesterday)

    # --- time helpers -----------------------------------------------------------------

    def _local(self, now: float) -> datetime:
        if self._tz is not None:
            return datetime.fromtimestamp(now, self._tz)
        return datetime.fromtimestamp(now).astimezone()

    @staticmethod
    def _iso(now: float) -> str:
        return datetime.fromtimestamp(now, UTC).isoformat()


def run_forever(daemon: Daemon) -> None:
    """Run on the main thread until SIGTERM/SIGINT; restores previous handlers after."""
    stop = threading.Event()

    def handle(signum, _frame):
        logger.info("received %s; shutting down", signal.Signals(signum).name)
        stop.set()

    previous = {sig: signal.signal(sig, handle) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        daemon.run(stop)
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
