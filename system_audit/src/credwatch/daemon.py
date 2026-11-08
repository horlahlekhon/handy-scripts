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
from datetime import UTC, date, datetime, timedelta, tzinfo
from datetime import time as dtime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

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
CANARY_STARTUP_DELAY_SECONDS = 5
HEALTH_INTERVAL_SECONDS = 300
HEALTH_DEDUP_SECONDS = 6 * 3600
BACKEND_BACKOFF_BASE_SECONDS = 5
BACKEND_BACKOFF_MAX_SECONDS = 300
READER_JOIN_SECONDS = 5.0
POLL_SECONDS = 1.0
CANARY_READ_BYTES = 4096
QUEUE_BACKLOG_WARN = 10000
QUEUE_BACKLOG_WARN_INTERVAL_SECONDS = 60
LOCALTIME_PATH = "/etc/localtime"

META_HEARTBEAT = "heartbeat"
META_CANARY_OK = "last_canary_ok"
META_DIGEST_DAY = "last_digest_day"
META_ALERT_ERROR = "last_alert_error"
META_HEALTH_ALERT = "last_health_alert"
META_ALERT_STATE = "health_alert_state"

# Health-alert sources: each is de-duplicated against its own last sent set.
SRC_HEALTH, SRC_CANARY, SRC_BACKEND = "health", "canary", "backend"
SRC_REPORTED, SRC_STORE, SRC_EXPORT = "reported", "store", "export"

_EVENT, _PROBLEM, _BACKEND_OK, _ALERT_ERROR = "event", "problem", "backend_ok", "alert_error"


def build_correlator(config: Config) -> Correlator:
    allowlist = Allowlist(
        config.allowlist, trusted_dirs=config.allowlist_trusted_dirs, os_name=config.os_name
    )
    return Correlator(
        allowlist, self_pid=os.getpid(), canary_path=str(config.data_dir / "canary")
    )


def system_zone() -> tzinfo | None:
    """The system's DST-aware zone ($TZ, else /etc/localtime); None if unavailable."""
    tz_env = os.environ.get("TZ", "").lstrip(":")
    if tz_env:
        try:
            return ZoneInfo(tz_env)
        except (ZoneInfoNotFoundError, ValueError):
            logger.warning("TZ=%r is not a known zone; trying %s", tz_env, LOCALTIME_PATH)
    try:
        with open(LOCALTIME_PATH, "rb") as fh:
            return ZoneInfo.from_file(fh, key="localtime")
    except (OSError, ValueError):
        logger.warning("cannot load %s; using per-date local offsets", LOCALTIME_PATH,
                       exc_info=True)
        return None


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
        self._zone = tz if tz is not None else system_zone()
        self._sleep = sleep  # None = stop.wait (interruptible)
        self._poll = poll_seconds
        self._queue: queue.Queue[tuple[str, object]] = queue.Queue()
        self._coalescer = AlertCoalescer(config.email.coalesce_seconds)
        self._canary = os.path.normpath(str(config.data_dir / "canary"))
        self._canary_deadline: float | None = None
        self._canary_not_before: float | None = None
        self._backend_entered = threading.Event()
        self._stop = threading.Event()
        self._reader: threading.Thread | None = None
        self._last_run: dict[str, float] = {}
        self._health_problems: tuple[str, ...] = ()
        self._alert_state: dict[str, tuple[tuple[str, ...], float]] | None = None
        self._failed_writes = 0
        self._last_backlog_warn: float | None = None
        self._digest_day: str | None = None
        self._backend_name = getattr(backend, "name", type(backend).__name__)

    # --- thread-safe entry points for other threads -------------------------

    def report_problem(self, message: str) -> None:
        """Queue a health problem (e.g. capture on_failure); sent by the main loop."""
        self._queue.put((_PROBLEM, (SRC_REPORTED, message)))

    def report_alert_error(self, message: str) -> None:
        """Dispatcher on_error hook; the main loop persists it as last_alert_error."""
        self._queue.put((_ALERT_ERROR, message))

    # --- lifecycle ------------------------------------------------------------

    def run(self, stop: threading.Event) -> None:
        self._start(stop)
        try:
            while not stop.is_set():
                self._step()
        finally:
            self._shutdown()

    def _start(self, stop: threading.Event) -> None:
        self._stop = stop
        self._dispatcher.start()
        try:
            self._capture.start()
            self._reader = threading.Thread(
                target=self._read_events, args=(stop, self._sleep or stop.wait),
                name="credwatch-backend", daemon=True,
            )
            self._reader.start()
        except BaseException:
            logger.critical("daemon startup failed", exc_info=True)
            stop.set()
            self._guarded("capture stop", self._capture.stop)
            self._guarded("dispatcher stop", self._dispatcher.stop)
            raise

    def _step(self) -> None:
        try:
            item = self._queue.get(timeout=self._poll)
        except queue.Empty:
            item = None
        if item is not None:
            self._handle(item)
        self._run_due_jobs()

    def _shutdown(self) -> None:
        self._stop.set()
        try:
            self._guarded("capture stop", self._capture.stop)
            if self._reader is not None:
                self._reader.join(READER_JOIN_SECONDS)
                if self._reader.is_alive():
                    logger.error("backend reader did not stop within %.0f s",
                                 READER_JOIN_SECONDS)
            while True:
                try:
                    item = self._queue.get_nowait()
                except queue.Empty:
                    break
                self._handle(item)
            if self._config.email.send_immediately:
                for batch in self._coalescer.drain_due(math.inf):
                    self._guarded("flagged alert", lambda b=batch: self._submit_flagged(b))
        finally:
            self._dispatcher.stop()

    # --- main-loop message handling -------------------------------------------------

    def _handle(self, item: tuple[str, object]) -> None:
        kind, payload = item
        if kind == _EVENT:
            self._guarded("event handling", lambda: self._on_event(payload))  # type: ignore[arg-type]
        elif kind == _PROBLEM:
            source, message = payload  # type: ignore[misc]
            self._guarded("health alert", lambda: self._raise_problems(source, (message,)))
        elif kind == _BACKEND_OK:
            self._guarded("health clear", lambda: self._clear_problems(SRC_BACKEND))
        elif kind == _ALERT_ERROR:
            self._save_meta(META_ALERT_ERROR, f"{self._iso(self._clock())} {payload}")

    def _on_event(self, pe: ProcessedEvent) -> None:
        now = self._clock()
        if self._record(pe) and self._canary_deadline is not None and self._is_canary(pe):
            self._canary_deadline = None
            logger.info("canary probe ok")
            self._clear_problems(SRC_CANARY)
            self._save_meta(META_CANARY_OK, self._iso(now))
        if not pe.verdict.allowed and self._config.email.send_immediately:
            batch = self._coalescer.add(pe, now)
            if batch:
                self._submit_flagged(batch)

    def _record(self, pe: ProcessedEvent) -> bool:
        try:
            self._store.record(pe)
        except Exception as exc:
            logger.exception("failed to store event for %s", pe.event.path)
            self._failed_writes += 1
            self._raise_problems(SRC_STORE, (f"event store write failed: {type(exc).__name__}",))
            return False
        self._clear_problems(SRC_STORE)
        return True

    def _is_canary(self, pe: ProcessedEvent) -> bool:
        paths = (pe.event.path, pe.canonical_path)
        return any(p is not None and os.path.normpath(p) == self._canary for p in paths)

    def _submit_flagged(self, batch: Sequence[ProcessedEvent]) -> None:
        subject, body = messages.format_flagged_alert(
            batch, self._hostname, data_dir=self._config.data_dir,
            rotate_seconds=self._config.capture.rotate_seconds, tz=self._zone,
        )
        self._dispatcher.submit(subject, body)

    # --- backend reader thread --------------------------------------------------

    def _read_events(self, stop: threading.Event, sleep: Callable[[float], object]) -> None:
        delay = BACKEND_BACKOFF_BASE_SECONDS
        # True at start: the first event of each process clears a `backend` problem
        # persisted by a previous process.
        failed = True
        while not stop.is_set():
            produced = False
            try:
                events = self._backend.events(stop)
                self._backend_entered.set()
                for ev in events:
                    pe = self._correlate(ev)
                    if not produced:
                        produced = True
                        if failed:
                            failed = False
                            self._queue.put((_BACKEND_OK, None))
                    self._queue.put((_EVENT, pe))
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
            failed = True
            if produced:
                delay = BACKEND_BACKOFF_BASE_SECONDS
            message = f"backend {self._backend_name} stopped ({reason}); restarting"
            self._queue.put((_PROBLEM, (SRC_BACKEND, message)))
            logger.warning("restarting backend %s in %d s", self._backend_name, delay)
            sleep(delay)
            delay = min(delay * 2, BACKEND_BACKOFF_MAX_SECONDS)

    def _correlate(self, ev: FileAccessEvent) -> ProcessedEvent:
        try:
            return self._correlator.process(ev)
        except Exception:
            logger.exception("correlator failed for %s; flagging event unjudged", ev.path)
            return ProcessedEvent(ev, Verdict(False, None), None)  # fail closed

    # --- scheduled jobs -----------------------------------------------------------

    def _run_due_jobs(self) -> None:
        now = self._clock()
        if self._config.email.send_immediately:
            for batch in self._coalescer.drain_due(now):
                self._guarded("flagged alert", lambda b=batch: self._submit_flagged(b))
        self._guarded("canary check", lambda: self._check_canary_deadline(now))
        self._guarded("backlog check", lambda: self._warn_on_backlog(now))
        if self._canary_not_before is None and self._backend_entered.is_set():
            self._canary_not_before = now + CANARY_STARTUP_DELAY_SECONDS
        jobs = [
            ("health", HEALTH_INTERVAL_SECONDS, self._check_health),
            ("export", self._config.audit_export.interval_minutes * 60, self._export_native_log),
            ("heartbeat", HEARTBEAT_INTERVAL_SECONDS, self._heartbeat),
        ]
        if self._canary_not_before is not None and now >= self._canary_not_before:
            jobs.insert(0, ("canary", CANARY_INTERVAL_SECONDS, self._start_canary_probe))
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

    def _save_meta(self, key: str, value: str) -> None:
        try:
            self._store.set_meta(key, value)
        except Exception:
            logger.exception("could not persist meta %s", key)

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
            self._raise_problems(
                SRC_CANARY,
                (f"canary probe failed: cannot read {self._canary} ({exc.strerror})",),
            )
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
        self._raise_problems(SRC_CANARY, (message,))

    def _check_health(self, now: float) -> None:
        problems: list[str] = []
        try:
            problems.extend(self._backend.health())
        except Exception as exc:
            logger.exception("backend health check failed")
            problems.append(f"backend health check failed: {type(exc).__name__}: {exc}")
        if self._reader is not None and not self._reader.is_alive() and not self._stop.is_set():
            problems.append("backend reader thread not running")
        if self._config.capture.enabled:
            try:
                status = self._capture.status()
                if not status.running:
                    suffix = f": {status.last_error}" if status.last_error else ""
                    problems.append(f"packet capture not running{suffix}")
            except Exception as exc:
                logger.exception("capture status check failed")
                problems.append(f"capture status check failed: {type(exc).__name__}: {exc}")
        self._health_problems = tuple(problems)
        if problems:
            logger.warning("health problems: %s", "; ".join(problems))
            self._raise_problems(SRC_HEALTH, problems)
        else:
            self._clear_problems(SRC_HEALTH)
            self._clear_problems(SRC_REPORTED)  # capture failures are re-checked above

    def _warn_on_backlog(self, now: float) -> None:
        depth = self._queue.qsize()
        if depth <= QUEUE_BACKLOG_WARN:
            return
        last = self._last_backlog_warn
        if last is not None and 0 <= now - last < QUEUE_BACKLOG_WARN_INTERVAL_SECONDS:
            return
        self._last_backlog_warn = now
        logger.warning("event queue backlog: %d items waiting", depth)

    # --- health alert de-duplication ------------------------------------------------

    def _raise_problems(self, source: str, problems: Sequence[str]) -> None:
        """Alert unless `source` last sent this exact set within 6 h; empty set clears it."""
        key = tuple(sorted(set(problems)))
        if not key:
            self._clear_problems(source)
            return
        now = self._clock()
        state = self._load_alert_state()
        previous = state.get(source)
        if previous is not None and previous[0] == key and 0 <= now - previous[1] < HEALTH_DEDUP_SECONDS:
            logger.info("health alert (%s) suppressed: same problems sent within 6 h", source)
            return
        subject, body = messages.format_health_alert(key, self._hostname)
        self._dispatcher.submit(subject, body + self._take_write_failure_note())
        self._alert_state = {**state, source: (key, now)}
        self._persist_alert_state()
        self._save_meta(META_HEALTH_ALERT, json.dumps({"problems": list(key), "sent_at": now}))

    def _clear_problems(self, source: str) -> None:
        state = self._load_alert_state()
        if source in state:
            logger.info("health problem source %s cleared", source)
            self._alert_state = {k: v for k, v in state.items() if k != source}
            self._persist_alert_state()

    def _take_write_failure_note(self) -> str:
        count, self._failed_writes = self._failed_writes, 0
        return f"\nFailed event-store writes since last report: {count}\n" if count else ""

    def _load_alert_state(self) -> dict[str, tuple[tuple[str, ...], float]]:
        if self._alert_state is None:
            self._alert_state = {}
            try:
                raw = self._store.get_meta(META_ALERT_STATE)
                if raw is not None:
                    self._alert_state = {
                        src: (tuple(v["problems"]), float(v["sent_at"]))
                        for src, v in json.loads(raw).items()
                    }
            except (ValueError, KeyError, TypeError, AttributeError):
                logger.warning("ignoring malformed %s meta", META_ALERT_STATE)
            except Exception:
                logger.exception("could not load %s meta", META_ALERT_STATE)
        return self._alert_state

    def _persist_alert_state(self) -> None:
        state = self._alert_state or {}
        payload = {src: {"problems": list(k), "sent_at": t} for src, (k, t) in state.items()}
        self._save_meta(META_ALERT_STATE, json.dumps(payload))

    # --- export and digest ------------------------------------------------------------

    def _export_native_log(self, now: float) -> None:
        export_dir = self._config.data_dir / "audit-exports"
        try:
            path = self._backend.export_native_log(export_dir)
            if path is not None:
                logger.info("exported native audit log to %s", path)
            self._clear_problems(SRC_EXPORT)
        except Exception as exc:
            logger.exception("native audit export failed")
            self._raise_problems(
                SRC_EXPORT, (f"native audit export failed: {type(exc).__name__}: {exc}",)
            )
        prune_old_files(
            export_dir, "*", timedelta(days=self._config.audit_export.retention_days),
            datetime.fromtimestamp(now, UTC),
        )

    def _maybe_send_digest(self, now: float) -> None:
        local_now = self._local(now)
        if local_now.hour < self._config.email.digest_hour:
            return
        today = local_now.date()
        if self._digest_day is None:
            try:
                self._digest_day = self._store.get_meta(META_DIGEST_DAY) or ""
            except Exception:
                logger.exception("could not read %s meta; assuming no digest sent today",
                                 META_DIGEST_DAY)
                self._digest_day = ""
        if self._digest_day == today.isoformat():
            return
        # Mark first: a broken store must not make every later tick resend (or retry) it.
        self._digest_day = today.isoformat()
        yesterday = today - timedelta(days=1)
        start, end = self._midnight(yesterday), self._midnight(today)
        summary = self._store.compute_daily_summary(yesterday, self._zone or start.tzinfo)
        self._guarded("summary save", lambda: self._store.save_daily_summary(summary))
        flagged = [r for r in self._store.flagged_events(since=start) if r.ts < end]
        health = self._health_problems
        if self._failed_writes:
            health += (f"event store write failures since last report: {self._failed_writes}",)
            self._failed_writes = 0
        subject, body = messages.format_digest(
            summary, flagged, health, self._hostname, tz=self._zone
        )
        self._dispatcher.submit(subject, body)
        self._save_meta(META_DIGEST_DAY, today.isoformat())
        logger.info("sent daily digest for %s", yesterday)

    # --- time helpers -----------------------------------------------------------------

    def _local(self, now: float) -> datetime:
        if self._zone is not None:
            return datetime.fromtimestamp(now, self._zone)
        return datetime.fromtimestamp(now).astimezone()

    def _midnight(self, day: date) -> datetime:
        if self._zone is not None:
            return datetime.combine(day, dtime.min, tzinfo=self._zone)
        return datetime.combine(day, dtime.min).astimezone()

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
