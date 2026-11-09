"""Daemon event flow, backend restart, canary probe and lifecycle."""
from __future__ import annotations

import json
import logging
import os
import signal
import sqlite3
import threading
from datetime import UTC, datetime

import pytest

from credwatch import daemon as daemon_mod
from credwatch.correlate import Correlator
from credwatch.daemon import build_correlator, run_forever
from _daemon_support import (
    BASE_TIME,
    STEP_TIMEOUT,
    FakeClock,
    FakeBackend,
    FakeCorrelator,
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
)


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


def test_backend_entry_cleared_after_restart(config, store):
    dispatcher = FakeDispatcher()

    def alerts():
        return [b for b in dispatcher.bodies("DEGRADED") if "RuntimeError: x" in b]

    first = FakeBackend(runs=[[RuntimeError("x")], []])
    with Harness(make_daemon(config, store, backend=first, dispatcher=dispatcher)) as h:
        h.settle()
    assert len(alerts()) == 1
    assert "backend" in json.loads(store.get_meta("health_alert_state"))

    # New process, same store, within 6 h: first event clears, the repeat crash re-alerts.
    second = FakeBackend(runs=[[ev(), RuntimeError("x")], []])
    with Harness(make_daemon(config, store, backend=second, dispatcher=dispatcher)) as h:
        h.settle()
    assert len(alerts()) == 2


def test_digest_day_meta_read_failure_seeds_once(config, store, monkeypatch, caplog):
    def broken_get_meta(key):
        if key == "last_digest_day":
            raise sqlite3.OperationalError("database is locked")
        return None

    monkeypatch.setattr(store, "get_meta", broken_get_meta)
    clock = FakeClock(datetime(2026, 11, 8, 9, 0, tzinfo=UTC).timestamp())
    dispatcher = FakeDispatcher()
    with caplog.at_level(logging.ERROR, logger="credwatch.daemon"), \
            Harness(make_daemon(config, store, dispatcher=dispatcher, clock=clock)) as h:
        h.step(5)

    assert len([r for r in caplog.records if "last_digest_day" in r.getMessage()]) == 1
    assert len(dispatcher.subjects("Daily digest")) == 1


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


def test_probe_ok_requires_canary_rule(config, store, data_dir):
    clock = FakeClock()
    backend = FakeBackend()
    canary = str(data_dir / "canary")
    with Harness(make_daemon(config, store, backend=backend, clock=clock)) as h:
        h.boot_canary(clock)
        # on the canary path but flagged (no canary verdict): must not pass the probe
        backend.feed(ev(path=canary, comm="evil"))
        h.until(lambda: store.events_since(datetime.fromtimestamp(0, UTC)))
        assert h.d._canary_deadline is not None
    assert store.get_meta("last_canary_ok") is None


def test_correlator_canary_problem_raises_health_alert(config, store):
    class Problem(FakeCorrelator):
        canary_problem = "canary file replaced or missing; re-run credwatch install"

    clock = FakeClock()
    dispatcher = FakeDispatcher()
    with Harness(make_daemon(config, store, dispatcher=dispatcher, clock=clock,
                             correlator=Problem())) as h:
        clock.advance(daemon_mod.HEALTH_INTERVAL_SECONDS)
        h.step()
    assert dispatcher.subjects("canary file replaced or missing")


def test_unreadable_canary_sends_health_alert(config, store, data_dir):
    (data_dir / "canary").unlink()
    clock = FakeClock()
    dispatcher = FakeDispatcher()
    with Harness(make_daemon(config, store, dispatcher=dispatcher, clock=clock)) as h:
        h.settle()
        clock.advance(daemon_mod.CANARY_STARTUP_DELAY_SECONDS)
        h.step()

    assert "cannot read" in dispatcher.subjects("canary probe failed")[0]


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
