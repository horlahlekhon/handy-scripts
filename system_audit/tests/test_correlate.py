import logging
import os
from datetime import datetime, timezone
from types import SimpleNamespace

import psutil
import pytest

from credwatch.correlate import Correlator, snapshot_process
from credwatch.models import FileAccessEvent, NetworkSnapshot, Verdict

NOW = datetime(2026, 1, 1, tzinfo=timezone.utc)
CANARY = "/home/u/.credwatch-canary"


class _Exc:
    NoSuchProcess = psutil.NoSuchProcess
    AccessDenied = psutil.AccessDenied
    ZombieProcess = psutil.ZombieProcess


def _addr(ip, port):
    return SimpleNamespace(ip=ip, port=port)


def _conn(raddr=True):
    return SimpleNamespace(
        family=SimpleNamespace(name="AF_INET"), type=SimpleNamespace(name="SOCK_STREAM"),
        laddr=_addr("10.0.0.1", 5000), raddr=_addr("1.2.3.4", 443) if raddr else (),
        status="ESTABLISHED",
    )


class FakeProc:
    def __init__(self, pid, *, conns=None, parent=None, exe="/bin/x", cmdline=("x",),
                 conn_exc=None, parent_exc=None, exe_exc=None):
        self.pid, self._conns, self._parent = pid, conns or [], parent
        self._exe, self._cmd = exe, list(cmdline)
        self._conn_exc, self._parent_exc, self._exe_exc = conn_exc, parent_exc, exe_exc

    def net_connections(self, kind):
        assert kind == "inet"
        if self._conn_exc:
            raise self._conn_exc
        return self._conns

    def parent(self):
        if self._parent_exc:
            raise self._parent_exc
        return self._parent

    def exe(self):
        if self._exe_exc:
            raise self._exe_exc
        return self._exe

    def cmdline(self):
        return self._cmd


def fake_mod(procs=None, raises=None):
    procs = procs or {}

    def Process(pid):
        if raises:
            raise raises
        if pid not in procs:
            raise psutil.NoSuchProcess(pid)
        return procs[pid]

    return SimpleNamespace(Process=Process, **vars(_Exc))


def test_flagged_event_snapshots_connections():
    parent = FakeProc(1, exe="/sbin/init", cmdline=("init",))
    mod = fake_mod({10: FakeProc(10, conns=[_conn(), _conn(raddr=False)], parent=parent)})
    snap = snapshot_process(10, NOW, psutil_mod=mod)
    assert snap.alive and snap.error is None and snap.pid == 10
    assert snap.connections[0].raddr == "1.2.3.4:443"
    assert snap.connections[0].laddr == "10.0.0.1:5000"
    assert snap.connections[0].family == "AF_INET"
    assert snap.connections[1].raddr is None
    assert [p.pid for p in snap.ancestry] == [1]
    assert snap.ancestry[0].cmdline == ("init",)


def test_process_exited_returns_dead_snapshot():
    snap = snapshot_process(10, NOW, psutil_mod=fake_mod({}))
    assert not snap.alive and snap.error == "process exited before snapshot"


def test_exit_during_connections_returns_dead_snapshot():
    mod = fake_mod({10: FakeProc(10, conn_exc=psutil.NoSuchProcess(10))})
    snap = snapshot_process(10, NOW, psutil_mod=mod)
    assert not snap.alive and snap.error == "process exited before snapshot"


def test_zombie_and_access_denied_do_not_raise():
    z = snapshot_process(10, NOW, psutil_mod=fake_mod(raises=psutil.ZombieProcess(10)))
    assert not z.alive and "zombie" in z.error
    d = snapshot_process(10, NOW, psutil_mod=fake_mod(raises=psutil.AccessDenied(10)))
    assert d.error == "access denied: process"
    mod = fake_mod({10: FakeProc(10, conn_exc=psutil.AccessDenied(10),
                                 parent=FakeProc(1, exe_exc=psutil.AccessDenied(1)))})
    snap = snapshot_process(10, NOW, psutil_mod=mod)
    assert snap.alive and snap.connections == ()
    assert "access denied: connections" in snap.error
    assert "access denied: ancestry" in snap.error
    assert snap.ancestry[0].exe is None and snap.ancestry[0].pid == 1


def test_connections_zombie_recorded():
    mod = fake_mod({10: FakeProc(10, conn_exc=psutil.ZombieProcess(10))})
    snap = snapshot_process(10, NOW, psutil_mod=mod)
    assert "zombie" in snap.error and snap.alive


def test_ancestry_stops_at_vanished_parent():
    gp = FakeProc(1, parent_exc=psutil.NoSuchProcess(1))
    p = FakeProc(5, parent=gp)
    mod = fake_mod({10: FakeProc(10, parent=p)})
    snap = snapshot_process(10, NOW, psutil_mod=mod)
    assert [a.pid for a in snap.ancestry] == [5, 1]
    assert snap.alive


def test_ancestry_parent_lookup_denied_recorded():
    mod = fake_mod({10: FakeProc(10, parent_exc=psutil.AccessDenied(10))})
    snap = snapshot_process(10, NOW, psutil_mod=mod)
    assert snap.ancestry == () and "access denied: ancestry" in snap.error


def test_ancestry_capped_at_five():
    chain = None
    for pid in range(1, 10):
        chain = FakeProc(pid, parent=chain)
    snap = snapshot_process(10, NOW, psutil_mod=fake_mod({10: FakeProc(10, parent=chain)}))
    assert len(snap.ancestry) == 5


def test_none_pid_handled():
    snap = snapshot_process(None, NOW, psutil_mod=fake_mod({}))
    assert not snap.alive and snap.error == "pid unknown" and snap.pid is None


def test_snapshot_of_own_pid_is_alive():
    snap = snapshot_process(os.getpid(), NOW)
    assert snap.alive and snap.pid == os.getpid()


# ---- Correlator ----

class StubAllowlist:
    def __init__(self, verdict=Verdict(True, "r")):
        self.verdict, self.seen = verdict, []

    def check(self, event):
        self.seen.append(event)
        return self.verdict


def ev(path="/home/u/.ssh/id_rsa", pid=42, inode=None, dev=None):
    return FileAccessEvent(
        timestamp=NOW, path=path, pid=pid, ppid=1, exe="/bin/cat", comm="cat",
        success=True, backend="t", raw="raw", inode=inode, dev=dev,
    )


def make(allow, snaps=None, *, stat_fn=None, realpath_fn=lambda p: p):
    calls = [] if snaps is None else snaps

    def snap(pid, now):
        calls.append((pid, now))
        return NetworkSnapshot(pid, now, True, (), (), None)

    c = Correlator(allow, self_pid=999, canary_path=CANARY, snapshot=snap, clock=lambda: NOW,
                   stat_fn=stat_fn or (lambda p: SimpleNamespace(st_ino=1, st_dev=2)),
                   realpath_fn=realpath_fn)
    return c, calls


def test_allowed_event_has_no_snapshot():
    c, calls = make(StubAllowlist())
    pe = c.process(ev())
    assert pe.verdict.allowed and pe.snapshot is None and calls == []
    assert pe.canonical_path == "/home/u/.ssh/id_rsa"


def test_flagged_event_gets_snapshot():
    c, calls = make(StubAllowlist(Verdict(False, None)))
    pe = c.process(ev())
    assert pe.snapshot is not None and calls == [(42, NOW)]


def test_canary_self_read_is_exempt():
    a = StubAllowlist(Verdict(False, None))
    c, calls = make(a)
    pe = c.process(ev(path="/home/u/./x/../.credwatch-canary", pid=999))
    assert pe.verdict == Verdict(True, "credwatch-canary")
    assert pe.snapshot is None and calls == [] and a.seen == []


def test_canary_read_by_other_pid_is_canary_allowed():
    a = StubAllowlist(Verdict(False, None))
    c, calls = make(a)
    pe = c.process(ev(path=CANARY, pid=5))
    assert pe.verdict == Verdict(True, "credwatch-canary")
    assert pe.snapshot is None and calls == [] and a.seen == []


def test_status_probe_canary_read_not_flagged():
    """`credwatch status --probe` reads the canary from another process (R49)."""
    a = StubAllowlist(Verdict(False, None))
    c, calls = make(a, realpath_fn=lambda p: CANARY)
    pe = c.process(ev(path="/proc/self/cwd/alias", pid=31337, inode=1, dev=2))
    assert pe.verdict == Verdict(True, "credwatch-canary")
    assert pe.snapshot is None and calls == [] and a.seen == []
    assert pe.canonical_path == CANARY


def test_verified_inode_uses_canonical_path_for_allowlist():
    a = StubAllowlist()
    c, _ = make(a, realpath_fn=lambda p: "/etc/shadow")
    original = ev(path="/allowed/alias", inode=1, dev=2)
    pe = c.process(original)
    assert a.seen[0].path == "/etc/shadow"
    assert pe.event is original and original.path == "/allowed/alias"
    assert pe.canonical_path == "/etc/shadow"


def test_inode_mismatch_fails_closed(caplog):
    a = StubAllowlist()
    c, calls = make(a, stat_fn=lambda p: SimpleNamespace(st_ino=9, st_dev=2))
    with caplog.at_level(logging.INFO):
        pe = c.process(ev(inode=1, dev=2))
    assert pe.verdict == Verdict(False, None) and a.seen == []
    assert pe.canonical_path is None
    assert len(calls) == 1 and "unverified path" in caplog.text


def test_stat_failure_fails_closed(caplog):
    def boom(p):
        raise FileNotFoundError(p)

    c, calls = make(StubAllowlist(), stat_fn=boom)
    with caplog.at_level(logging.INFO):
        pe = c.process(ev(inode=1, dev=2))
    assert not pe.verdict.allowed and len(calls) == 1
    assert pe.canonical_path is None and "unverified path" in caplog.text


@pytest.mark.parametrize("inode,dev", [(1, None), (None, 2)])
def test_partial_inode_dev_fails_closed(inode, dev, caplog):
    a = StubAllowlist()
    c, calls = make(a)
    with caplog.at_level(logging.INFO):
        pe = c.process(ev(inode=inode, dev=dev))
    assert pe.verdict == Verdict(False, None) and a.seen == []
    assert pe.canonical_path is None and len(calls) == 1
    assert "unverified path" in caplog.text


def test_raising_snapshot_falls_back(caplog):
    def boom(pid, now):
        raise RuntimeError("x")

    c = Correlator(StubAllowlist(Verdict(False, None)), self_pid=999, canary_path=CANARY,
                   snapshot=boom, clock=lambda: NOW, realpath_fn=lambda p: p)
    pe = c.process(ev())
    assert pe.verdict == Verdict(False, None)
    assert pe.snapshot == NetworkSnapshot(42, NOW, False, (), (), "snapshot failed: RuntimeError")
    assert "snapshot failed" in caplog.text


def test_unexpected_error_in_ancestry_does_not_raise():
    mod = fake_mod({10: FakeProc(10, parent_exc=RuntimeError("boom"))})
    snap = snapshot_process(10, NOW, psutil_mod=mod)
    assert snap.alive and snap.ancestry == ()
    assert "unexpected error: ancestry" in snap.error


def test_unexpected_error_reading_ancestor_keeps_pid():
    mod = fake_mod({10: FakeProc(10, parent=FakeProc(1, exe_exc=RuntimeError("boom")))})
    snap = snapshot_process(10, NOW, psutil_mod=mod)
    assert [a.pid for a in snap.ancestry] == [1]
    assert "unexpected error: ancestry" in snap.error


def test_exe_denied_still_collects_cmdline():
    parent = FakeProc(1, exe_exc=psutil.AccessDenied(1), cmdline=("init", "--x"))
    snap = snapshot_process(10, NOW, psutil_mod=fake_mod({10: FakeProc(10, parent=parent)}))
    assert snap.ancestry[0].exe is None and snap.ancestry[0].cmdline == ("init", "--x")


def test_missing_inode_uses_lexical_path():
    a = StubAllowlist()
    c, _ = make(a, realpath_fn=lambda p: "/other")
    pe = c.process(ev(path="/lex", inode=None, dev=None))
    assert a.seen[0].path == "/lex" and pe.canonical_path == "/other"


def test_realpath_failure_with_no_inode_info():
    def bad(p):
        raise OSError("x")

    a = StubAllowlist()
    c, _ = make(a, realpath_fn=bad)
    pe = c.process(ev())
    assert pe.canonical_path is None and a.seen[0].path == "/home/u/.ssh/id_rsa"


def test_realpath_failure_with_inode_info_fails_closed():
    def bad(p):
        raise OSError("x")

    c, _ = make(StubAllowlist(), realpath_fn=bad)
    assert not c.process(ev(inode=1, dev=2)).verdict.allowed
