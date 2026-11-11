import logging
import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import psutil
import pytest

from credwatch.correlate import PATH_ONLY_RULE, Correlator, snapshot_process
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


CANARY_ID = (7, 8)


def _stat_of(ident):
    if ident is None:
        raise FileNotFoundError("canary")
    return SimpleNamespace(st_ino=ident[0], st_dev=ident[1])


def make(allow, snaps=None, *, stat_fn=None, realpath_fn=lambda p: p, identity=CANARY_ID,
         canary_stat=CANARY_ID):
    calls = [] if snaps is None else snaps

    def snap(pid, now):
        calls.append((pid, now))
        return NetworkSnapshot(pid, now, True, (), (), None)

    c = Correlator(allow, self_pid=999, canary_path=CANARY, snapshot=snap, clock=lambda: NOW,
                   stat_fn=stat_fn or (lambda p: SimpleNamespace(st_ino=1, st_dev=2)),
                   realpath_fn=realpath_fn, canary_identity_fn=lambda p: identity,
                   canary_stat_fn=lambda p: _stat_of(canary_stat))
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
    pe = c.process(ev(path=CANARY, pid=999, inode=7, dev=8))
    assert pe.verdict == Verdict(True, "credwatch-canary")
    assert pe.snapshot is None and calls == [] and a.seen == []


def test_lexical_canary_path_with_foreign_inode_is_flagged():
    """/tmp/l/../../../<canary> can open ~/.ssh/id_rsa through a symlink (R51)."""
    a = StubAllowlist(Verdict(False, None))
    c, calls = make(a)
    pe = c.process(ev(path="/tmp/l/../../home/u/.credwatch-canary", pid=999, inode=1, dev=2))
    assert not pe.verdict.allowed and len(calls) == 1
    pe = c.process(ev(path=CANARY, pid=999, inode=1, dev=2))
    assert not pe.verdict.allowed


def test_canary_inode_match_exempt_any_pid():
    a = StubAllowlist(Verdict(False, None))
    c, calls = make(a)
    pe = c.process(ev(path="/anything/alias", pid=5, inode=7, dev=8))
    assert pe.verdict == Verdict(True, "credwatch-canary")
    assert pe.snapshot is None and calls == [] and a.seen == []


def test_status_probe_canary_read_not_flagged():
    """`credwatch status --probe` reads the canary from another process (R49/R51)."""
    a = StubAllowlist(Verdict(False, None))
    c, calls = make(a)
    pe = c.process(ev(path=CANARY, pid=31337, inode=7, dev=8))
    assert pe.verdict == Verdict(True, "credwatch-canary")
    assert pe.snapshot is None and calls == [] and a.seen == []


def test_macos_canary_requires_stat_identity():
    a = StubAllowlist(Verdict(False, None))
    ok = SimpleNamespace(st_ino=7, st_dev=8)
    c, calls = make(a, realpath_fn=lambda p: CANARY, stat_fn=lambda p: ok)
    assert c.process(ev(path="/x/alias", pid=5)).verdict == Verdict(True, "credwatch-canary")
    # canonical path equals canary but stat identity differs: normal checks
    other = SimpleNamespace(st_ino=1, st_dev=2)
    c, calls = make(a, realpath_fn=lambda p: CANARY, stat_fn=lambda p: other)
    assert not c.process(ev(path=CANARY, pid=999)).verdict.allowed
    # lexical canary path that resolves elsewhere: normal checks even for self_pid
    c, calls = make(a, realpath_fn=lambda p: "/home/u/.ssh/id_rsa", stat_fn=lambda p: ok)
    assert not c.process(ev(path=CANARY, pid=999)).verdict.allowed


def test_identity_pinned_not_refreshed_by_events():
    calls = []

    def identity(p):
        calls.append(p)
        return (7, 8)

    a = StubAllowlist(Verdict(False, None))
    c = Correlator(a, self_pid=999, canary_path=CANARY, snapshot=lambda p, n: None,
                   canary_identity_fn=identity, canary_stat_fn=lambda p: _stat_of((7, 8)),
                   realpath_fn=lambda p: p)
    assert not c.process(ev(path=CANARY, inode=9, dev=8)).verdict.allowed  # claims canary
    assert c.process(ev(path=CANARY, inode=7, dev=8)).verdict.allowed
    assert len(calls) == 1


def test_inode_reuse_after_canary_deleted_not_exempt():
    a = StubAllowlist(Verdict(False, None))
    c, calls = make(a, canary_stat=None)  # canary gone
    pe = c.process(ev(path="/tmp/reused", inode=7, dev=8))
    assert not pe.verdict.allowed and len(calls) == 1
    assert c.canary_problem == "canary file replaced or missing; re-run credwatch install"
    c, _ = make(a, canary_stat=(99, 8))  # replaced by another file
    assert not c.process(ev(path=CANARY, inode=7, dev=8)).verdict.allowed
    assert c.canary_problem is not None


def test_missing_canary_retry_rate_limited(caplog):
    now = [NOW]
    ids, reads = [None, None, (7, 8)], []

    def identity(p):
        reads.append(1)
        return ids[len(reads) - 1]

    a = StubAllowlist(Verdict(False, None))
    c = Correlator(a, self_pid=999, canary_path=CANARY, snapshot=lambda p, n: None,
                   clock=lambda: now[0], canary_identity_fn=identity,
                   canary_stat_fn=lambda p: _stat_of((7, 8)), realpath_fn=lambda p: p)
    canary_ev = ev(path=CANARY, inode=7, dev=8)
    for _ in range(5):
        assert not c.process(canary_ev).verdict.allowed
    assert len(reads) == 1  # startup read only; no per-event retries
    now[0] = NOW + timedelta(seconds=61)
    assert not c.process(canary_ev).verdict.allowed
    for _ in range(5):
        c.process(canary_ev)
    assert len(reads) == 2
    now[0] = NOW + timedelta(seconds=130)
    assert c.process(canary_ev).verdict.allowed and len(reads) == 3


def test_canary_fifo_or_wrong_owner_or_content_refused(tmp_path, caplog):
    from credwatch.correlate import read_canary_identity
    from credwatch.installer.common import CANARY_BODY
    f = tmp_path / "canary"
    f.write_text(CANARY_BODY)
    uid = f.stat().st_uid
    assert read_canary_identity(str(f), uid) is not None
    assert read_canary_identity(str(f), uid + 1) is None  # wrong owner
    g = tmp_path / "edited"
    g.write_text(CANARY_BODY + "x")
    assert read_canary_identity(str(g), uid) is None  # wrong content
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo)
    assert read_canary_identity(str(fifo), uid) is None  # must not hang


def test_canary_identity_refuses_hardlinked_or_symlinked_canary(tmp_path, caplog):
    from credwatch.correlate import read_canary_identity
    from credwatch.installer.common import CANARY_BODY
    f = tmp_path / "canary"
    f.write_text(CANARY_BODY)
    st = f.stat()
    uid = st.st_uid
    assert read_canary_identity(str(f), uid) == (st.st_ino, st.st_dev)
    os.link(f, tmp_path / "hard")
    with caplog.at_level(logging.WARNING):
        assert read_canary_identity(str(f), uid) is None
    assert "single link" in caplog.text
    (tmp_path / "hard").unlink()
    sym = tmp_path / "sym"
    sym.symlink_to(f)
    assert read_canary_identity(str(sym), uid) is None
    assert read_canary_identity(str(tmp_path / "missing"), uid) is None


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


# --- parent-directory fallback for short-lived files (R53) ------------------------------

GNUPG = "/home/u/.gnupg"
PARENT_ID = (50, 2)


def short_lived(path=f"{GNUPG}/pubring.kbx.lock", nametype="CREATE", parent=PARENT_ID):
    return FileAccessEvent(
        timestamp=NOW, path=path, pid=42, ppid=1, exe="/usr/bin/gpg", comm="gpg",
        success=True, backend="t", raw="raw", inode=60, dev=2, nametype=nametype,
        parent_inode=parent[0] if parent else None, parent_dev=parent[1] if parent else None,
    )


def stat_gone_file(dirs):
    """stat that knows only directories; every other path no longer exists."""
    def stat(p):
        if p in dirs:
            return SimpleNamespace(st_ino=dirs[p][0], st_dev=dirs[p][1])
        raise FileNotFoundError(p)
    return stat


@pytest.mark.parametrize("nametype", ["CREATE", "DELETE"])
def test_gone_file_verified_through_parent_dir(nametype):
    a = StubAllowlist(Verdict(True, "~/.gnupg/**"))
    c, calls = make(a, stat_fn=stat_gone_file({GNUPG: PARENT_ID}))
    pe = c.process(short_lived(nametype=nametype))
    assert pe.verdict == Verdict(True, "~/.gnupg/**") and calls == []
    assert a.seen[0].path == f"{GNUPG}/pubring.kbx.lock"
    assert pe.canonical_path == f"{GNUPG}/pubring.kbx.lock"


def test_parent_fallback_judges_the_resolved_parent_dir():
    """A symlinked parent is judged where it really points, not by its lexical name."""
    a = StubAllowlist()
    real = "/home/u/.ssh"
    c, _ = make(a, stat_fn=stat_gone_file({real: PARENT_ID}),
                realpath_fn=lambda p: real if p == GNUPG else p)
    pe = c.process(short_lived())
    assert a.seen[0].path == f"{real}/pubring.kbx.lock"
    assert pe.canonical_path == f"{real}/pubring.kbx.lock"


def test_gone_file_from_normal_open_stays_unverified(caplog):
    a = StubAllowlist()
    c, calls = make(a, stat_fn=stat_gone_file({GNUPG: PARENT_ID}))
    with caplog.at_level(logging.INFO):
        pe = c.process(short_lived(nametype="NORMAL"))
    assert pe.verdict == Verdict(False, None) and a.seen == [] and len(calls) == 1
    assert pe.canonical_path is None and "unverified path" in caplog.text


def test_gone_file_with_foreign_parent_inode_stays_unverified():
    a = StubAllowlist()
    c, calls = make(a, stat_fn=stat_gone_file({GNUPG: (99, 2)}))
    pe = c.process(short_lived())
    assert pe.verdict == Verdict(False, None) and a.seen == [] and len(calls) == 1


def test_gone_file_without_parent_identity_stays_unverified():
    a = StubAllowlist()
    c, _ = make(a, stat_fn=stat_gone_file({GNUPG: PARENT_ID}))
    pe = c.process(short_lived(parent=None))
    assert pe.verdict == Verdict(False, None) and a.seen == []


def test_gone_parent_dir_stays_unverified():
    a = StubAllowlist()
    c, _ = make(a, stat_fn=stat_gone_file({}))
    pe = c.process(short_lived())
    assert pe.verdict == Verdict(False, None) and a.seen == []


def test_existing_file_with_foreign_inode_never_uses_parent_fallback():
    """A replaced file (inode mismatch) is suspicious; only a vanished file may fall back."""
    a = StubAllowlist()
    dirs = {GNUPG: PARENT_ID, f"{GNUPG}/pubring.kbx.lock": (99, 2)}
    c, _ = make(a, stat_fn=stat_gone_file(dirs))
    pe = c.process(short_lived())
    assert pe.verdict == Verdict(False, None) and a.seen == []


@pytest.mark.parametrize("path", [f"{GNUPG}/..", f"{GNUPG}/.", "/"])
def test_parent_fallback_refuses_dot_and_root_names(path):
    a = StubAllowlist()
    c, _ = make(a, stat_fn=stat_gone_file({GNUPG: PARENT_ID, "/home/u": PARENT_ID,
                                           "/": PARENT_ID}))
    pe = c.process(short_lived(path=path))
    assert pe.verdict == Verdict(False, None) and a.seen == []


def test_parent_realpath_failure_stays_unverified():
    def realpath(p):
        if p == GNUPG:
            raise OSError("loop")
        return p

    a = StubAllowlist()
    c, _ = make(a, stat_fn=stat_gone_file({GNUPG: PARENT_ID}), realpath_fn=realpath)
    pe = c.process(short_lived())
    assert pe.verdict == Verdict(False, None) and a.seen == []


# --- O_PATH opens: recorded, never flagged (R55) -----------------------------------------

def path_only_event(**kw):
    return FileAccessEvent(
        timestamp=NOW, path="/home/u/.ssh", pid=42, ppid=1, exe="/usr/libexec/localsearch-3",
        comm="localsearch-3", success=True, backend="t", raw="raw", path_only=True, **kw,
    )


def test_o_path_open_is_allowed_without_allowlist_or_snapshot():
    a = StubAllowlist(Verdict(False, None))
    c, calls = make(a)
    pe = c.process(path_only_event(inode=1, dev=2))
    assert pe.verdict == Verdict(True, PATH_ONLY_RULE)
    assert pe.snapshot is None and calls == [] and a.seen == []
    assert pe.canonical_path == "/home/u/.ssh"


def test_o_path_open_of_unverifiable_path_is_still_not_flagged():
    """No read happened whatever the path really was; the record keeps it UNVERIFIED."""
    def gone(p):
        raise FileNotFoundError(p)

    c, calls = make(StubAllowlist(Verdict(False, None)), stat_fn=gone)
    pe = c.process(path_only_event(inode=1, dev=2))
    assert pe.verdict == Verdict(True, PATH_ONLY_RULE) and calls == []
    assert pe.canonical_path is None
