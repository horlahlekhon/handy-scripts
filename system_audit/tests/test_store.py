import stat
from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from credwatch.models import (
    Connection,
    FileAccessEvent,
    NetworkSnapshot,
    ProcessedEvent,
    ProcessInfo,
    Verdict,
)
import pytest

from credwatch.store import DailySummary, Store, StoreError

UTC = timezone.utc


@pytest.fixture
def store(tmp_path):
    s = Store(tmp_path / "e.db")
    yield s
    s.close()


def make_pe(
    ts,
    path="/home/u/.ssh/id_rsa",
    exe="/usr/bin/cat",
    comm="cat",
    allowed=False,
    rule=None,
    snapshot=None,
):
    ev = FileAccessEvent(
        timestamp=ts, path=path, pid=100, ppid=1, exe=exe, comm=comm,
        success=True, backend="linux_audit", raw="raw line",
    )
    return ProcessedEvent(event=ev, verdict=Verdict(allowed, rule), snapshot=snapshot)


def test_record_and_query_since(tmp_path):
    store = Store(tmp_path / "sub" / "events.db")
    try:
        _check_since(store)
    finally:
        store.close()


def _check_since(store):
    t0 = datetime(2026, 1, 1, 12, 0, tzinfo=UTC)
    store.record(make_pe(t0))
    store.record(make_pe(t0 + timedelta(hours=1), path="/b"))
    rows = store.events_since(t0 + timedelta(minutes=30))
    assert [r.path for r in rows] == ["/b"]
    assert rows[0].ts.tzinfo is not None
    assert rows[0].ts == t0 + timedelta(hours=1)
    assert len(store.events_since(t0)) == 2


def test_db_file_mode_is_0600(tmp_path):
    Store(tmp_path / "d" / "events.db").close()
    mode = stat.S_IMODE((tmp_path / "d" / "events.db").stat().st_mode)
    assert mode == 0o600


def test_flagged_events_excludes_allowed(store):
    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    store.record(make_pe(t0, allowed=True, rule="ssh"))
    store.record(make_pe(t0 + timedelta(seconds=1), path="/bad", allowed=False))
    rows = store.flagged_events()
    assert [r.path for r in rows] == ["/bad"]
    assert rows[0].allowed is False
    assert store.flagged_events(since=t0 + timedelta(hours=1)) == []


def test_events_by_process_matches_comm_when_exe_missing(store):
    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    store.record(make_pe(t0, exe="/usr/bin/curl", comm="curl", path="/1"))
    store.record(make_pe(t0, exe=None, comm="curl", path="/2"))
    store.record(make_pe(t0, exe="/usr/bin/curl-x", comm="curl-x", path="/3"))
    store.record(make_pe(t0, exe="/opt/100%_curl", comm="zz", path="/4"))
    got = sorted(r.path for r in store.events_by_process("curl"))
    assert got == ["/1", "/2"]
    assert store.events_by_process("curl", since=t0 + timedelta(days=1)) == []
    assert store.events_by_process("100%_curl")[0].path == "/4"
    assert store.events_by_process("%") == []


def test_snapshot_roundtrip(store):
    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    snap = NetworkSnapshot(
        pid=100,
        taken_at=t0 + timedelta(seconds=1),
        alive=True,
        connections=(Connection("AF_INET", "SOCK_STREAM", "1.2.3.4:5", "6.7.8.9:443", "ESTABLISHED"),
                     Connection("AF_INET", "SOCK_DGRAM", "0.0.0.0:53", None, "NONE")),
        ancestry=(ProcessInfo(100, "/usr/bin/cat", ("cat", "x")), ProcessInfo(1, None, ())),
        error=None,
    )
    store.record(make_pe(t0, snapshot=snap))
    store.record(make_pe(t0, path="/nosnap"))
    rows = {r.path: r for r in store.events_since(t0)}
    assert rows["/home/u/.ssh/id_rsa"].snapshot == snap
    assert rows["/nosnap"].snapshot is None


def test_daily_summary_uses_local_day_bounds(store):
    tz = ZoneInfo("Africa/Lagos")  # UTC+1
    # local Jan 2 00:30 == UTC Jan 1 23:30 (in day); local Jan 3 00:30 is out
    store.record(make_pe(datetime(2026, 1, 1, 23, 30, tzinfo=UTC), path="/a"))
    store.record(make_pe(datetime(2026, 1, 2, 22, 59, tzinfo=UTC), path="/a", allowed=True, exe="/bin/ls", comm="ls"))
    store.record(make_pe(datetime(2026, 1, 2, 23, 30, tzinfo=UTC), path="/c"))
    store.record(make_pe(datetime(2026, 1, 1, 22, 59, tzinfo=UTC), path="/z"))
    s = store.compute_daily_summary(date(2026, 1, 2), tz)
    assert s.day == date(2026, 1, 2)
    assert s.total == 2
    assert s.flagged == 1
    assert s.by_process == (("cat", 1), ("ls", 1))
    assert s.by_path == (("/a", 2),)


def test_save_daily_summary_is_idempotent(store):
    s = DailySummary(date(2026, 1, 2), 3, 1, (("cat", 3),), (("/a", 3),))
    store.save_daily_summary(s)
    store.save_daily_summary(s)
    s2 = DailySummary(date(2026, 1, 2), 5, 2, (("cat", 5),), (("/a", 5),))
    store.save_daily_summary(s2)
    assert store.get_daily_summary(date(2026, 1, 2)) == s2
    assert store.get_daily_summary(date(2026, 1, 3)) is None


def test_meta_roundtrip(store):
    assert store.get_meta("k") is None
    store.set_meta("k", "v1")
    store.set_meta("k", "v2")
    assert store.get_meta("k") == "v2"


def test_reopen_existing_db_keeps_data(tmp_path):
    p = tmp_path / "e.db"
    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    s1 = Store(p)
    s1.record(make_pe(t0))
    s1.set_meta("a", "b")
    s1.close()
    s2 = Store(p)
    assert len(s2.events_since(t0)) == 1
    assert s2.get_meta("a") == "b"
    assert s2._conn.execute("PRAGMA user_version").fetchone()[0] == 1
    assert s2._conn.execute("PRAGMA journal_mode").fetchone()[0] == "wal"
    s2.close()


def test_symlinked_db_path_rejected(tmp_path):
    target = tmp_path / "target"
    target.write_bytes(b"untouched")
    target.chmod(0o644)
    link = tmp_path / "d" / "events.db"
    link.parent.mkdir()
    link.symlink_to(target)
    with pytest.raises(StoreError):
        Store(link)
    assert target.read_bytes() == b"untouched"
    assert stat.S_IMODE(target.stat().st_mode) == 0o644


def test_symlinked_parent_dir_rejected(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real)
    with pytest.raises(StoreError):
        Store(link / "events.db")
    assert list(real.iterdir()) == []


def test_symlinked_ancestor_dir_rejected(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    with pytest.raises(StoreError):
        Store(tmp_path / "link" / "sub" / "events.db")
    assert list(real.iterdir()) == []


def test_hardlinked_db_rejected(tmp_path):
    p = tmp_path / "e.db"
    Store(p).close()
    (tmp_path / "other").hardlink_to(p)
    with pytest.raises(StoreError):
        Store(p)


def test_existing_loose_db_tightened_to_0600(tmp_path):
    p = tmp_path / "e.db"
    Store(p).close()
    p.chmod(0o666)
    Store(p).close()
    assert stat.S_IMODE(p.stat().st_mode) == 0o600


def test_parent_dir_created_0700(tmp_path):
    d = tmp_path / "data"
    Store(d / "e.db").close()
    assert stat.S_IMODE(d.stat().st_mode) == 0o700


def test_loose_existing_parent_dir_rejected(tmp_path):
    d = tmp_path / "data"
    d.mkdir()
    d.chmod(0o777)
    with pytest.raises(StoreError):
        Store(d / "e.db")
    assert stat.S_IMODE(d.stat().st_mode) == 0o777


def test_snapshot_pid_roundtrips_independently_of_event_pid(tmp_path, store):
    t0 = datetime(2026, 1, 1, tzinfo=UTC)
    with_pid = NetworkSnapshot(555, t0, True, (), (), None)
    no_pid = NetworkSnapshot(None, t0, False, (), (), "gone")
    store.record(make_pe(t0, path="/a", snapshot=with_pid))
    store.record(make_pe(t0, path="/b", snapshot=no_pid))
    rows = {r.path: r for r in store.events_since(t0)}
    assert rows["/a"].pid == 100
    assert rows["/a"].snapshot == with_pid
    assert rows["/b"].snapshot == no_pid


def test_newer_schema_version_rejected(tmp_path):
    import sqlite3
    p = tmp_path / "e.db"
    c = sqlite3.connect(p)
    c.execute("PRAGMA user_version = 2")
    c.close()
    with pytest.raises(StoreError, match="v2 is newer"):
        Store(p)


def test_naive_datetime_rejected(store):
    with pytest.raises(ValueError):
        store.record(make_pe(datetime(2026, 1, 1)))
    with pytest.raises(ValueError):
        store.events_since(datetime(2026, 1, 1))


def test_inode_mismatch_after_connect_rejected(tmp_path, monkeypatch):
    import os
    p = tmp_path / "e.db"
    real_lstat = os.lstat

    def fake(path, *a, **k):
        st = real_lstat(path, *a, **k)
        if str(path) == str(p):
            vals = list(st)[:10]
            vals[1] += 1
            return os.stat_result(vals)
        return st

    monkeypatch.setattr(os, "lstat", fake)
    with pytest.raises(StoreError, match="changed"):
        Store(p)


def test_open_fd_inode_mismatch_rejected(tmp_path, monkeypatch):
    import os
    import credwatch.store as store_mod

    def fake_find(path):
        st = os.stat(path)
        vals = list(st)[:10]
        vals[1] += 1
        return os.stat_result(vals)

    monkeypatch.setattr(store_mod, "_find_open_fd_stat", fake_find)
    with pytest.raises(StoreError, match="different file"):
        Store(tmp_path / "e.db")


def test_open_fd_not_found_only_warns(tmp_path, monkeypatch, caplog):
    import credwatch.store as store_mod

    monkeypatch.setattr(store_mod, "_find_open_fd_stat", lambda path: None)
    with caplog.at_level("WARNING"):
        Store(tmp_path / "e.db").close()
    assert "could not find" in caplog.text


def test_hardlinked_db_not_chmodded(tmp_path):
    import os
    p = tmp_path / "e.db"
    Store(p).close()
    other = tmp_path / "other"
    os.link(p, other)
    p.chmod(0o640)
    with pytest.raises(StoreError):
        Store(p)
    assert stat.S_IMODE(p.stat().st_mode) == 0o640


def test_relative_db_path_rejected():
    from pathlib import Path
    with pytest.raises(StoreError):
        Store(Path("rel/e.db"))


def test_canonical_path_round_trips(store):
    ts = datetime(2026, 1, 1, tzinfo=UTC)
    pe = make_pe(ts)
    store.record(ProcessedEvent(pe.event, pe.verdict, None, canonical_path="/real/id_rsa"))
    store.record(pe)
    rows = store.events_since(ts)
    assert [r.canonical_path for r in rows] == ["/real/id_rsa", None]
