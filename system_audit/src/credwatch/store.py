"""SQLite event store (single-threaded use, WAL, mode 0600)."""
from __future__ import annotations

import json
import logging
import os
import stat
import sqlite3
from collections import Counter
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta, timezone, tzinfo
from pathlib import Path

from credwatch.safe_fs import UnsafePathError, open_dir_chain
from credwatch.models import Connection, NetworkSnapshot, ProcessedEvent, ProcessInfo

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1
DB_FILE_MODE = 0o600
DB_DIR_MODE = 0o700

_SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT NOT NULL,
    path TEXT NOT NULL,
    pid INTEGER, ppid INTEGER, exe TEXT, comm TEXT,
    success INTEGER,
    backend TEXT NOT NULL,
    allowed INTEGER NOT NULL,
    matched_rule TEXT,
    raw TEXT NOT NULL,
    canonical_path TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_allowed ON events(allowed);
CREATE INDEX IF NOT EXISTS idx_events_exe ON events(exe);
CREATE TABLE IF NOT EXISTS net_snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES events(id),
    pid INTEGER,
    taken_at TEXT NOT NULL,
    alive INTEGER NOT NULL,
    error TEXT,
    connections_json TEXT NOT NULL,
    ancestry_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_event ON net_snapshots(event_id);
CREATE TABLE IF NOT EXISTS daily_summaries (
    day TEXT PRIMARY KEY,
    total INTEGER NOT NULL,
    flagged INTEGER NOT NULL,
    by_process_json TEXT NOT NULL,
    by_path_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
"""

_EVENT_SELECT = """
SELECT e.id, e.ts, e.path, e.pid, e.ppid, e.exe, e.comm, e.success, e.backend,
       e.allowed, e.matched_rule, e.raw,
       s.taken_at, s.alive, s.error, s.connections_json, s.ancestry_json, s.pid, e.canonical_path
FROM events e LEFT JOIN net_snapshots s ON s.event_id = e.id
"""


class StoreError(Exception):
    """Raised when the database location or schema is unsafe or unsupported."""


@dataclass(frozen=True)
class EventRow:
    id: int
    ts: datetime
    path: str
    pid: int | None
    ppid: int | None
    exe: str | None
    comm: str | None
    success: bool | None
    backend: str
    allowed: bool
    matched_rule: str | None
    raw: str
    snapshot: NetworkSnapshot | None
    canonical_path: str | None = None


@dataclass(frozen=True)
class DailySummary:
    day: date
    total: int
    flagged: int
    by_process: tuple[tuple[str, int], ...]
    by_path: tuple[tuple[str, int], ...]


def _to_text(dt: datetime) -> str:
    """Fixed-width UTC ISO string so lexicographic order equals time order."""
    if dt.tzinfo is None:
        raise ValueError("naive datetime not allowed")
    return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")


def _from_text(s: str) -> datetime:
    return datetime.fromisoformat(s)


def _opt_bool(v: int | None) -> bool | None:
    return None if v is None else bool(v)


def _basename(exe: str | None) -> str | None:
    return exe.rsplit("/", 1)[-1] if exe else None


def _escape_like(s: str) -> str:
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _conn_to_dict(c: Connection) -> dict:
    return {"family": c.family, "type": c.type, "laddr": c.laddr,
            "raddr": c.raddr, "status": c.status}


def _proc_to_dict(p: ProcessInfo) -> dict:
    return {"pid": p.pid, "exe": p.exe, "cmdline": list(p.cmdline)}


def _check_file(st: os.stat_result, path: Path) -> None:
    if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_nlink != 1:
        raise StoreError(
            f"{path} must be a regular, euid-owned file with a single link"
        )


def _open_db_file(dir_fd: int, db_path: Path) -> os.stat_result:
    """Create/open the db file relative to dir_fd without following symlinks."""
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
    try:
        fd = os.open(db_path.name, flags, DB_FILE_MODE, dir_fd=dir_fd)
    except OSError as exc:
        raise StoreError(f"cannot safely open {db_path}: {exc.strerror}") from exc
    try:
        st = os.fstat(fd)
        _check_file(st, db_path)  # validate before touching permissions
        os.fchmod(fd, DB_FILE_MODE)
        return os.fstat(fd)
    except OSError as exc:
        raise StoreError(f"cannot secure {db_path}: {exc.strerror}") from exc
    finally:
        os.close(fd)


def _verify_same_file(path: Path, st: os.stat_result) -> None:
    """Path must still be the (non-symlink) file we opened by fd."""
    now = os.lstat(path)
    if stat.S_ISLNK(now.st_mode) or (now.st_dev, now.st_ino) != (st.st_dev, st.st_ino):
        raise StoreError(f"{path} changed while opening")


def _verify_sidecars(db_path: Path) -> None:
    for suffix in ("-wal", "-shm"):
        side = db_path.with_name(db_path.name + suffix)
        try:
            now = os.lstat(side)
        except FileNotFoundError:
            continue
        _check_file(now, side)


def _find_open_fd_stat(path: Path) -> os.stat_result | None:
    """fstat of an fd of this process whose /proc link is exactly path (Linux)."""
    fd_dir = Path("/proc/self/fd")
    if not fd_dir.is_dir():
        return None
    target = str(path)
    for name in os.listdir(fd_dir):
        try:
            if os.readlink(fd_dir / name) == target:
                return os.fstat(int(name))
        except OSError:
            continue
    return None


def _row_to_event(r: tuple) -> EventRow:
    snapshot = None
    if r[12] is not None:
        snapshot = NetworkSnapshot(
            pid=r[17],
            taken_at=_from_text(r[12]),
            alive=bool(r[13]),
            connections=tuple(Connection(**d) for d in json.loads(r[15])),
            ancestry=tuple(
                ProcessInfo(d["pid"], d["exe"], tuple(d["cmdline"]))
                for d in json.loads(r[16])
            ),
            error=r[14],
        )
    return EventRow(
        id=r[0], ts=_from_text(r[1]), path=r[2], pid=r[3], ppid=r[4], exe=r[5],
        comm=r[6], success=_opt_bool(r[7]), backend=r[8], allowed=bool(r[9]),
        matched_rule=r[10], raw=r[11], snapshot=snapshot, canonical_path=r[18],
    )


class Store:
    def __init__(self, db_path: Path) -> None:
        db_path = Path(db_path)
        try:
            self._dir_fd = open_dir_chain(db_path.parent, create_mode=DB_DIR_MODE)
        except (UnsafePathError, ValueError, OSError) as exc:
            raise StoreError(str(exc)) from exc
        self._conn: sqlite3.Connection | None = None
        try:
            st = _open_db_file(self._dir_fd, db_path)
            self._conn = sqlite3.connect(db_path)
            _verify_same_file(db_path, st)
            self._init_schema()
            _verify_sidecars(db_path)
            self._verify_open_fd(db_path, st)
        except BaseException:
            self.close()
            raise

    def _verify_open_fd(self, db_path: Path, st: os.stat_result) -> None:
        found = _find_open_fd_stat(db_path)
        if found is None:
            logger.warning("could not find sqlite's open fd for %s to verify", db_path)
        elif (found.st_dev, found.st_ino) != (st.st_dev, st.st_ino):
            raise StoreError(f"sqlite opened a different file than verified: {db_path}")

    def _init_schema(self) -> None:
        version = self._conn.execute("PRAGMA user_version").fetchone()[0]
        if version > SCHEMA_VERSION:
            raise StoreError(
                f"database schema v{version} is newer than this credwatch supports"
            )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(_SCHEMA)
        if version == 0:
            self._conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        self._conn.commit()

    def close(self) -> None:
        try:
            if self._conn is not None:
                self._conn.close()
        finally:
            if self._dir_fd >= 0:
                os.close(self._dir_fd)
                self._dir_fd = -1

    def record(self, pe: ProcessedEvent) -> int:
        ev, snap = pe.event, pe.snapshot
        with self._conn:  # one transaction
            cur = self._conn.execute(
                "INSERT INTO events (ts, path, pid, ppid, exe, comm, success, backend,"
                " allowed, matched_rule, raw, canonical_path) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (_to_text(ev.timestamp), ev.path, ev.pid, ev.ppid, ev.exe, ev.comm,
                 None if ev.success is None else int(ev.success), ev.backend,
                 int(pe.verdict.allowed), pe.verdict.matched_rule, ev.raw, pe.canonical_path),
            )
            event_id = int(cur.lastrowid)
            if snap is not None:
                self._conn.execute(
                    "INSERT INTO net_snapshots (event_id, pid, taken_at, alive, error,"
                    " connections_json, ancestry_json) VALUES (?,?,?,?,?,?,?)",
                    (event_id, snap.pid, _to_text(snap.taken_at), int(snap.alive), snap.error,
                     json.dumps([_conn_to_dict(c) for c in snap.connections]),
                     json.dumps([_proc_to_dict(p) for p in snap.ancestry])),
                )
        return event_id

    def _query(self, where: str, params: tuple) -> list[EventRow]:
        sql = f"{_EVENT_SELECT} {where} ORDER BY e.ts, e.id"
        return [_row_to_event(r) for r in self._conn.execute(sql, params)]

    def events_since(self, since: datetime) -> list[EventRow]:
        return self._query("WHERE e.ts >= ?", (_to_text(since),))

    def events_by_process(self, name: str, since: datetime | None = None) -> list[EventRow]:
        where = "WHERE (e.exe = :n OR e.exe LIKE :suffix ESCAPE '\\' OR e.comm = :n)"
        params: dict = {"n": name, "suffix": "%/" + _escape_like(name)}
        if since is not None:
            where += " AND e.ts >= :since"
            params["since"] = _to_text(since)
        sql = f"{_EVENT_SELECT} {where} ORDER BY e.ts, e.id"
        return [_row_to_event(r) for r in self._conn.execute(sql, params)]

    def flagged_events(self, since: datetime | None = None) -> list[EventRow]:
        if since is None:
            return self._query("WHERE e.allowed = 0", ())
        return self._query("WHERE e.allowed = 0 AND e.ts >= ?", (_to_text(since),))

    def compute_daily_summary(self, day: date, tz: tzinfo) -> DailySummary:
        start = datetime.combine(day, time.min, tzinfo=tz)
        end = datetime.combine(day + timedelta(days=1), time.min, tzinfo=tz)
        rows = self._conn.execute(
            "SELECT path, exe, comm, allowed FROM events WHERE ts >= ? AND ts < ?",
            (_to_text(start), _to_text(end)),
        ).fetchall()
        procs: Counter[str] = Counter()
        paths: Counter[str] = Counter()
        flagged = 0
        for path, exe, comm, allowed in rows:
            procs[_basename(exe) or comm or "unknown"] += 1
            paths[path] += 1
            flagged += 0 if allowed else 1
        return DailySummary(
            day=day, total=len(rows), flagged=flagged,
            by_process=_ranked(procs), by_path=_ranked(paths),
        )

    def save_daily_summary(self, s: DailySummary) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO daily_summaries (day, total, flagged, by_process_json,"
                " by_path_json) VALUES (?,?,?,?,?) ON CONFLICT(day) DO UPDATE SET"
                " total=excluded.total, flagged=excluded.flagged,"
                " by_process_json=excluded.by_process_json,"
                " by_path_json=excluded.by_path_json",
                (s.day.isoformat(), s.total, s.flagged,
                 json.dumps([list(p) for p in s.by_process]),
                 json.dumps([list(p) for p in s.by_path])),
            )

    def get_daily_summary(self, day: date) -> DailySummary | None:
        r = self._conn.execute(
            "SELECT total, flagged, by_process_json, by_path_json"
            " FROM daily_summaries WHERE day = ?", (day.isoformat(),),
        ).fetchone()
        if r is None:
            return None
        return DailySummary(
            day=day, total=r[0], flagged=r[1],
            by_process=tuple((n, c) for n, c in json.loads(r[2])),
            by_path=tuple((n, c) for n, c in json.loads(r[3])),
        )

    def set_meta(self, key: str, value: str) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO meta (key, value) VALUES (?, ?)"
                " ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

    def get_meta(self, key: str) -> str | None:
        r = self._conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return None if r is None else r[0]


def _ranked(c: Counter[str]) -> tuple[tuple[str, int], ...]:
    return tuple(sorted(c.items(), key=lambda kv: (-kv[1], kv[0])))
