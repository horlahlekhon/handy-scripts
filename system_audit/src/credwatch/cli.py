"""credwatch command line: run, status, report, test-email, install."""
from __future__ import annotations

import argparse
import csv
import io
import json
import logging
import os
import re
import socket
import sys
import threading
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path

from credwatch import logging_setup
from credwatch.alert import (
    AlertDispatcher,
    CredentialsError,
    Mailer,
    SmtpCredentials,
    load_credentials,
)
from credwatch.backends import get_backend
from credwatch.backends.base import Backend, BackendError
from credwatch.capture import PCAP_GLOB, CaptureSupervisor, list_captures
from credwatch.config import Config, ConfigError, load_config
from credwatch.daemon import (
    META_ALERT_ERROR,
    META_ALERT_STATE,
    META_CANARY_OK,
    META_HEARTBEAT,
    Daemon,
    build_correlator,
    run_forever,
)
from credwatch.messages import escape_untrusted
from credwatch.paths import read_watch_list
from credwatch.platform_info import (
    CONFIG_PATH,
    SECRETS_PATH,
    UnknownUser,
    UnsupportedPlatform,
    WATCH_LIST_PATH,
    current_os,
    resolve_target_user,
)
from credwatch.proc import Runner, SubprocessRunner
from credwatch.store import EventRow, Store, StoreError

logger = logging.getLogger(__name__)

EXIT_OK = 0
EXIT_DEGRADED = 1
EXIT_USAGE = 2
EXIT_FAILURE = 1

HEARTBEAT_STALE_SECONDS = 180
PROBE_TIMEOUT_SECONDS = 15.0
PROBE_POLL_SECONDS = 0.5
CANARY_READ_BYTES = 4096
REPORT_FILE_MODE = 0o600
FORMULA_PREFIXES = ("=", "+", "-", "@")
DURATION_RE = re.compile(r"^(\d+)([mhdw])$")
DURATION_UNITS = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
CSV_COLUMNS = (
    "ts", "path", "canonical_path", "inode", "dev", "pid", "ppid", "exe", "comm",
    "success", "backend", "allowed", "matched_rule",
)

INSTALLER_MODULE = "credwatch.installer"

STARTUP_ERRORS = (
    ConfigError, UnknownUser, UnsupportedPlatform, StoreError, BackendError, OSError,
)


def parse_duration(s: str) -> timedelta:
    match = DURATION_RE.match(s.strip())
    if match is None or int(match.group(1)) == 0:
        raise argparse.ArgumentTypeError(f"invalid duration {s!r}; use e.g. 30m, 12h, 7d, 2w")
    return timedelta(**{DURATION_UNITS[match.group(2)]: int(match.group(1))})


def _is_root() -> bool:
    return os.geteuid() == 0


def _safe(value: object) -> str:
    return escape_untrusted(value, missing="")


def _now() -> datetime:
    return datetime.now(UTC)


# --- shared setup -------------------------------------------------------------------


def _load_config(args: argparse.Namespace) -> Config:
    os_name = current_os()
    target = resolve_target_user(args.user, os.environ)
    return load_config(Path(args.config), os_name, target)


def _secrets_file(args: argparse.Namespace) -> Path | None:
    if args.secrets_file:
        return Path(args.secrets_file)
    return SECRETS_PATH if SECRETS_PATH.exists() else None


def _guarded(handler: Callable[[argparse.Namespace], int]) -> Callable[[argparse.Namespace], int]:
    def wrapper(args: argparse.Namespace) -> int:
        try:
            return handler(args)
        except STARTUP_ERRORS as exc:
            logger.error("%s failed", args.command, exc_info=True)
            print(f"credwatch {args.command}: {type(exc).__name__}: {_safe(exc)}", file=sys.stderr)
            return EXIT_FAILURE

    return wrapper


def _require_root(command: str) -> bool:
    if _is_root():
        return True
    if command == "run":
        print("credwatch run must be run as root", file=sys.stderr)
    else:
        print(f"{command} requires root (sudo credwatch {command})", file=sys.stderr)
    return False


# --- run ----------------------------------------------------------------------------


class _DaemonRef:
    """Late binding: dispatcher/capture hooks are built before the Daemon exists."""

    def __init__(self) -> None:
        self._daemon: Daemon | None = None

    def set(self, daemon: Daemon) -> None:
        self._daemon = daemon

    def alert_error(self, message: str) -> None:
        if self._daemon is None:
            logger.error("alert error before daemon start: %s", message)
            return
        self._daemon.report_alert_error(message)

    def problem(self, message: str) -> None:
        if self._daemon is None:
            logger.error("problem before daemon start: %s", message)
            return
        self._daemon.report_problem(message)


def _check_mail_setup(config: Config, secrets: Path | None, store: Store) -> None:
    """Missing credentials must not stop monitoring: log, and surface via `status`."""
    try:
        Mailer(config.email, load_credentials(os.environ, secrets))
    except CredentialsError as exc:
        logger.critical("email alerts are disabled until fixed: %s", exc)
        store.set_meta(META_ALERT_ERROR, f"{_now().isoformat()} startup: {exc}")


@_guarded
def cmd_run(args: argparse.Namespace) -> int:
    if not _require_root("run"):
        return EXIT_USAGE
    config = _load_config(args)
    logging_setup.configure(
        config.data_dir / "logs", logging.DEBUG if args.verbose else logging.INFO
    )
    watch_paths = read_watch_list(WATCH_LIST_PATH)
    secrets = _secrets_file(args)
    store = Store(config.data_dir / "events.db")
    try:
        backend = get_backend(config, watch_paths, SubprocessRunner())
        _check_mail_setup(config, secrets, store)
        ref = _DaemonRef()
        dispatcher = AlertDispatcher(
            mailer_factory=lambda: Mailer(config.email, load_credentials(os.environ, secrets)),
            hostname=socket.gethostname(),
            on_error=lambda message: ref.alert_error(message),
        )
        capture = CaptureSupervisor(
            config.capture, config.data_dir / "captures",
            on_failure=lambda message: ref.problem(message),
        )
        daemon = Daemon(config, backend, store, build_correlator(config), dispatcher, capture)
        ref.set(daemon)
        try:
            run_forever(daemon)
        except Exception as exc:
            logger.critical("daemon crashed", exc_info=True)
            print(f"credwatch run: daemon crashed: {type(exc).__name__}: {_safe(exc)}",
                  file=sys.stderr)
            return EXIT_FAILURE
    finally:
        store.close()
    return EXIT_OK


# --- status -------------------------------------------------------------------------


def _service_state(config: Config, runner: Runner) -> str:
    argv = (
        ["systemctl", "is-active", "credwatch"]
        if config.os_name == "linux"
        else ["launchctl", "print", "system/com.credwatch.daemon"]
    )
    try:
        result = runner.run(argv, timeout=10)
    except (OSError, ValueError) as exc:
        return f"unknown ({type(exc).__name__})"
    except Exception as exc:  # e.g. subprocess.TimeoutExpired
        logger.warning("service probe failed", exc_info=True)
        return f"unknown ({type(exc).__name__})"
    if config.os_name == "linux":
        return (result.stdout or "").strip() or f"unknown (rc={result.returncode})"
    return "running" if result.returncode == 0 else f"not loaded (rc={result.returncode})"


def _parse_ts(text: str | None) -> datetime | None:
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.split(" ", 1)[0])
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _age(then: datetime | None, now: datetime) -> str:
    if then is None:
        return "never"
    return f"{max((now - then).total_seconds(), 0):.0f} s ago"


def _health_state_lines(raw: str | None) -> list[str]:
    if raw is None:
        return ["  none"]
    try:
        state = json.loads(raw)
        return [
            f"  {_safe(src)}: {_safe('; '.join(v['problems']))} (alerted at "
            f"{_safe(datetime.fromtimestamp(float(v['sent_at']), UTC).isoformat())})"
            for src, v in sorted(state.items())
        ] or ["  none"]
    except (ValueError, KeyError, TypeError, AttributeError, OverflowError, OSError):
        logger.warning("malformed %s meta", META_ALERT_STATE)
        return ["  (unreadable)"]


def _matches_canary(row: EventRow, canary: str) -> bool:
    return any(p is not None and os.path.normpath(p) == canary for p in (row.path, row.canonical_path))


def _probe(store: Store, canary: Path) -> bool:
    started = _now()
    try:
        fd = os.open(canary, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        try:
            os.read(fd, CANARY_READ_BYTES)
        finally:
            os.close(fd)
    except OSError as exc:
        print(f"probe: cannot read canary {canary}: {_safe(exc.strerror)}")
        return False
    target = os.path.normpath(str(canary))
    deadline = time.monotonic() + PROBE_TIMEOUT_SECONDS
    while True:
        if any(_matches_canary(r, target) for r in store.events_since(started)):
            print("probe: ok (canary access recorded)")
            return True
        if time.monotonic() >= deadline:
            print(f"probe: FAILED (no event within {PROBE_TIMEOUT_SECONDS:.0f} s)")
            return False
        time.sleep(PROBE_POLL_SECONDS)


def _backend_problems(config: Config, runner: Runner) -> tuple[str, ...]:
    try:
        backend: Backend = get_backend(config, read_watch_list(WATCH_LIST_PATH), runner)
        return tuple(backend.health())
    except Exception as exc:
        logger.warning("backend health unavailable", exc_info=True)
        return (f"backend health unavailable: {type(exc).__name__}: {exc}",)


def _count(pair: tuple[int, int]) -> str:
    return f"{pair[0]} total, {pair[1]} flagged"


def _db_missing(config: Config) -> bool:
    db = config.data_dir / "events.db"
    if db.exists():
        return False
    print(f"no event database at {_safe(db)} (has credwatch run?)", file=sys.stderr)
    return True


@_guarded
def cmd_status(args: argparse.Namespace) -> int:
    if not _require_root("status"):
        return EXIT_USAGE
    config = _load_config(args)
    if _db_missing(config):
        return EXIT_FAILURE
    runner = SubprocessRunner()
    now = _now()
    problems = list(_backend_problems(config, runner))
    store = Store(config.data_dir / "events.db")
    try:
        day_since, week_since = now - timedelta(days=1), now - timedelta(days=7)
        counts = {
            label: (store.count_events(since), store.count_events(since, flagged_only=True))
            for label, since in (("day", day_since), ("week", week_since))
        }
        latest = store.latest_event_ts()
        heartbeat = _parse_ts(store.get_meta(META_HEARTBEAT))
        alert_error = store.get_meta(META_ALERT_ERROR)
        canary_ok = store.get_meta(META_CANARY_OK)
        health_lines = _health_state_lines(store.get_meta(META_ALERT_STATE))
        probe_ok = _probe(store, config.data_dir / "canary") if args.probe else True
    finally:
        store.close()
    captures = list_captures(config.data_dir / "captures")
    newest = datetime.fromtimestamp(captures[-1].stat().st_mtime, UTC) if captures else None

    if heartbeat is None or (now - heartbeat).total_seconds() > HEARTBEAT_STALE_SECONDS:
        problems.append("daemon heartbeat missing or stale")
    if not probe_ok:
        problems.append("canary probe failed")
    print(f"service:          {_safe(_service_state(config, runner))}")
    print(f"backend health:   {_safe('; '.join(problems)) if problems else 'ok'}")
    print(f"heartbeat:        {_age(heartbeat, now)}")
    print(f"last event:       {_age(latest, now)}")
    print(f"events (24 h):    {_count(counts['day'])}")
    print(f"events (7 d):     {_count(counts['week'])}")
    print(f"captures:         {len(captures)} files ({PCAP_GLOB}), newest {_age(newest, now)}")
    print(f"last alert error: {_safe(alert_error) or 'none'}")
    print(f"last canary ok:   {_safe(canary_ok) or 'never'}")
    print("health alert state:")
    print("\n".join(health_lines))
    return EXIT_DEGRADED if problems else EXIT_OK


# --- report -------------------------------------------------------------------------


def _row_dict(r: EventRow) -> dict:
    snap = r.snapshot
    return {
        "id": r.id, "ts": r.ts.isoformat(), "path": r.path, "canonical_path": r.canonical_path,
        "inode": r.inode, "dev": r.dev, "pid": r.pid, "ppid": r.ppid, "exe": r.exe,
        "comm": r.comm, "success": r.success, "backend": r.backend, "allowed": r.allowed,
        "matched_rule": r.matched_rule, "raw": r.raw,
        "snapshot": None if snap is None else {
            "pid": snap.pid, "taken_at": snap.taken_at.isoformat(), "alive": snap.alive,
            "error": snap.error,
            "connections": [
                {"family": c.family, "type": c.type, "laddr": c.laddr, "raddr": c.raddr,
                 "status": c.status} for c in snap.connections
            ],
            "ancestry": [
                {"pid": p.pid, "exe": p.exe, "cmdline": list(p.cmdline)} for p in snap.ancestry
            ],
        },
    }


def _cell(value: object) -> str:
    """Escape control characters and defuse spreadsheet formulas."""
    text = _safe(value)
    if isinstance(value, str) and text.startswith(FORMULA_PREFIXES):
        return "'" + text
    return text


def _render_json(rows: Sequence[EventRow]) -> str:
    return json.dumps([_row_dict(r) for r in rows], indent=2) + "\n"


def _render_csv(rows: Sequence[EventRow]) -> str:
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for r in rows:
        values = _row_dict(r)
        writer.writerow([_cell(values[c]) for c in CSV_COLUMNS])
    return out.getvalue()


def _render_table(rows: Sequence[EventRow]) -> str:
    header = ("TIME (UTC)", "VERDICT", "PID", "PROCESS", "PATH")
    body = [
        (
            r.ts.astimezone(UTC).isoformat(timespec="seconds"),
            "ok" if r.allowed else "FLAGGED",
            _safe(r.pid),
            _safe(r.exe or r.comm),
            _safe(r.canonical_path or r.path),
        )
        for r in rows
    ]
    widths = [max(len(row[i]) for row in [header, *body]) for i in range(len(header))]
    lines = ["  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip() for row in [header, *body]]
    return "\n".join(lines) + "\n"


RENDERERS = {"table": _render_table, "json": _render_json, "csv": _render_csv}


def _write_private(path: Path, text: str) -> None:
    """Write 0600 without following a symlink at `path` (the report holds evidence)."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW | os.O_CLOEXEC
    fd = os.open(path, flags, REPORT_FILE_MODE)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        os.fchmod(fh.fileno(), REPORT_FILE_MODE)
        fh.write(text)


def _select_rows(store: Store, args: argparse.Namespace, since: datetime) -> list[EventRow]:
    rows = (
        store.events_by_process(args.process, since) if args.process else store.events_since(since)
    )
    return [r for r in rows if not r.allowed] if args.flagged else rows


@_guarded
def cmd_report(args: argparse.Namespace) -> int:
    if not _require_root("report"):
        return EXIT_USAGE
    config = _load_config(args)
    if _db_missing(config):
        return EXIT_FAILURE
    store = Store(config.data_dir / "events.db")
    try:
        rows = _select_rows(store, args, _now() - args.last)
    finally:
        store.close()
    text = RENDERERS[args.format](rows)
    if args.output:
        _write_private(Path(args.output), text)
        print(f"wrote {len(rows)} events to {_safe(args.output)}")
    else:
        sys.stdout.write(text)
    return EXIT_OK


# --- test-email ---------------------------------------------------------------------


def _redact(text: str, creds: SmtpCredentials | None) -> str:
    if creds is not None:
        for secret in (creds.password, creds.user):
            if secret:
                text = text.replace(secret, "***")
    return text


def cmd_test_email(args: argparse.Namespace) -> int:
    creds: SmtpCredentials | None = None
    try:
        config = _load_config(args)
        creds = load_credentials(os.environ, _secrets_file(args))
        Mailer(config.email, creds).send(
            f"[credwatch][{socket.gethostname()}] test email", "credwatch test email.\n"
        )
    except Exception as exc:
        logger.error("test-email failed: %s", type(exc).__name__, exc_info=False)
        print(
            f"test-email failed: {type(exc).__name__}: {_safe(_redact(str(exc), creds))}",
            file=sys.stderr,
        )
        return EXIT_FAILURE
    print("test email sent")
    return EXIT_OK


# --- install ------------------------------------------------------------------------


def cmd_install(args: argparse.Namespace) -> int:
    try:
        from credwatch.installer import run_install
    except ModuleNotFoundError as exc:
        if exc.name != INSTALLER_MODULE:
            logger.exception("installer import failed")
            raise
        print("installer not available yet", file=sys.stderr)
        return EXIT_USAGE
    except ImportError:
        logger.exception("installer import failed")
        raise
    return int(run_install(user=args.install_user or args.user, start=not args.no_start) or 0)


# --- parser -------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="credwatch", description="Credential file access monitor")
    parser.add_argument("--config", default=str(CONFIG_PATH), help="config file path")
    parser.add_argument("--user", help="user whose credentials are watched")
    parser.add_argument("--secrets-file", help="env-style file holding CREDWATCH_SMTP_* values")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("run", help="run the monitoring daemon (root)").set_defaults(func=cmd_run)

    status = sub.add_parser("status", help="show daemon health (root)")
    status.add_argument("--probe", action="store_true", help="read the canary and wait for its event")
    status.set_defaults(func=cmd_status)

    report = sub.add_parser("report", help="list recorded events (root)")
    report.add_argument("--last", type=parse_duration, required=True, metavar="DURATION")
    report.add_argument("--flagged", action="store_true")
    report.add_argument("--process", metavar="NAME")
    report.add_argument("--format", choices=sorted(RENDERERS), default="table")
    report.add_argument("--output", metavar="PATH")
    report.set_defaults(func=cmd_report)

    sub.add_parser("test-email", help="send a test email").set_defaults(func=cmd_test_email)

    install = sub.add_parser("install", help="install the service (root)")
    install.add_argument("--user", dest="install_user", metavar="NAME")
    install.add_argument("--no-start", action="store_true")
    install.set_defaults(func=cmd_install)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command != "run":
        logging.basicConfig(
            level=logging.DEBUG if args.verbose else logging.WARNING, stream=sys.stderr
        )
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
