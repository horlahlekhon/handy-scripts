"""Opt-in Linux end-to-end tests against the real kernel audit subsystem.

Run (as root, from a venv that has credwatch and pytest installed):

    CREDWATCH_E2E=1 python -m pytest tests/test_e2e_linux.py -v -m e2e

Isolation: a temp data dir and config, a dedicated rules file
(/etc/audit/rules.d/credwatch-e2e.rules) watching only temp files, and a daemon started
with the hidden `run --watch-list` flag. /etc/credwatch and /var/lib/credwatch are never
touched. Audit rules are kernel-global, so teardown always removes the rules file and
reloads them.

Side effects: if auditd is not active it is started AND enabled at boot
(`systemctl enable --now auditd`, via ensure_auditd); this persists after the test.
The test skips when real credwatch audit rules are already loaded, because the audit key
must stay `credwatch` and rule counting would collide.
"""
from __future__ import annotations

import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import warnings
from collections.abc import Iterator
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path

import pytest
import yaml

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(os.environ.get("CREDWATCH_E2E") != "1", reason="set CREDWATCH_E2E=1 to run"),
    pytest.mark.skipif(
        not hasattr(os, "geteuid") or os.geteuid() != 0, reason="end-to-end tests need root"
    ),
    pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux only"),
]

from credwatch.backends.linux_audit import (  # noqa: E402
    DEFAULT_RULES_FILE,
    count_loaded_rules,
    ensure_auditd,
    install_rules,
)
from credwatch.correlate import PATH_ONLY_RULE  # noqa: E402
from credwatch.installer.common import CANARY_BODY  # noqa: E402
from credwatch.proc import SubprocessRunner  # noqa: E402
from credwatch.store import Store  # noqa: E402

E2E_RULES_FILE = Path("/etc/audit/rules.d/credwatch-e2e.rules")
CURL = "/usr/bin/curl"
EVENT_TIMEOUT_SECONDS = 15.0
CANARY_TIMEOUT_SECONDS = 70.0
POLL_SECONDS = 0.5
RETRY_READ_SECONDS = 3.0
STOP_TIMEOUT_SECONDS = 20.0  # > daemon shutdown budget: reader join 5 s + dispatcher stop 10 s
REAL_RULES_SKIP = (
    "real credwatch audit rules are loaded; run the e2e test before `credwatch install`, "
    "or temporarily move /etc/audit/rules.d/credwatch.rules aside "
    "(see docs/linux-verification.md §2)"
)
RUN_MAIN = "import sys; from credwatch.cli import main; sys.exit(main())"
# R55 probe: take location-only (O_PATH) handles, then try to turn them into reads.
O_PATH_PROBE = """\
import os, sys
target, secret_dir = sys.argv[1], sys.argv[2]
fd = os.open(target, os.O_PATH)
reopened = os.open(f"/proc/self/fd/{fd}", os.O_RDONLY)  # re-open the same file for reading
os.read(reopened, 64)
dfd = os.open(secret_dir, os.O_PATH | os.O_DIRECTORY)
inner = os.open("inner", os.O_RDONLY, dir_fd=dfd)  # open a file beneath the handle
os.read(inner, 64)
"""


@dataclass(frozen=True)
class E2eEnv:
    root: Path
    data_dir: Path
    target: Path
    secret_dir: Path
    daemon: subprocess.Popen
    log_path: Path

    @property
    def db_path(self) -> Path:
        return self.data_dir / "events.db"

    def daemon_log(self) -> str:
        return self.log_path.read_text(errors="replace") if self.log_path.exists() else ""


def _wait_for(predicate, timeout: float, on_tick=None) -> bool:
    deadline = time.monotonic() + timeout
    while True:
        if predicate():
            return True
        if time.monotonic() >= deadline:
            return False
        if on_tick is not None:
            on_tick()
        time.sleep(POLL_SECONDS)


def _with_store(db_path: Path, fn):
    if not db_path.exists():
        return None
    store = Store(db_path)
    try:
        return fn(store)
    finally:
        store.close()


def _stop(daemon: subprocess.Popen | None) -> None:
    if daemon is None or daemon.poll() is not None:
        return
    daemon.send_signal(signal.SIGTERM)
    try:
        daemon.wait(timeout=STOP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired:
        warnings.warn("credwatch daemon ignored SIGTERM; killing", stacklevel=2)
        daemon.kill()
        daemon.wait()


def _remove_rules() -> None:
    try:
        E2E_RULES_FILE.unlink(missing_ok=True)
    except OSError as exc:
        warnings.warn(f"could not remove {E2E_RULES_FILE}: {exc}", stacklevel=2)
    result = subprocess.run(["augenrules", "--load"], capture_output=True, text=True)
    if result.returncode != 0:
        warnings.warn(f"augenrules --load failed during teardown: {result.stderr}", stacklevel=2)


def _prepare(root: Path) -> tuple[Path, Path, Path, Path, Path]:
    data_dir = root / "data"
    for sub in ("", "captures", "audit-exports", "logs"):
        (data_dir / sub).mkdir(mode=0o700, exist_ok=True)
    canary = data_dir / "canary"
    canary.write_text(CANARY_BODY)  # R52: identity pin requires the installer's exact body
    canary.chmod(0o600)
    target = root / "secret-target"
    target.write_text("e2e secret\n")
    target.chmod(0o600)
    secret_dir = root / "secret-dir"
    secret_dir.mkdir(mode=0o700)
    (secret_dir / "inner").write_text("e2e inner secret\n")
    config = root / "config.yaml"
    config.write_text(yaml.safe_dump({
        "data_dir": str(data_dir),
        "capture": {"enabled": False},
        "email": {"from_addr": "e2e@localhost", "to_addrs": ["e2e@localhost"]},
    }))
    watch_list = root / "watched_paths.txt"
    watch_list.write_text(f"{target}\n{secret_dir}\n{canary}\n")
    return data_dir, target, secret_dir, config, watch_list


@pytest.fixture(scope="module")
def e2e_env() -> Iterator[E2eEnv]:
    runner = SubprocessRunner()
    # Skip before any teardown can run: teardown reloads rules and would flush real ones.
    if DEFAULT_RULES_FILE.exists() or count_loaded_rules(runner) > 0:
        pytest.skip(REAL_RULES_SKIP)
    root = Path(tempfile.mkdtemp(prefix="credwatch-e2e-"))
    daemon: subprocess.Popen | None = None
    try:
        data_dir, target, secret_dir, config, watch_list = _prepare(root)
        if runner.run(["systemctl", "is-active", "auditd"]).stdout.strip() != "active":
            ensure_auditd(runner)
        install_rules([target, secret_dir, data_dir / "canary"], E2E_RULES_FILE, runner=runner)
        log_path = root / "daemon.log"
        secrets = root / "empty-secrets.env"
        secrets.write_text("")
        secrets.chmod(0o600)
        child_env = {k: v for k, v in os.environ.items() if not k.startswith("CREDWATCH_SMTP_")}
        with log_path.open("w") as log:
            daemon = subprocess.Popen(
                [sys.executable, "-c", RUN_MAIN, "--config", str(config), "--user", "root",
                 "--secrets-file", str(secrets), "run", "--watch-list", str(watch_list)],
                stdout=log, stderr=subprocess.STDOUT, env=child_env,
            )
        env = E2eEnv(root, data_dir, target, secret_dir, daemon, log_path)
        # Readiness: the daemon's own startup canary probe proves the tail is live.
        ready = _wait_for(
            lambda: _canary_ok(env) or daemon.poll() is not None, CANARY_TIMEOUT_SECONDS
        )
        if not ready or not _canary_ok(env):
            pytest.fail(
                "daemon never recorded its canary probe; see daemon log below\n"
                + env.daemon_log(),
                pytrace=False,
            )
        yield env
    finally:
        _stop(daemon)
        _remove_rules()
        shutil.rmtree(root, ignore_errors=True)
        if root.exists():
            warnings.warn(f"could not fully delete {root}", stacklevel=2)


def _canary_ok(env: E2eEnv) -> bool:
    return bool(_with_store(env.db_path, lambda s: s.get_meta("last_canary_ok")))


def _flagged_curl_rows(env: E2eEnv):
    def query(store: Store):
        return [
            r for r in store.flagged_events()
            if (r.exe or "").endswith("curl") and r.path.endswith(env.target.name)
        ]

    return _with_store(env.db_path, query) or []


def test_curl_reading_target_is_flagged_and_stored(e2e_env: E2eEnv) -> None:
    def read_target() -> None:
        subprocess.run([CURL, "-s", f"file://{e2e_env.target}"], capture_output=True, check=False)

    read_target()
    assert _wait_for(
        lambda: bool(_flagged_curl_rows(e2e_env)), EVENT_TIMEOUT_SECONDS, on_tick=read_target
    ), f"no flagged curl event within {EVENT_TIMEOUT_SECONDS:.0f}s; daemon log:\n{e2e_env.daemon_log()}"
    row = _flagged_curl_rows(e2e_env)[0]
    assert row.allowed is False
    assert row.snapshot is not None, "flagged event has no network snapshot row"


def test_e2e_canary_probe_ok(e2e_env: E2eEnv) -> None:
    assert _wait_for(lambda: _canary_ok(e2e_env), CANARY_TIMEOUT_SECONDS), (
        f"last_canary_ok not set within {CANARY_TIMEOUT_SECONDS:.0f}s; "
        f"daemon log:\n{e2e_env.daemon_log()}"
    )


# --- R55: O_PATH opens are recorded, not flagged; turning them into reads is flagged ----

def _probe_rows(env: E2eEnv, pids: list[int]):
    def query(store: Store):
        return [r for r in store.events_since(datetime.fromtimestamp(0, timezone.utc))
                if r.pid in pids]

    return _with_store(env.db_path, query) or []


def _probe_pids(env: E2eEnv) -> list[int]:
    """Run the probe via Popen so we know its pid; retry until its events are stored."""
    pids: list[int] = []

    def run_once() -> None:
        proc = subprocess.Popen(
            [sys.executable, "-c", O_PATH_PROBE, str(env.target), str(env.secret_dir)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )
        _, err = proc.communicate(timeout=10)
        assert proc.returncode == 0, f"probe failed: {err}"
        pids.append(proc.pid)

    def has_all() -> bool:
        rows = _probe_rows(env, pids)
        return (
            any(r.matched_rule == PATH_ONLY_RULE and r.path.endswith(env.target.name) for r in rows)
            and any(not r.allowed for r in rows
                    if not r.path.endswith(("inner", env.secret_dir.name)))
            and any(not r.allowed and r.path.endswith("inner") for r in rows)
        )

    run_once()
    assert _wait_for(has_all, EVENT_TIMEOUT_SECONDS, on_tick=run_once), (
        f"probe events incomplete within {EVENT_TIMEOUT_SECONDS:.0f}s: "
        f"{[(r.path, r.allowed, r.matched_rule) for r in _probe_rows(env, pids)]}\n"
        f"daemon log:\n{env.daemon_log()}"
    )
    return pids


def test_o_path_open_is_recorded_but_not_flagged(e2e_env: E2eEnv) -> None:
    rows = _probe_rows(e2e_env, _probe_pids(e2e_env))
    path_only = [r for r in rows if r.matched_rule == PATH_ONLY_RULE]
    assert any(r.path.endswith(e2e_env.target.name) for r in path_only)
    assert all(r.allowed and r.snapshot is None for r in path_only)


def test_proc_reopen_of_o_path_handle_is_flagged(e2e_env: E2eEnv) -> None:
    """The /proc/self/fd re-open is a new open: it must be audited and flagged."""
    rows = _probe_rows(e2e_env, _probe_pids(e2e_env))
    reads = [r for r in rows if r.matched_rule != PATH_ONLY_RULE
             and not r.path.endswith(("inner", e2e_env.secret_dir.name))]
    assert reads and all(not r.allowed for r in reads), [(r.path, r.allowed) for r in rows]


def test_open_beneath_o_path_dir_handle_is_flagged(e2e_env: E2eEnv) -> None:
    rows = _probe_rows(e2e_env, _probe_pids(e2e_env))
    inner = [r for r in rows if r.path.endswith("inner")]
    assert inner and all(not r.allowed for r in inner), [(r.path, r.allowed) for r in rows]
