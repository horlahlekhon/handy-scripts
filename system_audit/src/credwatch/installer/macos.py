"""Idempotent macOS install: config, data dirs, watch list, launchd daemon.

The plist is built with plistlib (no template file): launchd has no
EnvironmentFile, so SMTP secrets reach the daemon via `--secrets-file`.
"""
from __future__ import annotations

import grp
import logging
import os
import plistlib
import stat
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from credwatch.installer.common import (
    InstallError,
    InstallReport,
    StepResult,
    assert_root_owned_install,
    outcome,
    prepare_install,
    rooted,
    write_if_changed,
)
from credwatch.platform_info import CONFIG_DIR, CONFIG_PATH, SECRETS_PATH, TargetUser
from credwatch.proc import Runner

logger = logging.getLogger(__name__)

LABEL = "com.credwatch.daemon"
PLIST_PATH = Path("/Library/LaunchDaemons/com.credwatch.daemon.plist")
PLIST_FILE_MODE = 0o644
WHEEL_GROUP = "wheel"
LOG_SUBDIR = "logs"
STDOUT_LOG = "launchd.out.log"
STDERR_LOG = "launchd.err.log"
BOOTSTRAP_EIO = 5  # launchd has not finished tearing down the booted-out job
BOOTSTRAP_RETRY_DELAY_SECONDS = 1.0
# Root-owned symlinks into /private on macOS; safe_fs refuses symlinked
# ancestors, so paths under these are handed to it in resolved form.
SYMLINKED_SYSTEM_PREFIXES = (Path("/etc"), Path("/var"), Path("/tmp"))
BREW_HINT = (
    "on macOS `sudo pipx install --global` defaults to /usr/local/bin, which Homebrew "
    "makes user-owned on Intel Macs, so a non-root user could replace the entry point "
    "the root daemon runs. Reinstall into root-owned dirs, e.g. "
    "`sudo PIPX_GLOBAL_HOME=/opt/pipx PIPX_GLOBAL_BIN_DIR=/opt/pipx/bin "
    "pipx install --global ./system_audit`, then run /opt/pipx/bin/credwatch install"
)


def resolve_system_path(
    path: Path,
    *,
    realpath: Callable[[str], str] = os.path.realpath,
    lstat: Callable[[str], Any] = os.lstat,
) -> Path:
    """Replace a known symlinked system prefix (/etc, /var, /tmp) by its target.

    Only the fixed prefix is resolved, never the rest of the path, and the
    prefix must be root-owned if it is a symlink.
    """
    for prefix in SYMLINKED_SYSTEM_PREFIXES:
        if path != prefix and prefix not in path.parents:
            continue
        st = lstat(str(prefix))
        if stat.S_ISLNK(st.st_mode) and st.st_uid != 0:
            raise InstallError(f"{prefix} is a symlink not owned by root (uid {st.st_uid})")
        return Path(realpath(str(prefix))) / path.relative_to(prefix)
    return path


def render_plist(executable: Path, data_dir: Path, user: str) -> bytes:
    """`user` must already be validated (validate_service_user)."""
    logs = data_dir / LOG_SUBDIR
    return plistlib.dumps({
        "Label": LABEL,
        "ProgramArguments": [
            str(executable), "run", "--config", str(CONFIG_PATH),
            "--secrets-file", str(SECRETS_PATH), "--user", user,
        ],
        "RunAtLoad": True,
        "KeepAlive": True,
        "StandardOutPath": str(logs / STDOUT_LOG),
        "StandardErrorPath": str(logs / STDERR_LOG),
    })


def _trust_check(executable: Path, prefix: Path) -> None:
    try:
        assert_root_owned_install(executable, prefix)
    except InstallError as exc:
        raise InstallError(f"{exc}; {BREW_HINT}") from exc


def _set_owner(path: Path, owner_uid: int) -> None:
    """root:wheel in production; the owner_uid test seam leaves ownership alone."""
    if owner_uid != 0:
        return
    try:
        gid = grp.getgrnam(WHEEL_GROUP).gr_gid
    except KeyError:
        logger.warning("group %r not found; leaving %s group unchanged", WHEEL_GROUP, path)
        gid = -1
    os.chown(path, 0, gid, follow_symlinks=False)


def _plist(
    executable: Path, user: str, data_dir: Path, plist_path: Path, owner_uid: int
) -> StepResult:
    content = render_plist(executable, data_dir, user).decode("utf-8")
    changed = write_if_changed(plist_path, content, PLIST_FILE_MODE)
    _set_owner(plist_path, owner_uid)
    return outcome(f"plist {plist_path}", changed)


def _bootstrap(runner: Runner, plist_path: Path) -> Any:
    return runner.run(["launchctl", "bootstrap", "system", str(plist_path)])


def _launchctl_load(
    runner: Runner, plist_path: Path, sleep: Callable[[float], object] = time.sleep
) -> None:
    out = runner.run(["launchctl", "bootout", f"system/{LABEL}"])
    if out.returncode != 0:
        logger.info(
            "launchctl bootout: %s was not loaded (rc=%d): %s",
            LABEL, out.returncode, (out.stderr or "").strip(),
        )
    result = _bootstrap(runner, plist_path)
    if result.returncode == BOOTSTRAP_EIO:
        logger.warning(
            "launchctl bootstrap returned %d (%s); retrying once in %.0f s",
            BOOTSTRAP_EIO, (result.stderr or "").strip(), BOOTSTRAP_RETRY_DELAY_SECONDS,
        )
        sleep(BOOTSTRAP_RETRY_DELAY_SECONDS)
        result = _bootstrap(runner, plist_path)
    if result.returncode != 0:
        raise InstallError(
            f"launchctl bootstrap system {plist_path} failed (rc={result.returncode}): "
            f"{(result.stderr or '').strip()}"
        )


def install(
    target: TargetUser,
    *,
    runner: Runner,
    root: Path = Path("/"),
    start: bool = True,
    owner_uid: int = 0,
    executable: Path | None = None,
    realpath: Callable[[str], str] = os.path.realpath,
    sleep: Callable[[float], object] = time.sleep,
) -> InstallReport:
    prepared = prepare_install(
        "darwin", target, root=root, owner_uid=owner_uid, executable=executable,
        config_dir=resolve_system_path(CONFIG_DIR, realpath=realpath),
        trust_check=_trust_check,
    )
    plist_path = rooted(root, PLIST_PATH)
    result = prepared.result.merge(
        _plist(prepared.executable, prepared.user, prepared.config.data_dir, plist_path, owner_uid)
    )
    if start:
        _launchctl_load(runner, plist_path, sleep)
    else:
        logger.info("--no-start: %s written but not loaded; launchd loads it at boot", plist_path)
    return InstallReport(
        created=result.created,
        unchanged=result.unchanged,
        warnings=result.warnings,
        watched=len(prepared.paths),
        skipped=(),
    )
