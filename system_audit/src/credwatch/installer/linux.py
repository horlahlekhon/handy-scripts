"""Idempotent Linux install: config, data dirs, audit rules, systemd unit."""
from __future__ import annotations

import logging
import os
import shutil
import sys
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path

from credwatch.backends.base import BackendError
from credwatch.backends.linux_audit import (
    DEFAULT_RULES_FILE,
    ensure_auditd,
    install_rules,
    render_rules,
)
from credwatch.config import Config, ConfigError, load_config
from credwatch.installer.common import (
    InstallError,
    InstallReport,
    StepResult,
    assert_root_owned_install,
    bootstrap_config,
    bootstrap_secrets,
    ensure_dirs,
    ensure_owned_dir,
    outcome,
    template_text,
    write_if_changed,
)
from credwatch.paths import has_control_chars, read_watch_list, resolve_watch_paths_report, write_watch_list
from credwatch.platform_info import CONFIG_DIR, CONFIG_PATH, SECRETS_PATH, WATCH_LIST_PATH, TargetUser
from credwatch.proc import Runner

logger = logging.getLogger(__name__)

SERVICE_NAME = "credwatch"
UNIT_PATH = Path("/etc/systemd/system/credwatch.service")
UNIT_TEMPLATE = "credwatch.service"
UNIT_FILE_MODE = 0o644
EXECUTABLE_PLACEHOLDER = "{executable}"
SHEBANG_MAX_BYTES = 4096
NEEDS_RELOAD = "yes"


def _rooted(root: Path, path: Path) -> Path:
    """Map an absolute system path under root (identity when root is '/')."""
    return root / path.relative_to("/")


def _shebang_interpreter(script: Path) -> Path | None:
    try:
        with script.open("rb") as fh:
            first = fh.readline(SHEBANG_MAX_BYTES)
    except OSError:
        logger.warning("cannot read %s to check its interpreter", script, exc_info=True)
        return None
    if not first.startswith(b"#!"):
        return None
    words = first[2:].decode("utf-8", errors="replace").split()
    return Path(words[0]) if words else None


def find_executable(
    argv0: str | None = None,
    *,
    which: Callable[[str], str | None] = shutil.which,
    prefix: Path | None = None,
) -> Path:
    """The entry point that is actually running (unresolved, so a pipx symlink stays).

    Falls back to PATH lookup only when argv[0] is not a file, and then only if
    that script's interpreter lives inside our own sys.prefix.
    """
    argv0 = sys.argv[0] if argv0 is None else argv0
    if argv0.endswith(".py"):
        raise InstallError("run install via the installed `credwatch` command")
    running = Path(os.path.abspath(argv0))
    if running.is_file():
        return running
    found = which(SERVICE_NAME)
    if not found:
        raise InstallError("cannot locate the credwatch entry point; run the installed `credwatch` command")
    candidate = Path(os.path.abspath(found))
    own_prefix = (prefix or Path(sys.prefix)).resolve()
    interpreter = _shebang_interpreter(candidate)
    if interpreter is None or own_prefix not in interpreter.resolve().parents:
        raise InstallError(
            f"{candidate} (found on PATH) does not run this credwatch installation "
            f"(interpreter {interpreter}, expected inside {own_prefix})"
        )
    return candidate


def _validate_executable(executable: Path) -> None:
    text = str(executable)
    if not executable.is_absolute():
        raise InstallError(f"credwatch executable path must be absolute: {text!r}")
    if has_control_chars(text) or any(c.isspace() for c in text):
        raise InstallError(
            f"credwatch executable path contains whitespace/control characters: {text!r}"
        )


def render_unit(executable: Path) -> str:
    return template_text(UNIT_TEMPLATE).replace(EXECUTABLE_PLACEHOLDER, str(executable))


def _systemctl(runner: Runner, *args: str) -> None:
    result = runner.run(["systemctl", *args])
    if result.returncode != 0:
        raise InstallError(
            f"systemctl {' '.join(args)} failed: {(result.stderr or '').strip()}"
        )


def _load(config_path: Path, target: TargetUser, root: Path) -> Config:
    try:
        cfg = load_config(config_path, "linux", target)
    except ConfigError as exc:
        raise InstallError(f"invalid config {config_path}: {exc}") from exc
    if not cfg.data_dir.is_absolute():
        raise InstallError(f"data_dir must be an absolute path: {cfg.data_dir}")
    return replace(cfg, data_dir=_rooted(root, cfg.data_dir))


def _config_files(root: Path, owner_uid: int) -> StepResult:
    config_path = _rooted(root, CONFIG_PATH)
    secrets_path = _rooted(root, SECRETS_PATH)
    result = ensure_owned_dir(_rooted(root, CONFIG_DIR), owner_uid=owner_uid)
    created = bootstrap_config(config_path, owner_uid=owner_uid)
    secrets_created, warnings = bootstrap_secrets(secrets_path, owner_uid=owner_uid)
    return (
        result.merge(outcome(f"file {config_path}", created))
        .merge(outcome(f"file {secrets_path}", secrets_created))
        .merge(StepResult(warnings=warnings))
    )


def _watch_list(paths: tuple[Path, ...], dest: Path) -> StepResult:
    try:
        if read_watch_list(dest) == paths:
            return outcome(f"file {dest}", False)
    except FileNotFoundError:
        pass
    except (OSError, ValueError):  # includes UnicodeDecodeError
        logger.warning("cannot read existing watch list %s; rewriting it", dest, exc_info=True)
    write_watch_list(paths, dest)
    return outcome(f"file {dest}", True)


def _audit_rules(paths: tuple[Path, ...], rules_file: Path, runner: Runner) -> StepResult:
    label = f"audit rules {rules_file}"
    try:
        ensure_auditd(runner)
        changed = install_rules(paths, rules_file, runner=runner)
    except BackendError as exc:
        raise InstallError(f"audit setup failed: {exc}") from exc
    return StepResult(created=(f"{label} (reloaded)",)) if changed else StepResult(unchanged=(label,))


def _needs_daemon_reload(runner: Runner) -> bool:
    """systemd's own view; a failing query counts as 'needs reload' (repairs a failed run)."""
    result = runner.run(["systemctl", "show", "-p", "NeedDaemonReload", "--value", SERVICE_NAME])
    if result.returncode != 0:
        logger.warning(
            "systemctl show NeedDaemonReload failed (rc=%d): %s; reloading anyway",
            result.returncode, (result.stderr or "").strip(),
        )
        return True
    return (result.stdout or "").strip() == NEEDS_RELOAD


def _unit(executable: Path, unit_path: Path, runner: Runner) -> StepResult:
    changed = write_if_changed(unit_path, render_unit(executable), UNIT_FILE_MODE)
    if changed or _needs_daemon_reload(runner):
        _systemctl(runner, "daemon-reload")
    return outcome(f"unit {unit_path}", changed)


def install(
    target: TargetUser,
    *,
    runner: Runner,
    root: Path = Path("/"),
    start: bool = True,
    owner_uid: int = 0,
    executable: Path | None = None,
) -> InstallReport:
    if os.geteuid() != owner_uid:
        raise InstallError("credwatch install must be run as root (sudo credwatch install)")
    exe = executable or find_executable()
    _validate_executable(exe)
    assert_root_owned_install(exe, Path(sys.prefix))

    result = _config_files(root, owner_uid)
    cfg = _load(_rooted(root, CONFIG_PATH), target, root)
    result = result.merge(ensure_dirs(cfg, owner_uid=owner_uid))

    paths, skipped_targets = resolve_watch_paths_report(cfg)
    link_warnings = tuple(
        f"symlink {link} points outside {cfg.home} (or to an unsafe path) at {target_path}; "
        "only the link is watched"
        for link, target_path in skipped_targets
    )
    rendered = render_rules(paths)  # same paths install_rules renders; one source for counts
    result = (
        result.merge(StepResult(warnings=link_warnings))
        .merge(_watch_list(paths, _rooted(root, WATCH_LIST_PATH)))
        .merge(_audit_rules(paths, _rooted(root, DEFAULT_RULES_FILE), runner))
        .merge(_unit(exe, _rooted(root, UNIT_PATH), runner))
    )
    _systemctl(runner, "enable", SERVICE_NAME)
    if start:
        _systemctl(runner, "restart", SERVICE_NAME)
    return InstallReport(
        created=result.created,
        unchanged=result.unchanged,
        warnings=result.warnings,
        watched=len(paths) - len(rendered.skipped),
        skipped=rendered.skipped,
    )
