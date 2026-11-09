"""Idempotent Linux install: config, data dirs, audit rules, systemd unit."""
from __future__ import annotations

import logging
from pathlib import Path

from credwatch.backends.base import BackendError
from credwatch.backends.linux_audit import (
    DEFAULT_RULES_FILE,
    ensure_auditd,
    install_rules,
    render_rules,
)
from credwatch.installer.common import (
    InstallError,
    InstallReport,
    StepResult,
    assert_root_owned_install,
    find_executable,
    outcome,
    prepare_install,
    rooted,
    template_text,
    write_if_changed,
)
from credwatch.platform_info import CONFIG_DIR, TargetUser
from credwatch.proc import Runner

__all__ = ["find_executable", "install", "render_unit"]

logger = logging.getLogger(__name__)

SERVICE_NAME = "credwatch"
UNIT_PATH = Path("/etc/systemd/system/credwatch.service")
UNIT_TEMPLATE = "credwatch.service"
UNIT_FILE_MODE = 0o644
EXECUTABLE_PLACEHOLDER = "{executable}"
USER_PLACEHOLDER = "{user}"
NEEDS_RELOAD = "yes"


def render_unit(executable: Path, user: str) -> str:
    """`user` must already be validated (validate_service_user): it lands in ExecStart."""
    return (
        template_text(UNIT_TEMPLATE)
        .replace(EXECUTABLE_PLACEHOLDER, str(executable))
        .replace(USER_PLACEHOLDER, user)
    )


def _systemctl(runner: Runner, *args: str) -> None:
    result = runner.run(["systemctl", *args])
    if result.returncode != 0:
        raise InstallError(
            f"systemctl {' '.join(args)} failed: {(result.stderr or '').strip()}"
        )


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


def _unit(executable: Path, user: str, unit_path: Path, runner: Runner) -> StepResult:
    changed = write_if_changed(unit_path, render_unit(executable, user), UNIT_FILE_MODE)
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
    prepared = prepare_install(
        "linux", target, root=root, owner_uid=owner_uid, executable=executable,
        config_dir=CONFIG_DIR, trust_check=assert_root_owned_install,
    )
    paths = prepared.paths
    rendered = render_rules(paths)  # same paths install_rules renders; one source for counts
    result = (
        prepared.result
        .merge(_audit_rules(paths, rooted(root, DEFAULT_RULES_FILE), runner))
        .merge(_unit(prepared.executable, prepared.user, rooted(root, UNIT_PATH), runner))
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
