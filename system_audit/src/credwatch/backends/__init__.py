"""Platform backends that turn OS audit facilities into FileAccessEvents."""
from __future__ import annotations

import importlib
from collections.abc import Iterable
from pathlib import Path

from credwatch.backends.base import Backend, BackendError
from credwatch.config import Config
from credwatch.proc import Runner

LINUX_AUDIT_LOG = Path("/var/log/audit/audit.log")
MACOS_MODULE = "credwatch.backends.macos_fsusage"
MACOS_CLASS = "MacFsUsageBackend"


def get_backend(config: Config, watch_paths: Iterable[Path], runner: Runner) -> Backend:
    """Pick the backend for config.os_name.

    `watch_paths` is needed (beyond the planned (config, runner) signature) so the Linux
    backend knows how many audit rules it must find loaded.
    """
    paths = tuple(watch_paths)
    if config.os_name == "linux":
        from credwatch.backends.linux_audit import LinuxAuditBackend, render_rules

        rendered = render_rules(paths)
        return LinuxAuditBackend(
            audit_log=LINUX_AUDIT_LOG,
            expected_rule_count=len(paths) - len(rendered.skipped),
            runner=runner,
            export_checkpoint=config.data_dir / "audit-exports" / ".checkpoint",
        )
    if config.os_name == "darwin":
        try:
            module = importlib.import_module(MACOS_MODULE)
        except ModuleNotFoundError as exc:
            if exc.name != MACOS_MODULE:
                raise
            raise BackendError("macOS backend not available in this build") from exc
        # fs_usage is a long-lived child, spawned with Popen rather than the Runner.
        return getattr(module, MACOS_CLASS)(
            watch_paths=paths, export_dir=config.data_dir / "audit-exports",
            trust_name_resolution=config.darwin_trust_name_resolution,
        )
    raise BackendError(f"unsupported platform: {config.os_name}")
