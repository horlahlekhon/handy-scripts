"""credwatch installer entry point."""
from __future__ import annotations

from pathlib import Path

from credwatch.installer import linux, macos
from credwatch.installer.common import InstallError, InstallReport
from credwatch.platform_info import TargetUser
from credwatch.proc import Runner

__all__ = ["InstallError", "InstallReport", "run_install"]


def run_install(
    os_name: str,
    target: TargetUser,
    *,
    runner: Runner,
    root: Path = Path("/"),
    start: bool = True,
    owner_uid: int = 0,
    executable: Path | None = None,
) -> InstallReport:
    """Install/refresh the service. owner_uid is the test seam (see installer.common)."""
    if os_name == "darwin":
        module = macos
    elif os_name == "linux":
        module = linux
    else:
        raise InstallError(f"unsupported platform: {os_name}")
    return module.install(
        target, runner=runner, root=root, start=start, owner_uid=owner_uid, executable=executable
    )
