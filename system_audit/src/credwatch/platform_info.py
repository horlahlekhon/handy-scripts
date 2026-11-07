"""OS detection, target user resolution and default locations."""
from __future__ import annotations

import os
import pwd
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

OsName = Literal["linux", "darwin"]

CONFIG_DIR = Path("/etc/credwatch")
CONFIG_PATH = CONFIG_DIR / "config.yaml"
SECRETS_PATH = CONFIG_DIR / "secrets.env"
WATCH_LIST_PATH = CONFIG_DIR / "watched_paths.txt"


class UnsupportedPlatform(RuntimeError):
    pass


class UnknownUser(RuntimeError):
    pass


@dataclass(frozen=True)
class TargetUser:
    name: str
    uid: int
    gid: int
    home: Path


def current_os() -> OsName:
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform == "darwin":
        return "darwin"
    raise UnsupportedPlatform(f"unsupported platform: {sys.platform}")


def resolve_target_user(explicit: str | None, environ: Mapping[str, str]) -> TargetUser:
    """Pick the user whose credentials are watched: explicit, SUDO_USER, then current."""
    name = explicit or environ.get("SUDO_USER") or None
    try:
        entry = pwd.getpwnam(name) if name else pwd.getpwuid(os.getuid())
    except KeyError as exc:
        raise UnknownUser(f"no such user: {name or os.getuid()}") from exc
    return TargetUser(
        name=entry.pw_name, uid=entry.pw_uid, gid=entry.pw_gid, home=Path(entry.pw_dir)
    )


def default_data_dir(os_name: str) -> Path:
    """Root-owned data dir (never under the target user's home)."""
    if os_name == "darwin":
        return Path("/Library/Application Support/credwatch")
    return Path("/var/lib/credwatch")
