"""Symlink-safe directory creation/opening for root-run code."""
from __future__ import annotations

import errno
import logging
import os
import stat
from pathlib import Path

logger = logging.getLogger(__name__)

_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
_SYMLINK_ERRNOS = {errno.ELOOP, errno.ENOTDIR}


class UnsafePathError(Exception):
    """Raised when a path component is a symlink, wrongly owned, or too writable."""


def _components(path: Path) -> list[str]:
    if not path.is_absolute():
        raise ValueError(f"path must be absolute: {path}")
    normalized = os.path.normpath(str(path))
    parts = [p for p in normalized.split("/") if p]
    if any(p in (".", "..") for p in parts):
        raise ValueError(f"path contains '.' or '..' components: {path}")
    return parts


def _open_component(name: str, parent_fd: int, create_mode: int) -> tuple[int, bool]:
    """Open one directory under parent_fd, creating it if missing. Returns (fd, created)."""
    created = False
    try:
        try:
            return os.open(name, _DIR_FLAGS, dir_fd=parent_fd), False
        except FileNotFoundError:
            os.mkdir(name, create_mode, dir_fd=parent_fd)
            created = True
        return os.open(name, _DIR_FLAGS, dir_fd=parent_fd), created
    except OSError as exc:
        if exc.errno in _SYMLINK_ERRNOS:
            raise UnsafePathError(
                f"path component {name!r} is a symlink or not a directory"
            ) from exc
        raise


def open_dir_chain(path: Path, *, create_mode: int = 0o700) -> int:
    """Open (creating as needed) every directory of an absolute path without
    following symlinks. Returns an O_DIRECTORY fd for the final directory;
    the caller must close it."""
    parts = _components(Path(path))
    fd = os.open("/", _DIR_FLAGS)
    created = False
    try:
        for name in parts:
            child, created = _open_component(name, fd, create_mode)
            os.close(fd)
            fd = child
        st = os.fstat(fd)
        if st.st_uid != os.geteuid():
            raise UnsafePathError(f"{path} is not owned by uid {os.geteuid()}")
        if created:
            os.fchmod(fd, create_mode)
        elif st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise UnsafePathError(f"{path} is group/other writable")
        return fd
    except BaseException:
        os.close(fd)
        raise
