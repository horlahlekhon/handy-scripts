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
    raw_parts = str(path).split("/")
    if any(p in (".", "..") for p in raw_parts):
        raise ValueError(f"path contains '.' or '..' components: {path}")
    return [p for p in raw_parts if p]


def _open_component(name: str, parent_fd: int, create_mode: int) -> tuple[int, bool]:
    """Open one directory under parent_fd, creating it if missing. Returns (fd, created)."""
    created = False
    try:
        try:
            return os.open(name, _DIR_FLAGS, dir_fd=parent_fd), False
        except FileNotFoundError:
            pass
        try:
            os.mkdir(name, create_mode, dir_fd=parent_fd)
            created = True
        except FileExistsError:
            logger.warning("directory %r was created concurrently; retrying open", name)
        return os.open(name, _DIR_FLAGS, dir_fd=parent_fd), created
    except OSError as exc:
        if exc.errno in _SYMLINK_ERRNOS:
            raise UnsafePathError(
                f"path component {name!r} is a symlink or not a directory"
            ) from exc
        if isinstance(exc, FileNotFoundError):
            raise UnsafePathError(f"path component {name!r} vanished while opening") from exc
        raise


def _check_ancestor(fd: int, name: str) -> None:
    st = os.fstat(fd)
    if st.st_uid not in (0, os.geteuid()):
        raise UnsafePathError(f"directory {name!r} has untrusted owner uid {st.st_uid}")
    if st.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        sticky_root = st.st_uid == 0 and st.st_mode & stat.S_ISVTX
        if not sticky_root:
            raise UnsafePathError(f"directory {name!r} is group/other writable")


def open_dir_chain(path: Path, *, create_mode: int = 0o700) -> int:
    """Open (creating as needed) every directory of an absolute path without
    following symlinks. Returns an O_DIRECTORY fd for the final directory;
    the caller must close it.

    Every existing directory walked (including "/") must be owned by uid 0 or
    the euid and not group/other writable; the exception is a root-owned
    directory with the sticky bit (like /tmp), which is allowed. Newly created
    components are owned by us with create_mode.

    Paths are NOT resolved: on macOS /etc, /var and /tmp are root-owned
    symlinks, so callers must pass already-resolved paths."""
    parts = _components(Path(path))
    fd = os.open("/", _DIR_FLAGS)
    created = False
    try:
        _check_ancestor(fd, "/")
        for name in parts:
            child, created = _open_component(name, fd, create_mode)
            if not created:
                _check_ancestor(child, name)
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
