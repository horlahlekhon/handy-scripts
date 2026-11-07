"""Allowlist matching: (path pattern, process names) rules, unioned.

Process identity comes from the resolved exe only (comm and basenames of
untrusted locations are spoofable), and fails closed when exe is unknown.
"""
from __future__ import annotations

import grp
import logging
import os
import re
import stat as stat_mod
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field, replace
from fnmatch import fnmatchcase
from functools import lru_cache
from typing import Any

from credwatch.config import AllowRule
from credwatch.models import FileAccessEvent, Verdict

logger = logging.getLogger(__name__)

_RECURSIVE_SUFFIX = "/**"
_WHEEL_GROUP = "wheel"


@lru_cache(maxsize=1024)
def _glob_regex(pattern: str) -> re.Pattern[str]:
    """Translate a glob where '*' and '?' never cross '/'."""
    out: list[str] = []
    for ch in pattern:
        if ch == "*":
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(ch))
    return re.compile("".join(out) + r"\Z")


def _path_matches(pattern: str, path: str) -> bool:
    if pattern.endswith(_RECURSIVE_SUFFIX):
        base = pattern[: -len(_RECURSIVE_SUFFIX)]
        return path == base or path.startswith(base.rstrip("/") + "/")
    return _glob_regex(pattern).match(path) is not None


def _is_under(path: str, directory: str) -> bool:
    base = os.path.normpath(directory)
    return path.startswith(base.rstrip("/") + "/")


def _wheel_gid() -> int | None:
    try:
        return grp.getgrnam(_WHEEL_GROUP).gr_gid
    except KeyError:
        logger.warning("group %r not found; treating group-writable dirs as untrusted", _WHEEL_GROUP)
        return None


def is_root_controlled_dir(
    path: str,
    stat_fn: Callable[[str], Any] = os.stat,
    allow_wheel: bool = False,
) -> bool:
    """True if path and every ancestor up to '/' is root-owned and not writable by others.

    Group-writable is tolerated only for gid 0 (or group "wheel" if allow_wheel).
    """
    allowed_gids = {0}
    if allow_wheel:
        wheel = _wheel_gid()
        if wheel is not None:
            allowed_gids.add(wheel)
    current = os.path.normpath(path)
    while True:
        try:
            st = stat_fn(current)
        except OSError:
            logger.warning("cannot stat %s; treating as untrusted", current, exc_info=True)
            return False
        if st.st_uid != 0 or st.st_mode & stat_mod.S_IWOTH:
            return False
        if st.st_mode & stat_mod.S_IWGRP and st.st_gid not in allowed_gids:
            return False
        parent = os.path.dirname(current)
        if parent == current:
            return True
        current = parent


def _normalize_pattern(pattern: str) -> str:
    if pattern.endswith(_RECURSIVE_SUFFIX):
        base = pattern[: -len(_RECURSIVE_SUFFIX)] or "/"
        return os.path.normpath(base).rstrip("/") + _RECURSIVE_SUFFIX
    return os.path.normpath(pattern)


@dataclass(frozen=True)
class Allowlist:
    rules: tuple[AllowRule, ...]
    trusted_dirs: Iterable[str | os.PathLike[str]] = ()
    stat_fn: Callable[[str], Any] = os.stat
    os_name: str = "linux"
    _dir_cache: dict[str, bool] = field(default_factory=dict, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "rules",
            tuple(replace(r, path_pattern=_normalize_pattern(r.path_pattern)) for r in self.rules),
        )
        object.__setattr__(
            self, "trusted_dirs",
            tuple(os.path.normpath(str(d)) for d in self.trusted_dirs),
        )

    def _trusted_exe_dir(self, exe: str) -> bool:
        directory = os.path.dirname(exe)
        if not any(_is_under(exe, d) for d in self.trusted_dirs):
            return False
        cached = self._dir_cache.get(directory)
        if cached is None:
            cached = is_root_controlled_dir(
                directory, self.stat_fn, allow_wheel=self.os_name == "darwin"
            )
            self._dir_cache[directory] = cached
            if not cached:
                logger.debug("exe dir %s is not root-controlled; basename match refused", directory)
        return cached

    def _process_matches(self, pattern: str, exe: str) -> bool:
        if pattern.startswith("/"):
            return fnmatchcase(exe, pattern)
        if not self._trusted_exe_dir(exe):
            return False
        return fnmatchcase(os.path.basename(exe), pattern)

    def check(self, event: FileAccessEvent) -> Verdict:
        if not event.exe:
            return Verdict(False, None)
        exe = os.path.normpath(event.exe)
        path = os.path.normpath(event.path)
        for rule in self.rules:
            if not _path_matches(rule.path_pattern, path):
                continue
            if any(self._process_matches(p, exe) for p in rule.processes):
                return Verdict(True, rule.path_pattern)
        return Verdict(False, None)
