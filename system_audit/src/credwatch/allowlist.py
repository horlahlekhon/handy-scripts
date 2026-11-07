"""Allowlist matching: (path pattern, process names) rules, unioned.

Process identity comes from the resolved exe only (comm and basenames of
untrusted locations are spoofable), and fails closed when exe is unknown.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass
from fnmatch import fnmatchcase
from functools import lru_cache

from credwatch.config import AllowRule
from credwatch.models import FileAccessEvent, Verdict

_RECURSIVE_SUFFIX = "/**"


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


@dataclass(frozen=True)
class Allowlist:
    rules: tuple[AllowRule, ...]
    trusted_dirs: tuple[str, ...] = ()

    def _process_matches(self, pattern: str, exe: str) -> bool:
        if pattern.startswith("/"):
            return fnmatchcase(exe, pattern)
        if not any(_is_under(exe, d) for d in self.trusted_dirs):
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
