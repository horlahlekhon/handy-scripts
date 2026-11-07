"""Allowlist matching: (path pattern, process names) rules, unioned."""
from __future__ import annotations

import os
from dataclasses import dataclass
from fnmatch import fnmatchcase

from credwatch.config import AllowRule
from credwatch.models import FileAccessEvent, Verdict

COMM_MAX_LEN = 15  # Linux truncates comm to 15 characters
_RECURSIVE_SUFFIX = "/**"


def _path_matches(pattern: str, path: str) -> bool:
    if pattern.endswith(_RECURSIVE_SUFFIX):
        base = pattern[: -len(_RECURSIVE_SUFFIX)]
        return path == base or path.startswith(base + "/")
    return fnmatchcase(path, pattern)


def _candidate_names(event: FileAccessEvent) -> tuple[tuple[str, ...], str | None]:
    """Return (exact names, truncated-comm fallback).

    comm is spoofable (prctl PR_SET_NAME), so it is only trusted when exe is unknown.
    """
    if event.exe:
        return (os.path.basename(event.exe),), None
    if event.comm:
        return (event.comm,), event.comm
    return (), None


def _process_matches(pattern: str, names: tuple[str, ...], comm: str | None) -> bool:
    if any(fnmatchcase(name, pattern) for name in names):
        return True
    return (
        comm is not None
        and len(comm) >= COMM_MAX_LEN
        and pattern.startswith(comm[:COMM_MAX_LEN])
    )


@dataclass(frozen=True)
class Allowlist:
    rules: tuple[AllowRule, ...]

    def check(self, event: FileAccessEvent) -> Verdict:
        names, comm = _candidate_names(event)
        if not names:
            return Verdict(False, None)
        for rule in self.rules:
            if not _path_matches(rule.path_pattern, event.path):
                continue
            if any(_process_matches(p, names, comm) for p in rule.processes):
                return Verdict(True, rule.path_pattern)
        return Verdict(False, None)
