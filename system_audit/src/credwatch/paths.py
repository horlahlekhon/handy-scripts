"""Watched-path discovery: default sensitive paths, .env scan, matching, watch-list file io."""
from __future__ import annotations

import logging
import os
import tempfile
from collections.abc import Iterable
from pathlib import Path

from credwatch.config import Config, EnvScanConfig

logger = logging.getLogger(__name__)

DEFAULT_SENSITIVE_PATHS: tuple[str, ...] = (
    "~/.aws/credentials",
    "~/.aws/config",
    "~/.ssh",
    "~/.config/gh/hosts.yml",
    "~/.config/gcloud/credentials.db",
    "~/.config/gcloud/legacy_credentials",
    "~/.docker/config.json",
    "~/.kube/config",
    "~/.npmrc",
    "~/.pypirc",
    "~/.netrc",
    "~/.gnupg",
    "~/.config/op",
    "~/.terraform.d/credentials.tfrc.json",
    "~/.azure/accessTokens.json",
    "~/.config/doctl",
)


def _expand_home(text: str, home: Path) -> Path:
    if text == "~":
        return home
    if text.startswith("~/"):
        return home / text[2:]
    return Path(text)


_LINE_BREAKS = frozenset("\x85\u2028\u2029")


def has_control_chars(text: str) -> bool:
    """True if text could break a line-oriented rule file (newline, NUL, DEL, Unicode breaks)."""
    return any(ord(c) < 0x20 or ord(c) == 0x7F or c in _LINE_BREAKS for c in text)


def _is_safe(path: Path | str) -> bool:
    if has_control_chars(str(path)):
        logger.warning("skipping path with control characters: %r", str(path))
        return False
    return True


def _log_walk_error(exc: OSError) -> None:
    logger.warning("env scan: cannot read directory %s: %s", exc.filename, exc.strerror)


def scan_env_files(cfg: EnvScanConfig) -> tuple[Path, ...]:
    found: set[Path] = set()
    for root in cfg.roots:
        root_str = str(root)
        for dirpath, dirnames, filenames in os.walk(
            root_str, followlinks=False, onerror=_log_walk_error
        ):
            rel = os.path.relpath(dirpath, root_str)
            depth = 0 if rel == "." else rel.count(os.sep) + 1
            # In-place pruning is how os.walk is steered.
            dirnames[:] = [] if depth >= cfg.max_depth else [
                d for d in dirnames if d not in cfg.excludes
            ]
            for f in filenames:
                candidate = Path(dirpath) / f
                if f.startswith(".env") and _is_safe(candidate):
                    found.add(candidate)
    return tuple(sorted(found))


def _resolve(path: Path) -> Path | None:
    try:
        return path.resolve()
    except (OSError, RuntimeError) as exc:
        logger.warning("cannot resolve %s (%s); watching link path only", path, exc)
        return None


def _is_home_or_ancestor(path: Path, homes: tuple[Path, ...]) -> bool:
    return any(path == h or path in h.parents for h in homes)


def _is_strictly_inside(path: Path, homes: tuple[Path, ...]) -> bool:
    return any(path != h and h in path.parents for h in homes)


def _with_resolved(path: Path, homes: tuple[Path, ...]) -> tuple[Path, ...]:
    full = _resolve(path)
    if full is None or full == path:
        return (path,)
    if not os.path.lexists(full):
        logger.warning("dangling symlink %s -> %s; watching link only", path, full)
        return (path,)
    if not _is_strictly_inside(full, homes) or not _is_safe(full):
        logger.warning("symlink %s resolves outside home to %s; not watching target", path, full)
        return (path,)
    return (path, full)


def resolve_watch_paths(cfg: Config) -> tuple[Path, ...]:
    homes = tuple({cfg.home, _resolve(cfg.home) or cfg.home})
    defaults = (_expand_home(p, cfg.home) for p in DEFAULT_SENSITIVE_PATHS)
    candidates = (
        *defaults,
        *cfg.extra_paths,
        *scan_env_files(cfg.env_scan),
        cfg.data_dir / "canary",
    )
    existing = {p for p in candidates if _is_safe(p) and os.path.lexists(p)}
    expanded = {q for p in existing for q in _with_resolved(p, homes)}
    allowed = {p for p in expanded if not _is_home_or_ancestor(p, homes)}
    dirs = {p for p in allowed if p.is_dir()}
    kept = {p for p in allowed if not any(d != p and d in p.parents for d in dirs)}
    return tuple(sorted(kept))


class WatchMatcher:
    def __init__(self, paths: Iterable[Path], case_insensitive: bool = False) -> None:
        self._fold = case_insensitive
        normalized = tuple(self._norm(str(p)) for p in paths)
        self._exact = frozenset(normalized)
        self._prefixes = tuple(n.rstrip(os.sep) + os.sep for n in normalized)

    def _norm(self, path: str) -> str:
        normed = os.path.normpath(path)
        return normed.casefold() if self._fold else normed

    def matches(self, path: str) -> bool:
        normed = self._norm(path)
        return normed in self._exact or normed.startswith(self._prefixes)


def write_watch_list(paths: Iterable[Path], dest: Path) -> None:
    materialized = tuple(paths)
    for p in materialized:
        if has_control_chars(str(p)):
            raise ValueError(f"watch path contains control characters: {str(p)!r}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=dest.parent, prefix=f".{dest.name}.")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write("".join(f"{p}\n" for p in materialized))
        os.replace(tmp_name, dest)
    except BaseException:
        logger.exception("failed writing watch list %s", dest)
        Path(tmp_name).unlink(missing_ok=True)
        raise


def read_watch_list(src: Path) -> tuple[Path, ...]:
    return tuple(Path(line) for line in src.read_text().split("\n") if line)
