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
            found.update(Path(dirpath) / f for f in filenames if f.startswith(".env"))
    return tuple(sorted(found))


def _exists(path: Path) -> bool:
    return os.path.lexists(path)


def _expand_symlink(path: Path) -> tuple[Path, ...]:
    if not path.is_symlink():
        return (path,)
    target = path.resolve()
    if not target.exists():
        logger.warning("dangling symlink %s -> %s; watching link only", path, target)
        return (path,)
    return (path, target)


def resolve_watch_paths(cfg: Config) -> tuple[Path, ...]:
    defaults = (_expand_home(p, cfg.home) for p in DEFAULT_SENSITIVE_PATHS)
    candidates = (
        *defaults,
        *cfg.extra_paths,
        *scan_env_files(cfg.env_scan),
        cfg.data_dir / "canary",
    )
    existing = {p for p in candidates if _exists(p)}
    expanded = {q for p in existing for q in _expand_symlink(p)}
    dirs = {p for p in expanded if p.is_dir()}
    kept = {p for p in expanded if not any(d != p and d in p.parents for d in dirs)}
    return tuple(sorted(kept))


class WatchMatcher:
    def __init__(self, paths: Iterable[Path]) -> None:
        stripped = tuple(str(p).rstrip(os.sep) for p in paths)
        self._exact = frozenset(stripped)
        self._prefixes = tuple(s + os.sep for s in stripped)

    def matches(self, path: str) -> bool:
        return path in self._exact or path.startswith(self._prefixes)


def write_watch_list(paths: Iterable[Path], dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=dest.parent, prefix=f".{dest.name}.")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write("".join(f"{p}\n" for p in paths))
        os.replace(tmp_name, dest)
    except BaseException:
        logger.exception("failed writing watch list %s", dest)
        Path(tmp_name).unlink(missing_ok=True)
        raise


def read_watch_list(src: Path) -> tuple[Path, ...]:
    return tuple(Path(line) for line in src.read_text().splitlines() if line)
