"""Watched-path discovery: default sensitive paths, .env scan, matching, watch-list file io."""
from __future__ import annotations

import logging
import os
import tempfile
import unicodedata
from collections.abc import Iterable, Set
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


def scan_env_files(
    cfg: EnvScanConfig, watched_dirs: Set[Path] = frozenset()
) -> tuple[Path, ...]:
    """Find `.env*` files under the scan roots.

    `watched_dirs` are never opened: they already carry a directory watch, so
    descending into them (as root, at install time) would audit our own scan
    and alert on it. Their contents are covered by that watch anyway.
    """
    found: set[Path] = set()
    for root in cfg.roots:
        root_str = str(root)
        if Path(root_str) in watched_dirs:
            logger.info("env scan: root %s is a watched directory; not scanning it", root_str)
            continue
        for dirpath, dirnames, filenames in os.walk(
            root_str, followlinks=False, onerror=_log_walk_error
        ):
            rel = os.path.relpath(dirpath, root_str)
            depth = 0 if rel == "." else rel.count(os.sep) + 1
            # In-place pruning is how os.walk is steered.
            dirnames[:] = [] if depth >= cfg.max_depth else [
                d for d in dirnames
                if d not in cfg.excludes and Path(dirpath, d) not in watched_dirs
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


def _with_resolved(path: Path, homes: tuple[Path, ...]) -> tuple[tuple[Path, ...], Path | None]:
    """Return (paths to watch, symlink target skipped as outside home/unsafe or None)."""
    full = _resolve(path)
    if full is None or full == path:
        return (path,), None
    if not os.path.lexists(full):
        logger.warning("dangling symlink %s -> %s; watching link only", path, full)
        return (path,), None
    if not _is_strictly_inside(full, homes) or not _is_safe(full):
        logger.warning("symlink %s resolves outside home to %s; not watching target", path, full)
        return (path,), full
    return (path, full), None


SkippedTarget = tuple[Path, Path]


def _watched_dirs(static: tuple[Path, ...], homes: tuple[Path, ...]) -> frozenset[Path]:
    """Directories that will carry a watch (link and resolved form): the env scan skips them."""
    dirs = {
        q
        for p in static
        if _is_safe(p) and os.path.isdir(p)
        for q in (p, _resolve(p) or p)
    }
    return frozenset(d for d in dirs if not _is_home_or_ancestor(d, homes))


def resolve_watch_paths_report(cfg: Config) -> tuple[tuple[Path, ...], tuple[SkippedTarget, ...]]:
    """Watch paths plus (link, target) pairs whose target was not watched (outside home/unsafe)."""
    homes = tuple({cfg.home, _resolve(cfg.home) or cfg.home})
    static = (*(_expand_home(p, cfg.home) for p in DEFAULT_SENSITIVE_PATHS), *cfg.extra_paths)
    candidates = (
        *static,
        *scan_env_files(cfg.env_scan, _watched_dirs(static, homes)),
        cfg.data_dir / "canary",
    )
    existing = {p for p in candidates if _is_safe(p) and os.path.lexists(p)}
    resolved = {p: _with_resolved(p, homes) for p in existing}
    expanded = {q for watched, _ in resolved.values() for q in watched}
    allowed = {p for p in expanded if not _is_home_or_ancestor(p, homes)}
    dirs = {p for p in allowed if p.is_dir()}
    kept = {p for p in allowed if not any(d != p and d in p.parents for d in dirs)}
    skipped = tuple(sorted((p, t) for p, (_, t) in resolved.items() if t is not None))
    return tuple(sorted(kept)), skipped


def resolve_watch_paths(cfg: Config) -> tuple[Path, ...]:
    return resolve_watch_paths_report(cfg)[0]


class WatchMatcher:
    def __init__(self, paths: Iterable[Path], case_insensitive: bool = False) -> None:
        self._fold = case_insensitive
        lexical = tuple(_lexical(str(p)) for p in paths)
        self._display = tuple(sorted(set(lexical)))
        normalized = tuple(self._norm(p) for p in lexical)
        self._exact = frozenset(normalized)
        self._prefixes = tuple(n.rstrip(os.sep) + os.sep for n in normalized)

    def _norm(self, path: str) -> str:
        """NFC + normpath, then casefold (re-NFC'd) if insensitive.

        NFC: APFS treats NFC and NFD spellings of a name as the same file, and NFC
        only merges canonically equivalent spellings, so ASCII paths are unaffected.
        """
        normed = _lexical(path)
        return unicodedata.normalize("NFC", normed.casefold()) if self._fold else normed

    def normalize(self, path: str) -> str:
        """`path` in the form matches() compares (and normalized_watch_paths() returns)."""
        return self._norm(path)

    def matches(self, path: str) -> bool:
        normed = self._norm(path)
        return normed in self._exact or normed.startswith(self._prefixes)

    @property
    def case_insensitive(self) -> bool:
        return self._fold

    def normalized_watch_paths(self) -> tuple[str, ...]:
        """The watched paths as matches() compares them: normpath'd, NFC, casefolded if insensitive."""
        return tuple(sorted(self._exact))

    def watch_paths(self) -> tuple[str, ...]:
        """The watched paths normpath'd and NFC'd, original case kept (for reporting)."""
        return self._display


def _lexical(path: str) -> str:
    return unicodedata.normalize("NFC", os.path.normpath(path))


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
