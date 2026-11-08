"""Age-based file pruning."""
from __future__ import annotations

import logging
from datetime import datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)


def prune_old_files(
    directory: Path, pattern: str, older_than: timedelta, now: datetime
) -> tuple[Path, ...]:
    """Delete files matching `pattern` in `directory` whose mtime is older than the cutoff."""
    if not directory.is_dir():
        return ()
    cutoff = (now - older_than).timestamp()
    deleted: list[Path] = []
    for path in sorted(directory.glob(pattern)):
        try:
            if path.is_symlink() or not path.is_file() or path.stat().st_mtime >= cutoff:
                continue
            path.unlink()
        except OSError:
            logger.warning("could not prune %s", path, exc_info=True)
            continue
        logger.info("pruned old file %s", path)
        deleted.append(path)
    return tuple(deleted)
