"""Root logging: a private rotating file in the data dir's logs/ plus stderr (journal/launchd)."""
from __future__ import annotations

import logging
import os
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path

from credwatch.safe_fs import open_dir_chain

LOG_FILENAME = "credwatch.log"
LOG_MAX_BYTES = 10 * 1024 * 1024
LOG_BACKUP_COUNT = 5
LOG_DIR_MODE = 0o700
LOG_FILE_MODE = 0o600
LOG_FORMAT = "%(asctime)s %(levelname)s %(threadName)s %(name)s: %(message)s"
_MARKER = "_credwatch_handler"


class _PrivateRotatingFileHandler(RotatingFileHandler):
    """Creates the log (and each rotated successor) 0600 without following symlinks."""

    def _open(self):
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC
        fd = os.open(self.baseFilename, flags, LOG_FILE_MODE)
        return os.fdopen(fd, "a", encoding=self.encoding, errors=self.errors)


def configure(log_dir: Path, level: int = logging.INFO) -> None:
    """Install credwatch's handlers on the root logger; calling again replaces them."""
    os.close(open_dir_chain(Path(log_dir), create_mode=LOG_DIR_MODE))
    root = logging.getLogger()
    for handler in [h for h in root.handlers if getattr(h, _MARKER, False)]:
        root.removeHandler(handler)
        handler.close()
    formatter = logging.Formatter(LOG_FORMAT)
    file_handler = _PrivateRotatingFileHandler(
        Path(log_dir) / LOG_FILENAME, maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT, encoding="utf-8",
    )
    stderr_handler = logging.StreamHandler(sys.stderr)
    for handler in (file_handler, stderr_handler):
        handler.setFormatter(formatter)
        setattr(handler, _MARKER, True)
        root.addHandler(handler)
    root.setLevel(level)
