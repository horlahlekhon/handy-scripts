from __future__ import annotations

import logging
import stat
from logging.handlers import RotatingFileHandler

import pytest

from credwatch import logging_setup


@pytest.fixture
def clean_root():
    root = logging.getLogger()
    handlers, level = list(root.handlers), root.level
    yield root
    for h in [h for h in root.handlers if h not in handlers]:
        root.removeHandler(h)
        h.close()
    root.setLevel(level)


def _ours(root):
    return [h for h in root.handlers if getattr(h, logging_setup._MARKER, False)]


def test_configure_adds_private_rotating_file_and_stderr(tmp_path, clean_root):
    log_dir = tmp_path / "data" / "logs"

    logging_setup.configure(log_dir, level=logging.DEBUG)
    logging.getLogger("credwatch.test").warning("hello log")

    ours = _ours(clean_root)
    files = [h for h in ours if isinstance(h, RotatingFileHandler)]
    assert len(ours) == 2 and len(files) == 1
    assert files[0].maxBytes == 10 * 1024 * 1024 and files[0].backupCount == 5
    files[0].flush()
    log_file = log_dir / "credwatch.log"
    assert "hello log" in log_file.read_text()
    assert stat.S_IMODE(log_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(log_dir.stat().st_mode) == 0o700
    assert clean_root.level == logging.DEBUG


def test_configure_twice_replaces_handlers(tmp_path, clean_root):
    logging_setup.configure(tmp_path / "logs")
    logging_setup.configure(tmp_path / "logs")

    assert len(_ours(clean_root)) == 2


def test_configure_refuses_symlinked_log_file(tmp_path, clean_root):
    log_dir = tmp_path / "logs"
    log_dir.mkdir(mode=0o700)
    (log_dir / "credwatch.log").symlink_to(tmp_path / "elsewhere")

    with pytest.raises(OSError):
        logging_setup.configure(log_dir)
