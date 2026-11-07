import os
import stat
import sys

import pytest

from credwatch.safe_fs import UnsafePathError, open_dir_chain


def test_creates_missing_dirs_0700(tmp_path):
    target = tmp_path / "a" / "b" / "c"
    fd = open_dir_chain(target)
    os.close(fd)
    for d in (tmp_path / "a", tmp_path / "a" / "b", target):
        assert stat.S_IMODE(d.stat().st_mode) == 0o700


def test_symlinked_ancestor_rejected(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    with pytest.raises(UnsafePathError, match="link"):
        open_dir_chain(tmp_path / "link" / "sub" / "deep")
    assert list(real.iterdir()) == []


def test_symlinked_final_component_rejected(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    with pytest.raises(UnsafePathError):
        open_dir_chain(tmp_path / "link")


def test_existing_group_writable_dir_rejected(tmp_path):
    d = tmp_path / "loose"
    d.mkdir()
    d.chmod(0o775)
    with pytest.raises(UnsafePathError, match="writable"):
        open_dir_chain(d)
    assert stat.S_IMODE(d.stat().st_mode) == 0o775


def test_existing_tight_dir_accepted_unchanged(tmp_path):
    d = tmp_path / "ok"
    d.mkdir()
    d.chmod(0o755)
    os.close(open_dir_chain(d))
    assert stat.S_IMODE(d.stat().st_mode) == 0o755


def test_relative_path_rejected(tmp_path):
    from pathlib import Path
    with pytest.raises(ValueError):
        open_dir_chain(Path("relative/dir"))


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs /proc/self/fd")
def test_fds_closed_on_error(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    (tmp_path / "link").symlink_to(real)
    before = len(os.listdir("/proc/self/fd"))
    for _ in range(3):
        with pytest.raises(UnsafePathError):
            open_dir_chain(tmp_path / "link" / "x")
    assert len(os.listdir("/proc/self/fd")) == before
