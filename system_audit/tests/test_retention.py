import os
from datetime import datetime, timedelta, timezone

from credwatch.retention import prune_old_files


def test_prune_old_files_keeps_recent(tmp_path):
    now = datetime(2026, 1, 31, tzinfo=timezone.utc)
    old, recent, other = (tmp_path / n for n in ("a-old.txt", "b-new.txt", "c-old.log"))
    for f, age in ((old, 40), (recent, 1), (other, 40)):
        f.write_text("x")
        ts = (now - timedelta(days=age)).timestamp()
        os.utime(f, (ts, ts))
    deleted = prune_old_files(tmp_path, "*.txt", timedelta(days=30), now)
    assert deleted == (old,)
    assert not old.exists() and recent.exists() and other.exists()


def test_prune_missing_directory_is_noop(tmp_path):
    now = datetime(2026, 1, 31, tzinfo=timezone.utc)
    assert prune_old_files(tmp_path / "nope", "*", timedelta(days=1), now) == ()
