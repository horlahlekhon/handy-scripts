import os
import threading
from pathlib import Path

from credwatch.tail import follow


def collect(gen, n):
    out = []
    for line in gen:
        if line:
            out.append(line)
        if len(out) == n:
            break
    return out


def append(path: Path, data: bytes) -> None:
    with open(path, "ab") as fh:
        fh.write(data)


def test_follow_survives_rotation_without_loss_or_dupes(tmp_path):
    log = tmp_path / "audit.log"
    append(log, b"a1\na2\na3\n")
    stop = threading.Event()
    gen = follow(log, stop, poll=0.01, from_end=False)
    got = [next(gen) for _ in range(3)]
    os.rename(log, tmp_path / "audit.log.1")
    append(tmp_path / "audit.log.1", b"a4\n")  # written to old file after rotation
    append(log, b"b1\nb2\n")
    got += collect(gen, 3)
    stop.set()
    assert got == ["a1", "a2", "a3", "a4", "b1", "b2"]


def test_follow_handles_truncation(tmp_path):
    log = tmp_path / "audit.log"
    append(log, b"one\ntwo\n")
    stop = threading.Event()
    gen = follow(log, stop, poll=0.01, from_end=False)
    assert collect(gen, 2) == ["one", "two"]
    log.write_bytes(b"x\n")
    assert collect(gen, 1) == ["x"]
    stop.set()


def test_follow_keeps_0x1d_inside_line(tmp_path):
    log = tmp_path / "audit.log"
    append(log, b"type=SYSCALL a=1\x1dUID=root\nnext\n")
    stop = threading.Event()
    got = collect(follow(log, stop, poll=0.01, from_end=False), 2)
    stop.set()
    assert got == ["type=SYSCALL a=1\x1dUID=root", "next"]


def test_follow_buffers_partial_line_until_newline(tmp_path):
    log = tmp_path / "audit.log"
    append(log, b"par")
    stop = threading.Event()
    gen = follow(log, stop, poll=0.01, from_end=False)
    assert next(gen) == ""  # idle, partial held back
    append(log, b"tial\n")
    assert collect(gen, 1) == ["partial"]
    stop.set()


def test_follow_from_end_skips_existing(tmp_path):
    log = tmp_path / "audit.log"
    append(log, b"old\n")
    stop = threading.Event()
    gen = follow(log, stop, poll=0.01)
    assert next(gen) == ""
    append(log, b"new\n")
    assert collect(gen, 1) == ["new"]
    stop.set()


def test_follow_missing_file_then_appears(tmp_path, caplog):
    log = tmp_path / "audit.log"
    stop = threading.Event()
    gen = follow(log, stop, poll=0.01, from_end=False)
    assert next(gen) == ""
    assert "not found" in caplog.text
    append(log, b"hi\n")
    assert collect(gen, 1) == ["hi"]
    stop.set()


def test_follow_replaces_invalid_utf8(tmp_path):
    log = tmp_path / "audit.log"
    append(log, b"bad\xff\n")
    stop = threading.Event()
    assert collect(follow(log, stop, poll=0.01, from_end=False), 1) == ["bad�"]
    stop.set()


def test_follow_reads_late_appearing_file_from_start_even_with_from_end(tmp_path):
    log = tmp_path / "audit.log"
    stop = threading.Event()
    gen = follow(log, stop, poll=0.01)  # from_end=True, file missing at startup
    assert next(gen) == ""
    append(log, b"first\nsecond\n")
    assert collect(gen, 2) == ["first", "second"]
    stop.set()
