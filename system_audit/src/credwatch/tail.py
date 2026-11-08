"""Rotation-aware, truncation-aware file follower."""
from __future__ import annotations

import logging
import os
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import BinaryIO

logger = logging.getLogger(__name__)

MISSING_WARN_INTERVAL = 30.0
_CHUNK = 65536


def _open(path: Path) -> BinaryIO | None:
    try:
        return open(path, "rb")
    except FileNotFoundError:
        return None


def _decode(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


def _drain(fh: BinaryIO, buf: bytes) -> tuple[list[str], bytes]:
    """Read fh to EOF; return complete lines and the trailing partial bytes.

    Splits on b"\\n" only: audit ENRICHED lines contain 0x1d, which
    str.splitlines() would treat as a line break.
    """
    lines: list[str] = []
    while True:
        chunk = fh.read(_CHUNK)
        if not chunk:
            return lines, buf
        buf += chunk
        *complete, buf = buf.split(b"\n")
        lines.extend(_decode(c) for c in complete)


def _rotated(path: Path, fh: BinaryIO) -> bool:
    try:
        current = os.stat(path)
    except FileNotFoundError:
        return False
    opened = os.fstat(fh.fileno())
    return (current.st_ino, current.st_dev) != (opened.st_ino, opened.st_dev)


def follow(
    path: Path,
    stop: threading.Event,
    *,
    poll: float = 0.25,
    from_end: bool = True,
) -> Iterator[str]:
    """Yield complete lines appended to `path` until `stop` is set.

    Yields "" on every idle poll (nothing new, or file missing) so callers
    can run periodic work; a genuinely blank file line also yields "".
    """
    fh: BinaryIO | None = None
    buf = b""
    last_warn = 0.0
    seek_end = from_end
    try:
        while not stop.is_set():
            if fh is None:
                fh = _open(path)
                if fh is None:
                    seek_end = False  # appears after startup: read from the beginning
                    now = time.monotonic()
                    if last_warn == 0.0 or now - last_warn >= MISSING_WARN_INTERVAL:
                        logger.warning("audit log %s not found; retrying", path)
                        last_warn = now
                    yield ""
                    stop.wait(poll)
                    continue
                last_warn = 0.0
                if seek_end:
                    fh.seek(0, os.SEEK_END)
                seek_end = False
                buf = b""
            lines, buf = _drain(fh, buf)
            if lines:
                yield from lines
                continue
            if _rotated(path, fh):
                lines, buf = _drain(fh, buf)  # final drain of the old handle
                yield from lines
                if buf:
                    yield _decode(buf)
                fh.close()
                fh, buf = None, b""
                continue
            if os.fstat(fh.fileno()).st_size < fh.tell():
                logger.warning("%s truncated; restarting from offset 0", path)
                fh.seek(0)
                buf = b""
                continue
            yield ""
            stop.wait(poll)
    finally:
        if fh is not None:
            fh.close()
