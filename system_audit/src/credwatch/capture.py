"""Rotating tcpdump capture supervisor."""
from __future__ import annotations

import logging
import os
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path

from credwatch.config import CaptureConfig

logger = logging.getLogger(__name__)

PCAP_GLOB = "credwatch-*.pcap"
STDERR_TAIL_BYTES = 2048
BACKOFF_BASE_SECONDS = 1
BACKOFF_MAX_SECONDS = 300
BACKOFF_RESET_UPTIME_SECONDS = 600
SLEEP_SLICE_SECONDS = 1.0
POLL_INTERVAL_SECONDS = 0.2
PCAP_UMASK = 0o077


def build_tcpdump_argv(cfg: CaptureConfig, out_dir: Path) -> list[str]:
    return [
        "tcpdump", "-i", cfg.interface, "-n", "-s", str(cfg.snaplen),
        "-G", str(cfg.rotate_seconds), "-Z", "root",
        "-w", str(out_dir / "credwatch-%Y%m%d-%H%M%S.pcap"),
    ]


def _list_captures(out_dir: Path) -> list[Path]:
    if not out_dir.is_dir():
        return []
    return [p for p in sorted(out_dir.glob(PCAP_GLOB)) if not p.is_symlink() and p.is_file()]


def prune_captures(out_dir: Path, keep: int) -> tuple[Path, ...]:
    """Delete the oldest captures beyond `keep`; the newest file is never deleted."""
    files = _list_captures(out_dir)
    doomed = files[: max(len(files) - max(keep, 1), 0)]
    deleted: list[Path] = []
    for path in doomed:
        try:
            path.unlink()
        except OSError:
            logger.warning("could not prune capture %s", path, exc_info=True)
            continue
        logger.info("pruned capture %s", path)
        deleted.append(path)
    return tuple(deleted)


@dataclass(frozen=True)
class CaptureStatus:
    running: bool
    restarts: int
    last_error: str | None
    newest_file: Path | None


def _restrict_umask() -> None:
    os.umask(PCAP_UMASK)


def _read_tail(stderr_file) -> str:
    try:
        stderr_file.flush()
        size = stderr_file.seek(0, os.SEEK_END)
        stderr_file.seek(max(size - STDERR_TAIL_BYTES, 0))
        return stderr_file.read().decode("utf-8", errors="replace")
    except (OSError, ValueError):
        logger.warning("could not read tcpdump stderr", exc_info=True)
        return ""


class CaptureSupervisor:
    def __init__(
        self,
        cfg: CaptureConfig,
        out_dir: Path,
        *,
        popen=subprocess.Popen,
        on_failure: Callable[[str], None],
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._cfg = cfg
        self._out_dir = out_dir
        self._popen = popen
        self._on_failure = on_failure
        self._sleep = sleep
        self._clock = clock
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._proc = None
        self._status = CaptureStatus(False, 0, None, None)

    def start(self) -> None:
        if not self._cfg.enabled:
            logger.info("packet capture disabled; not starting tcpdump")
            return
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._run, name="credwatch-capture", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10) -> None:
        self._stop.set()
        with self._lock:
            proc = self._proc
        if proc is not None:
            try:
                proc.terminate()
            except OSError:
                logger.warning("could not terminate tcpdump", exc_info=True)
        thread = self._thread
        if thread is not None:
            thread.join(timeout)
            if thread.is_alive() and proc is not None:
                try:
                    proc.kill()
                except OSError:
                    logger.warning("could not kill tcpdump", exc_info=True)
                thread.join(timeout)
        self._update(running=False)

    def status(self) -> CaptureStatus:
        with self._lock:
            status = self._status
        files = _list_captures(self._out_dir)
        return replace(status, newest_file=files[-1] if files else None)

    def _update(self, **changes) -> None:
        with self._lock:
            self._status = replace(self._status, **changes)

    def _prune(self) -> None:
        prune_captures(self._out_dir, self._cfg.retain_files)

    def _run(self) -> None:
        failures = 0
        self._prune()
        while not self._stop.is_set():
            started = self._clock()
            error = self._run_once()
            if self._stop.is_set():
                break
            if self._clock() - started >= BACKOFF_RESET_UPTIME_SECONDS:
                failures = 0
            delay = min(BACKOFF_BASE_SECONDS * 2**failures, BACKOFF_MAX_SECONDS)
            failures += 1
            self._update(running=False, last_error=error)
            self._safe_on_failure(error)
            self._backoff(delay)
            if self._stop.is_set():
                break
            self._update(restarts=self._status.restarts + 1)

    def _safe_on_failure(self, message: str) -> None:
        try:
            self._on_failure(message)
        except Exception:
            logger.exception("capture on_failure callback raised")

    def _backoff(self, delay: float) -> None:
        remaining = delay
        while remaining > 0 and not self._stop.is_set():
            chunk = min(remaining, SLEEP_SLICE_SECONDS)
            self._sleep(chunk)
            remaining -= chunk

    def _run_once(self) -> str:
        """Run tcpdump until it exits or stop is requested; return the stderr tail."""
        argv = build_tcpdump_argv(self._cfg, self._out_dir)
        with tempfile.TemporaryFile() as stderr_file:
            try:
                proc = self._popen(
                    argv, stdout=subprocess.DEVNULL, stderr=stderr_file,
                    preexec_fn=_restrict_umask,
                )
            except OSError as exc:
                logger.error("failed to spawn tcpdump: %s", exc)
                return f"spawn failed: {exc}"
            with self._lock:
                self._proc = proc
                self._status = replace(self._status, running=True)
            logger.info("tcpdump started: %s", " ".join(argv))
            last_prune = self._clock()
            while proc.poll() is None and not self._stop.is_set():
                if self._clock() - last_prune >= self._cfg.rotate_seconds:
                    self._prune()
                    last_prune = self._clock()
                self._stop.wait(POLL_INTERVAL_SECONDS)
            code = proc.poll()
            with self._lock:
                self._proc = None
            if self._stop.is_set():
                return ""
            tail = _read_tail(stderr_file)
            logger.warning("tcpdump exited with code %s", code)
            return tail or f"tcpdump exited with code {code}"
