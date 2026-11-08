"""Rotating tcpdump capture supervisor."""
from __future__ import annotations

import logging
import os
import pwd
import stat as stat_mod
import subprocess
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from credwatch.config import CaptureConfig

logger = logging.getLogger(__name__)

PCAP_FILENAME_PATTERN = "credwatch-%Y%m%d-%H%M%S.pcap"
PCAP_GLOB = "credwatch-*.pcap"
STDERR_TAIL_BYTES = 2048
BACKOFF_BASE_SECONDS = 1
BACKOFF_MAX_SECONDS = 300
BACKOFF_RESET_UPTIME_SECONDS = 600
SLEEP_SLICE_SECONDS = 1.0
POLL_INTERVAL_SECONDS = 0.2
PCAP_UMASK = 0o077
CAPTURE_DIR_MODE = 0o700
TERMINATE_WAIT_SECONDS = 5
MAX_BACKOFF_EXPONENT = 10
ROOT_USER = "root"


def build_tcpdump_argv(cfg: CaptureConfig, out_dir: Path) -> list[str]:
    return [
        "tcpdump", "-i", cfg.interface, "-n", "-s", str(cfg.snaplen),
        "-G", str(cfg.rotate_seconds), "-Z", cfg.drop_privileges_to,
        "-w", str(out_dir / PCAP_FILENAME_PATTERN),
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
        getpwnam=pwd.getpwnam,
        stat_fn=os.stat,
    ) -> None:
        self._cfg = cfg
        self._out_dir = out_dir
        self._popen = popen
        self._on_failure = on_failure
        self._sleep = sleep
        self._clock = clock
        self._getpwnam = getpwnam
        self._stat = stat_fn
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._proc = None
        self._last_prune = clock()
        self._restarts = 0
        self._last_error: str | None = None

    def start(self) -> None:
        if not self._cfg.enabled:
            logger.info("packet capture disabled; not starting tcpdump")
            return
        if self._thread is not None:
            return
        problem = self._check_privilege_drop()
        if problem is not None:
            logger.error("capture not started: %s", problem)
            self._last_error = problem
            self._safe_on_failure(problem)
            return
        self._thread = threading.Thread(target=self._run, name="credwatch-capture", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 10) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout)

    def status(self) -> CaptureStatus:
        with self._lock:
            proc = self._proc
        running = proc is not None and proc.poll() is None
        files = _list_captures(self._out_dir)
        return CaptureStatus(running, self._restarts, self._last_error, files[-1] if files else None)

    def _check_privilege_drop(self) -> str | None:
        user = self._cfg.drop_privileges_to
        if user == ROOT_USER:
            return None
        message = (
            f"captures dir must be owned by {user} mode 0700; re-run credwatch install"
        )
        try:
            uid = self._getpwnam(user).pw_uid
        except KeyError:
            return f"capture user {user!r} does not exist; {message}"
        try:
            st = self._stat(self._out_dir)
        except OSError as exc:
            return f"cannot stat {self._out_dir} ({exc}); {message}"
        if st.st_uid != uid or stat_mod.S_IMODE(st.st_mode) != CAPTURE_DIR_MODE:
            return message
        return None

    def _prune(self) -> None:
        prune_captures(self._out_dir, self._cfg.retain_files)
        self._last_prune = self._clock()

    def _run(self) -> None:
        failures = 0
        self._guarded(self._prune)
        while not self._stop.is_set():
            started = self._clock()
            try:
                error = self._run_once()
            except Exception as exc:
                logger.exception("capture supervisor iteration failed")
                error = f"supervisor error: {exc!r}"
            if self._stop.is_set():
                break
            if self._clock() - started >= BACKOFF_RESET_UPTIME_SECONDS:
                failures = 0
            delay = min(BACKOFF_BASE_SECONDS * 2 ** min(failures, MAX_BACKOFF_EXPONENT), BACKOFF_MAX_SECONDS)
            failures += 1
            self._last_error = error
            self._safe_on_failure(error)
            self._backoff(delay)
            if self._stop.is_set():
                break
            self._restarts += 1

    @staticmethod
    def _guarded(fn: Callable[[], None]) -> None:
        try:
            fn()
        except Exception:
            logger.exception("capture housekeeping failed")

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
                    argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=stderr_file, umask=PCAP_UMASK,
                )
            except OSError as exc:
                logger.error("failed to spawn tcpdump: %s", exc)
                return f"spawn failed: {exc}"
            with self._lock:
                self._proc = proc
            try:
                if self._stop.is_set():
                    return ""
                logger.info("tcpdump started: %s", " ".join(argv))
                while proc.poll() is None and not self._stop.is_set():
                    if self._clock() - self._last_prune >= self._cfg.rotate_seconds:
                        self._guarded(self._prune)
                    self._stop.wait(POLL_INTERVAL_SECONDS)
                code = proc.poll()
                if self._stop.is_set():
                    return ""
                tail = _read_tail(stderr_file)
                logger.warning("tcpdump exited with code %s", code)
                return tail or f"tcpdump exited with code {code}"
            finally:
                self._reap(proc)
                with self._lock:
                    self._proc = None

    @staticmethod
    def _reap(proc) -> None:
        """Ensure the child is gone: terminate, then kill if it ignores SIGTERM."""
        if proc.poll() is not None:
            return
        try:
            proc.terminate()
            proc.wait(timeout=TERMINATE_WAIT_SECONDS)
        except subprocess.TimeoutExpired:
            logger.warning("tcpdump ignored terminate; killing")
            proc.kill()
            proc.wait()
        except OSError:
            logger.warning("could not terminate tcpdump", exc_info=True)
