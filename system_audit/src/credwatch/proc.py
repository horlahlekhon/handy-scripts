"""Injectable external-command runner so tests never need root."""
from __future__ import annotations

import logging
import subprocess
from collections.abc import Sequence
from typing import Protocol

logger = logging.getLogger(__name__)


class Runner(Protocol):
    def run(
        self,
        argv: Sequence[str],
        *,
        check: bool = False,
        timeout: float | None = 60,
    ) -> subprocess.CompletedProcess[str]: ...


class SubprocessRunner:
    def run(
        self,
        argv: Sequence[str],
        *,
        check: bool = False,
        timeout: float | None = 60,
    ) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            list(argv), text=True, capture_output=True, check=check, timeout=timeout
        )
        logger.debug("ran %s -> rc=%d", list(argv), result.returncode)
        return result
