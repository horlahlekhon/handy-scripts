"""Backend abstract base class."""
from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path

from credwatch.models import FileAccessEvent


class BackendError(Exception):
    """Raised when a backend cannot start or has failed."""


class Backend(ABC):
    name: str

    @abstractmethod
    def events(self, stop: threading.Event) -> Iterator[FileAccessEvent]:
        """Yield file access events until `stop` is set."""

    @abstractmethod
    def export_native_log(self, dest_dir: Path) -> Path | None:
        """Copy the relevant native audit log into dest_dir; None if unavailable."""

    @abstractmethod
    def health(self) -> tuple[str, ...]:
        """Problem descriptions; empty when healthy."""
