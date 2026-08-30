"""Storage backend interface and errors."""

from __future__ import annotations

import abc

from ..records import AuditRecord


class BackendError(Exception):
    """Base class for storage errors."""


class LogCorruptedError(BackendError):
    """Raised when stored records cannot be parsed (e.g. a truncated JSON line)."""


class StorageBackend(abc.ABC):
    """Append-only storage for audit records."""

    @abc.abstractmethod
    async def init(self) -> None:
        """Create the storage (file, table, ...) if needed."""

    @abc.abstractmethod
    async def append(self, record: AuditRecord) -> None:
        """Append a single record. Must not rewrite existing data."""

    @abc.abstractmethod
    async def load(self) -> list[AuditRecord]:
        """Load all records in order."""

    @abc.abstractmethod
    async def close(self) -> None:
        """Release resources."""
