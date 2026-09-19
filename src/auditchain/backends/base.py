"""Storage backend interface and errors."""

from __future__ import annotations

import abc
from collections.abc import Sequence

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

    async def append_many(self, records: Sequence[AuditRecord]) -> None:
        """Append several records. Default implementation appends one by one;
        backends override this with an atomic batch write where possible."""
        for record in records:
            await self.append(record)

    @abc.abstractmethod
    async def load(self) -> list[AuditRecord]:
        """Load all records in order."""

    async def load_last(self) -> AuditRecord | None:
        """Load only the last record, or None for an empty log.

        Writers sharing a log use this to chain onto the real tail instead of a stale
        cached one; backends override it with an O(1) read where they can.
        """
        records = await self.load()
        return records[-1] if records else None

    @abc.abstractmethod
    async def close(self) -> None:
        """Release resources."""
