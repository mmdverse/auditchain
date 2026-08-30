"""In-memory backend (mainly useful for tests and short-lived processes)."""

from __future__ import annotations

from ..records import AuditRecord
from .base import StorageBackend


class MemoryBackend(StorageBackend):
    """Keeps records in a list. Nothing survives process exit."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    async def init(self) -> None:
        return None

    async def append(self, record: AuditRecord) -> None:
        self._records.append(record)

    async def load(self) -> list[AuditRecord]:
        return list(self._records)

    async def close(self) -> None:
        return None
