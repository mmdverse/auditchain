"""Thin synchronous wrappers around :class:`auditchain.AuditLog`.

Each call runs its own event loop (``asyncio.run``). Do not use these from code
that already runs inside an event loop; use the async API there.
"""

from __future__ import annotations

import asyncio
from typing import Any

from .backends import StorageBackend
from .log import AuditLog
from .records import AuditRecord
from .verify import VerifyReport


class SyncAuditLog:
    """Synchronous facade over :class:`AuditLog`."""

    def __init__(self, backend: StorageBackend, *, seal_key: bytes | None = None) -> None:
        self._log = AuditLog(backend, seal_key=seal_key)
        asyncio.run(self._log.init())

    def append(
        self,
        actor: str,
        action: str,
        subject: str = "",
        *,
        metadata: dict[str, Any] | None = None,
        timestamp: str | None = None,
    ) -> AuditRecord:
        return asyncio.run(
            self._log.append(actor, action, subject, metadata=metadata, timestamp=timestamp)
        )

    def read(self) -> list[AuditRecord]:
        return asyncio.run(self._log.read())

    def verify(self, *, expected_count: int | None = None) -> VerifyReport:
        return asyncio.run(self._log.verify(expected_count=expected_count))

    def close(self) -> None:
        asyncio.run(self._log.close())
