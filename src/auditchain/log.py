"""Async audit log API: append, read and verify."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

from .backends import StorageBackend
from .hash import compute_record_hash
from .records import GENESIS_HASH, AuditRecord
from .verify import VerifyReport

_MIN_KEY_LENGTH = 16


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class AuditLog:
    """A single-writer, hash-chained audit log.

    Every appended record commits to the hash of the previous one, so any later
    modification, insertion, removal or reordering of records breaks the chain and
    is reported by :meth:`verify`.

    Pass ``seal_key`` to sign records with HMAC-SHA256 (authenticity against
    tampering by parties that do not hold the key). Without a key, records are
    protected only by SHA-256 integrity checks.
    """

    def __init__(self, backend: StorageBackend, *, seal_key: bytes | None = None) -> None:
        if seal_key is not None and len(seal_key) < _MIN_KEY_LENGTH:
            raise ValueError(f"seal_key must be at least {_MIN_KEY_LENGTH} bytes")
        self.backend = backend
        self.seal_key = seal_key
        self._last: AuditRecord | None = None
        self._inited = False

    async def __aenter__(self) -> AuditLog:
        await self.init()
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.close()

    async def init(self) -> None:
        """Open storage and restore chain state (the hash of the last record)."""
        await self.backend.init()
        records = await self.backend.load()
        self._last = records[-1] if records else None
        self._inited = True

    async def close(self) -> None:
        await self.backend.close()

    async def append(
        self,
        actor: str,
        action: str,
        subject: str = "",
        *,
        metadata: dict[str, Any] | None = None,
        timestamp: str | None = None,
    ) -> AuditRecord:
        """Append one record and return it. ``actor``/``action`` are required."""
        if not self._inited:
            await self.init()
        meta = dict(metadata or {})
        seq = 0 if self._last is None else self._last.seq + 1
        prev_hash = GENESIS_HASH if self._last is None else self._last.hash
        record = AuditRecord(
            seq=seq,
            timestamp=timestamp or _utcnow(),
            actor=actor,
            action=action,
            subject=subject,
            metadata=meta,
            prev_hash=prev_hash,
            hash="",
        )
        try:
            record_hash = compute_record_hash(record, self.seal_key)
        except TypeError as exc:
            raise ValueError("metadata must be JSON-serializable") from exc
        sealed = replace(record, hash=record_hash)
        await self.backend.append(sealed)
        self._last = sealed
        return sealed

    async def read(self) -> list[AuditRecord]:
        """Load every record, in chain order."""
        if not self._inited:
            await self.init()
        return await self.backend.load()

    async def verify(self, *, expected_count: int | None = None) -> VerifyReport:
        """Check the whole chain. See :func:`auditchain.verify_chain`."""
        from .verify import verify_chain

        try:
            records = await self.read()
        except Exception as exc:  # storage-level failure (e.g. unparsable line)
            return VerifyReport(ok=False, records_checked=0, first_error_seq=None, reason=str(exc))
        return verify_chain(records, self.seal_key, expected_count=expected_count)


__all__ = ["AuditLog", "VerifyReport"]
