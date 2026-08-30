"""Async audit log API: append, read, rotate keys, checkpoint and verify."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime, timezone
from typing import Any

from .backends import StorageBackend
from .checkpoint import Checkpoint, make_checkpoint
from .hash import compute_record_hash
from .records import GENESIS_HASH, AuditRecord
from .verify import VerifyReport, verify_chain

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

    ``key_id`` labels the current key (stored with each sealed record, outside the
    hashed payload, so v0.1 logs remain verifiable). ``keyring`` keeps older keys so
    that :meth:`verify` can still validate records sealed before :meth:`rotate`.
    """

    def __init__(
        self,
        backend: StorageBackend,
        *,
        seal_key: bytes | None = None,
        key_id: str = "k0",
        keyring: dict[str, bytes] | None = None,
    ) -> None:
        if seal_key is not None and len(seal_key) < _MIN_KEY_LENGTH:
            raise ValueError(f"seal_key must be at least {_MIN_KEY_LENGTH} bytes")
        self.backend = backend
        self.seal_key = seal_key
        self.key_id = key_id
        self._keyring: dict[str, bytes] = dict(keyring or {})
        if seal_key is not None:
            self._keyring[key_id] = seal_key
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

    def _build_record(
        self,
        actor: str,
        action: str,
        subject: str,
        metadata: dict[str, Any],
        timestamp: str | None,
        prev: AuditRecord | None,
    ) -> AuditRecord:
        seq = 0 if prev is None else prev.seq + 1
        prev_hash = GENESIS_HASH if prev is None else prev.hash
        return AuditRecord(
            seq=seq,
            timestamp=timestamp or _utcnow(),
            actor=actor,
            action=action,
            subject=subject,
            metadata=metadata,
            prev_hash=prev_hash,
            hash="",
            key_id=self.key_id if self.seal_key is not None else "",
        )

    def _seal(self, record: AuditRecord) -> AuditRecord:
        try:
            record_hash = compute_record_hash(record, self.seal_key)
        except TypeError as exc:
            raise ValueError("metadata must be JSON-serializable") from exc
        return replace(record, hash=record_hash)

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
        sealed = self._seal(
            self._build_record(actor, action, subject, dict(metadata or {}), timestamp, self._last)
        )
        await self.backend.append(sealed)
        self._last = sealed
        return sealed

    async def append_many(
        self, entries: Sequence[tuple[str, str, str, dict[str, Any] | None]]
    ) -> list[AuditRecord]:
        """Append several records atomically (single batch write where the backend
        supports it) and return them. Entries are ``(actor, action, subject, metadata)``.
        """
        if not self._inited:
            await self.init()
        sealed: list[AuditRecord] = []
        prev = self._last
        for actor, action, subject, metadata in entries:
            record = self._build_record(actor, action, subject, dict(metadata or {}), None, prev)
            sealed.append(self._seal(record))
            prev = sealed[-1]
        if not sealed:
            return []
        await self.backend.append_many(sealed)
        self._last = sealed[-1]
        return sealed

    async def rotate(
        self, new_seal_key: bytes, new_key_id: str, *, actor: str = "system"
    ) -> AuditRecord:
        """Switch the sealing key and record the rotation in the chain itself.

        The rotation marker is sealed with the *old* key, so it documents the
        decision under the key that was in effect. Keep retired keys in ``keyring``
        (or pass them to ``verify``) so previous records stay verifiable.
        """
        if len(new_seal_key) < _MIN_KEY_LENGTH:
            raise ValueError(f"seal_key must be at least {_MIN_KEY_LENGTH} bytes")
        if not self._inited:
            await self.init()
        marker = await self.append(
            actor,
            "key.rotate",
            f"key:{new_key_id}",
            metadata={
                "from_key_id": self.key_id if self.seal_key is not None else None,
                "to_key_id": new_key_id,
            },
        )
        self.seal_key = new_seal_key
        self.key_id = new_key_id
        self._keyring[new_key_id] = new_seal_key
        return marker

    async def read(self) -> list[AuditRecord]:
        """Load every record, in chain order."""
        if not self._inited:
            await self.init()
        return await self.backend.load()

    async def checkpoint(self) -> Checkpoint:
        """Anchor the current end of the chain (a Checkpoint for the last record).

        Save it outside the log's trust boundary; verifying against it later detects
        tail truncation and proves the chain's state as of this point.
        """
        records = await self.read()
        if not records:
            raise ValueError("cannot checkpoint an empty log")
        return make_checkpoint(records[-1], self.seal_key)

    async def verify(
        self, *, expected_count: int | None = None, checkpoint: Checkpoint | None = None
    ) -> VerifyReport:
        """Check the whole chain. See :func:`auditchain.verify_chain`."""
        try:
            records = await self.read()
        except Exception as exc:  # storage-level failure (e.g. unparsable line)
            return VerifyReport(ok=False, records_checked=0, first_error_seq=None, reason=str(exc))
        keyring = dict(self._keyring)
        if self.seal_key is not None:
            keyring.setdefault(self.key_id, self.seal_key)
        return verify_chain(
            records,
            self.seal_key,
            expected_count=expected_count,
            keyring=keyring or None,
            checkpoint=checkpoint,
        )


__all__ = ["AuditLog", "VerifyReport"]
