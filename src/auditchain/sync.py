"""Thin synchronous wrappers around :class:`auditchain.AuditLog`.

Each call runs its own event loop (``asyncio.run``). Do not use these from code
that already runs inside an event loop; use the async API there.
"""

from __future__ import annotations

import asyncio
from collections.abc import Sequence
from typing import Any

from .backends import StorageBackend
from .checkpoint import Checkpoint
from .log import AuditLog
from .records import AuditRecord
from .verify import VerifyReport


class SyncAuditLog:
    """Synchronous facade over :class:`AuditLog`."""

    def __init__(
        self,
        backend: StorageBackend,
        *,
        seal_key: bytes | None = None,
        key_id: str = "k0",
        keyring: dict[str, bytes] | None = None,
        signing_key: bytes | str | object | None = None,
        signer_id: str = "s0",
    ) -> None:
        self._log = AuditLog(
            backend,
            seal_key=seal_key,
            key_id=key_id,
            keyring=keyring,
            signing_key=signing_key,
            signer_id=signer_id,
        )
        asyncio.run(self._log.init())

    @property
    def public_key(self):  # noqa: ANN201 - mirrors AuditLog.public_key
        """The Ed25519 public key to hand to verifiers, or None when not signing."""
        return self._log.public_key

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

    def append_many(
        self, entries: Sequence[tuple[str, str, str, dict[str, Any] | None]]
    ) -> list[AuditRecord]:
        return asyncio.run(self._log.append_many(entries))

    def rotate(self, new_seal_key: bytes, new_key_id: str, *, actor: str = "system") -> AuditRecord:
        return asyncio.run(self._log.rotate(new_seal_key, new_key_id, actor=actor))

    def read(self) -> list[AuditRecord]:
        return asyncio.run(self._log.read())

    def checkpoint(self) -> Checkpoint:
        return asyncio.run(self._log.checkpoint())

    def merkle_root(self) -> str:
        return asyncio.run(self._log.merkle_root())

    def inclusion_proof(self, seq: int):  # noqa: ANN201 - mirrors AuditLog.inclusion_proof
        return asyncio.run(self._log.inclusion_proof(seq))

    def verify(
        self,
        *,
        expected_count: int | None = None,
        checkpoint: Checkpoint | None = None,
        signers: dict[str, Any] | None = None,
    ) -> VerifyReport:
        return asyncio.run(
            self._log.verify(expected_count=expected_count, checkpoint=checkpoint, signers=signers)
        )

    def close(self) -> None:
        asyncio.run(self._log.close())
