"""Audit record model and canonical serialization."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

#: Hash of the empty chain; used as ``prev_hash`` of the first record.
GENESIS_HASH = "0" * 64


@dataclass(frozen=True, slots=True)
class AuditRecord:
    """One entry of a hash-chained audit log."""

    seq: int
    timestamp: str
    actor: str
    action: str
    subject: str
    metadata: dict[str, Any]
    prev_hash: str
    hash: str
    #: Identifier of the HMAC key that sealed this record. Stored next to the
    #: record but deliberately NOT part of the hashed payload, so that adding key
    #: rotation in 0.2 kept every v0.1 log verifiable. Empty for integrity-only
    #: (SHA-256) records and for records written before 0.2.
    key_id: str = ""
    #: Identifier of the Ed25519 key that signed this record. Empty when the record
    #: is not signed. Like ``key_id`` it is not part of the hashed payload, so a log
    #: written before signing existed stays verifiable.
    signer_id: str = ""
    #: Hex Ed25519 signature over ``seq:hash:signer_id`` (see
    #: :func:`auditchain.signing.record_signing_message`). Empty when not signed.
    signature: str = ""

    def to_payload_dict(self) -> dict[str, Any]:
        """All fields that participate in the hash, as a JSON-safe dict.

        ``key_id``, ``signer_id`` and ``signature`` are intentionally excluded: they
        describe *how* a record was authenticated rather than what it says. The
        signature covers the hash, so it still commits to every field below.
        """
        return {
            "seq": self.seq,
            "ts": self.timestamp,
            "actor": self.actor,
            "action": self.action,
            "subject": self.subject,
            "meta": self.metadata,
            "prev": self.prev_hash,
        }

    def to_payload_bytes(self) -> bytes:
        """Canonical, deterministic bytes for a record (JSON, keys sorted)."""
        return json.dumps(
            self.to_payload_dict(), sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")

    @classmethod
    def from_stored(cls, stored: dict[str, Any]) -> AuditRecord:
        """Rebuild a record from backend storage (JSON object or row dict)."""
        meta = stored.get("meta") or {}
        return cls(
            seq=int(stored["seq"]),
            timestamp=str(stored["ts"]),
            actor=str(stored["actor"]),
            action=str(stored["action"]),
            subject=str(stored.get("subject", "")),
            metadata=dict(meta),
            prev_hash=str(stored["prev_hash"]),
            hash=str(stored["hash"]),
            key_id=str(stored.get("key_id", "")),
            signer_id=str(stored.get("signer_id", "")),
            signature=str(stored.get("signature", "")),
        )
