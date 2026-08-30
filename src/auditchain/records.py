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

    def to_payload_dict(self) -> dict[str, Any]:
        """All fields that participate in the hash, as a JSON-safe dict."""
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
        )
