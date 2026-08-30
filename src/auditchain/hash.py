"""Sealing of audit records: SHA-256 or HMAC-SHA256 over the canonical payload."""

from __future__ import annotations

import hashlib
import hmac

from .records import AuditRecord

_SEPARATOR = b"\x00"


def compute_record_hash(record: AuditRecord, seal_key: bytes | None) -> str:
    """Hash a record: ``seal(prev_hash || payload)``.

    With ``seal_key`` the hash is HMAC-SHA256 (authenticity, keyed), otherwise a plain
    SHA-256 (only integrity, no authenticity).
    """
    data = record.prev_hash.encode("ascii") + _SEPARATOR + record.to_payload_bytes()
    if seal_key is not None:
        return hmac.new(seal_key, data, hashlib.sha256).hexdigest()
    return hashlib.sha256(data).hexdigest()


def verify_record_hash(record: AuditRecord, seal_key: bytes | None) -> bool:
    """Constant-time check that a record's stored hash matches its content."""
    return hmac.compare_digest(record.hash, compute_record_hash(record, seal_key))
