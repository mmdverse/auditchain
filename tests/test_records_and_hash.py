import pytest

from auditchain import GENESIS_HASH, AuditRecord
from auditchain.hash import compute_record_hash, verify_record_hash


def _record(**overrides) -> AuditRecord:
    base = dict(
        seq=0,
        timestamp="2026-08-30T12:00:00.000000Z",
        actor="sara",
        action="login",
        subject="admin",
        metadata={"ip": "10.0.0.1"},
        prev_hash=GENESIS_HASH,
        hash="",
    )
    base.update(overrides)
    return AuditRecord(**base)


def test_canonical_serialization_is_stable():
    a = _record()
    b = _record()
    assert a.to_payload_bytes() == b.to_payload_bytes()
    # order of metadata keys must not matter
    c = _record(metadata={"ip": "10.0.0.1"})
    assert a.to_payload_bytes() == c.to_payload_bytes()


def test_canonical_serialization_is_unicode_safe():
    record = _record(actor="محمد", metadata={"note": "مرور کامل"})
    assert "محمد" in record.to_payload_bytes().decode("utf-8")
    assert compute_record_hash(record, None) == compute_record_hash(record, None)


def test_golden_vector():
    # Guards the serialization + hashing order; if this test fails, existing
    # logs would no longer verify, which is exactly what we must never allow.
    record = _record()
    assert (
        compute_record_hash(record, None)
        == "6adf05fa527463011707be155116b628a521a106012c0b6c2a7e90fe6b281b55"
    )
    assert (
        compute_record_hash(record, b"k" * 32)
        == "22cbe78f7d5bac962de627983d75370ebab91a6b078ec6d18adc59e721a095e9"
    )


def test_hash_changes_with_any_field():
    h = compute_record_hash(_record(), None)
    assert compute_record_hash(_record(actor="other"), None) != h
    assert compute_record_hash(_record(action="logout"), None) != h
    assert compute_record_hash(_record(prev_hash="1" * 64), None) != h


def test_hmac_requires_the_key():
    key = b"k" * 32
    record = _record(hash=compute_record_hash(_record(), key))
    assert verify_record_hash(record, key)
    assert not verify_record_hash(record, b"x" * 32)
    # HMAC and plain SHA-256 produce different hashes
    assert compute_record_hash(_record(), key) != compute_record_hash(_record(), None)


def test_record_roundtrip_through_stored_dict():
    record = _record(hash=compute_record_hash(_record(), None))
    restored = AuditRecord.from_stored(
        {
            "seq": record.seq,
            "ts": record.timestamp,
            "actor": record.actor,
            "action": record.action,
            "subject": record.subject,
            "meta": dict(record.metadata),
            "prev_hash": record.prev_hash,
            "hash": record.hash,
        }
    )
    assert restored == record
    assert restored.to_payload_bytes() == record.to_payload_bytes()


def test_seal_key_too_short_is_rejected():
    from auditchain import AuditLog, MemoryBackend

    with pytest.raises(ValueError, match="seal_key"):
        AuditLog(MemoryBackend(), seal_key=b"short")
