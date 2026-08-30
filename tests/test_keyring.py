import pytest

from auditchain import AuditLog, MemoryBackend
from auditchain.verify import verify_chain


async def test_rotation_keeps_old_records_verifiable():
    log = AuditLog(MemoryBackend(), seal_key=b"a" * 32, key_id="k0")
    await log.append("sara", "login")
    marker = await log.rotate(b"b" * 32, "k1")
    await log.append("jawad", "logout")
    marker2 = await log.rotate(b"c" * 32, "k2")
    await log.append("sara", "audit", metadata={"x": 1})

    assert marker.action == "key.rotate"
    assert marker.key_id == "k0"  # the marker is sealed with the OLD key
    assert marker.metadata == {"from_key_id": "k0", "to_key_id": "k1"}
    assert marker2.metadata == {"from_key_id": "k1", "to_key_id": "k2"}

    report = await log.verify()
    assert report.ok, report
    assert report.records_checked == 5


async def test_verify_fails_without_retired_keys():
    log = AuditLog(MemoryBackend(), seal_key=b"a" * 32, key_id="k0")
    await log.append("sara", "login")
    await log.rotate(b"b" * 32, "k1")
    await log.append("jawad", "logout")
    # a fresh AuditLog that only knows k1 cannot verify the k0-sealed prefix;
    # simulate the incomplete keyring directly against the chain data
    report = verify_chain(await log.read(), b"b" * 32, keyring={"k1": b"b" * 32})
    assert not report.ok
    assert "unknown key_id" in report.reason


async def test_verify_with_complete_keyring():
    log = AuditLog(MemoryBackend(), seal_key=b"a" * 32, key_id="k0")
    await log.append("sara", "login")
    await log.rotate(b"b" * 32, "k1")
    await log.append("jawad", "logout")
    report = verify_chain(await log.read(), b"b" * 32, keyring={"k0": b"a" * 32, "k1": b"b" * 32})
    assert report.ok, report
    assert report.records_checked == 3


async def test_wrong_key_for_record_is_detected():
    log = AuditLog(MemoryBackend(), seal_key=b"a" * 32, key_id="k0")
    await log.append("sara", "login")
    report = verify_chain(await log.read(), b"b" * 32, keyring={"k0": b"a" * 32})
    # records carry key_id k0 -> keyring provides the right key -> OK
    assert report.ok
    # ...but if the keyring maps k0 to the wrong key, the hash must not match
    report = verify_chain(await log.read(), b"b" * 32, keyring={"k0": b"b" * 32})
    assert not report.ok
    assert "modified" in report.reason


async def test_tampered_key_id_is_detected():
    from dataclasses import replace

    log = AuditLog(MemoryBackend(), seal_key=b"a" * 32, key_id="k0")
    await log.append("sara", "login")
    await log.append("jawad", "logout")
    records = await log.read()
    forged = replace(records[1], key_id="other")
    report = verify_chain([records[0], forged], b"a" * 32, keyring={"k0": b"a" * 32})
    assert not report.ok
    assert "unknown key_id" in report.reason


async def test_legacy_v01_records_verify_without_key_id():
    from dataclasses import replace

    log = AuditLog(MemoryBackend(), seal_key=b"a" * 32, key_id="k0")
    await log.append("sara", "login")
    records = await log.read()
    legacy = replace(records[0], key_id="")  # v0.1 style: no key_id stored
    report = verify_chain([legacy], b"a" * 32)
    assert report.ok, report


async def test_rotate_rejects_short_key():
    log = AuditLog(MemoryBackend(), seal_key=b"a" * 32, key_id="k0")
    with pytest.raises(ValueError, match="seal_key"):
        await log.rotate(b"short", "k1")
