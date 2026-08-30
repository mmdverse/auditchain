import pytest

from auditchain import AuditLog, MemoryBackend, verify_chain


@pytest.fixture
def log():
    return AuditLog(MemoryBackend())


async def test_append_read_roundtrip(log):
    rec0 = await log.append("sara", "login", "admin", metadata={"ip": "10.0.0.1"})
    rec1 = await log.append("jawad", "logout", "admin")
    records = await log.read()
    assert [r.seq for r in records] == [0, 1]
    assert records[0].prev_hash == "0" * 64
    assert rec1.prev_hash == rec0.hash
    assert rec0.metadata == {"ip": "10.0.0.1"}


async def test_verify_ok_on_clean_chain(log):
    await log.append("sara", "login", "admin")
    await log.append("sara", "update", "invoice:12", metadata={"field": "status"})
    report = await log.verify()
    assert report.ok
    assert report.records_checked == 2


async def test_verify_catches_modified_record(log):
    from dataclasses import replace

    await log.append("sara", "login")
    await log.append("jawad", "logout")
    records = await log.read()
    forged = replace(records[1], action="logout")  # attacker edits content...
    forged = replace(forged, action="delete_everything")  # ...without re-sealing
    report = verify_chain([records[0], forged], None)
    assert not report.ok
    assert report.first_error_seq == 1
    assert "modified" in report.reason


async def test_verify_catches_removed_middle_record(log):
    await log.append("sara", "login")
    await log.append("jawad", "update")
    await log.append("jawad", "logout")
    records = await log.read()
    report = verify_chain([records[0], records[2]], None)  # removed seq 1
    assert not report.ok
    assert report.first_error_seq == 2
    # either the linkage (prev_hash) or the sequence check catches it first
    assert "prev_hash" in report.reason or "sequence gap" in report.reason


async def test_verify_catches_reordered_records(log):
    await log.append("sara", "login")
    await log.append("jawad", "update")
    records = await log.read()
    report = verify_chain([records[1], records[0]], None)
    assert not report.ok


async def test_verify_catches_sequence_gap(log):
    from dataclasses import replace

    await log.append("sara", "login")
    await log.append("jawad", "update")
    records = await log.read()
    report = verify_chain([replace(records[1], seq=5)], None)
    assert not report.ok
    assert "sequence gap" in report.reason


async def test_verify_catches_truncation_with_expected_count(log):
    await log.append("sara", "login")
    await log.append("jawad", "update")
    records = await log.read()
    report = verify_chain(records[:1], None, expected_count=2)
    assert not report.ok
    assert "count mismatch" in report.reason


def test_verify_chain_empty_is_ok():
    report = verify_chain([], None)
    assert report.ok and report.records_checked == 0


async def test_metadata_must_be_json_serializable(log):
    with pytest.raises(ValueError, match="JSON-serializable"):
        await log.append("sara", "login", metadata={"bad": object()})


async def test_auto_init_before_append():
    log = AuditLog(MemoryBackend())
    rec = await log.append("sara", "login")
    assert rec.seq == 0
    report = await log.verify()
    assert report.ok


async def test_context_manager(log):
    async with AuditLog(MemoryBackend()) as ctx:
        await ctx.append("sara", "login")
        report = await ctx.verify()
        assert report.ok
