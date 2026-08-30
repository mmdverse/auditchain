import pytest

from auditchain import (
    AuditLog,
    MemoryBackend,
    load_checkpoint,
    save_checkpoint,
)


async def _log_with_records(n=5):
    log = AuditLog(MemoryBackend())
    for i in range(n):
        await log.append("sara", f"action-{i}", metadata={"i": i})
    return log


async def test_checkpoint_anchors_the_tail():
    log = await _log_with_records(5)
    cp = await log.checkpoint()
    assert cp.seq == 4
    records = await log.read()
    assert cp.hash == records[-1].hash
    report = await log.verify(checkpoint=cp)
    assert report.ok, report
    assert report.records_checked == 5


async def test_checkpoint_detects_tail_truncation():

    log = await _log_with_records(5)
    cp = await log.checkpoint()
    records = await log.read()
    truncated = records[:3]  # attacker removes the last two records
    report = await log.verify(checkpoint=cp)
    # verify() reads from the backend, so check verify_chain directly instead
    from auditchain.verify import verify_chain

    report = verify_chain(truncated, checkpoint=cp)
    assert not report.ok
    assert "tail truncation" in report.reason


async def test_checkpoint_detects_modified_history():
    from dataclasses import replace

    log = await _log_with_records(5)
    cp = await log.checkpoint()
    records = await log.read()
    forged = [records[0], replace(records[1], metadata={"i": 999})] + records[2:]
    from auditchain.verify import verify_chain

    report = verify_chain(forged, checkpoint=cp)
    assert not report.ok, report
    assert "modified" in report.reason


async def test_checkpoint_empty_log_raises():
    log = AuditLog(MemoryBackend())
    with pytest.raises(ValueError, match="empty"):
        await log.checkpoint()


async def test_checkpoint_file_roundtrip_signed(tmp_path):
    log = AuditLog(MemoryBackend(), seal_key=b"a" * 32, key_id="k0")
    await log.append("sara", "login")
    cp = await log.checkpoint()
    path = tmp_path / "cp.json"
    save_checkpoint(cp, path)
    loaded = load_checkpoint(path, b"a" * 32)
    assert loaded == cp
    assert loaded.signature


async def test_signed_checkpoint_requires_key(tmp_path):
    log = AuditLog(MemoryBackend(), seal_key=b"a" * 32, key_id="k0")
    await log.append("sara", "login")
    cp = await log.checkpoint()
    path = tmp_path / "cp.json"
    save_checkpoint(cp, path)
    with pytest.raises(ValueError, match="seal key"):
        load_checkpoint(path)


async def test_tampered_checkpoint_file_is_rejected(tmp_path):
    log = AuditLog(MemoryBackend(), seal_key=b"a" * 32, key_id="k0")
    await log.append("sara", "login")
    path = tmp_path / "cp.json"
    save_checkpoint(await log.checkpoint(), path)
    text = path.read_text(encoding="utf-8").replace('"seq": 0', '"seq": 1')
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match="signature mismatch"):
        load_checkpoint(path, b"a" * 32)


async def test_unsigned_checkpoint_loads_without_key(tmp_path):
    log = await _log_with_records(2)
    path = tmp_path / "cp.json"
    save_checkpoint(await log.checkpoint(), path)
    loaded = load_checkpoint(path)
    assert loaded.key_id == "" and loaded.signature == ""


async def test_verify_with_checkpoint_and_good_tail():
    log = await _log_with_records(6)
    cp = await log.checkpoint()
    report = await log.verify(checkpoint=cp)
    assert report.ok, report
