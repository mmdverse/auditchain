import os
import uuid

import asyncpg
import pytest
import pytest_asyncio

from auditchain import AuditLog, PostgresBackend, verify_chain

DSN = os.environ.get("AUDITCHAIN_TEST_POSTGRES_DSN")

pytestmark = [
    pytest.mark.postgres,
    pytest.mark.skipif(not DSN, reason="AUDITCHAIN_TEST_POSTGRES_DSN is not set"),
]


@pytest_asyncio.fixture
async def backend():
    table = f"audit_test_{uuid.uuid4().hex[:12]}"
    b = PostgresBackend(DSN, table=table)
    await b.init()
    yield b
    await b.close()
    conn = await asyncpg.connect(DSN)
    try:
        await conn.execute(f'DROP TABLE IF EXISTS "{table}"')
    finally:
        await conn.close()


async def test_roundtrip_and_reopen(backend):
    path = backend
    async with AuditLog(path) as log:
        await log.append("sara", "login", "admin", metadata={"ip": "10.0.0.1"})
        await log.append("محمد", "update", "سند:۱", metadata={"note": "نسخهٔ جدید"})
    async with AuditLog(PostgresBackend(backend.dsn, table=backend.table)) as log:
        records = await log.read()
        assert len(records) == 2
        assert records[1].prev_hash == records[0].hash
        assert (await log.verify()).ok


async def test_tamper_is_detected(backend):
    async with AuditLog(backend) as log:
        await log.append("sara", "login")
        await log.append("jawad", "logout")
    conn = await asyncpg.connect(DSN)
    try:
        await conn.execute(
            f'UPDATE "{backend.table}" SET action = $1 WHERE seq = 1', "delete_everything"
        )
    finally:
        await conn.close()
    async with AuditLog(PostgresBackend(backend.dsn, table=backend.table)) as log:
        report = await log.verify()
    assert not report.ok
    assert "modified" in report.reason


async def test_key_rotation_with_keyring(backend):
    async with AuditLog(backend, seal_key=b"a" * 32, key_id="k0") as log:
        await log.append("sara", "login")
        await log.rotate(b"b" * 32, "k1")
        await log.append("jawad", "logout")
        assert (await log.verify()).ok
    # reopening with only the newest key must fail on the old record
    async with AuditLog(
        PostgresBackend(backend.dsn, table=backend.table), seal_key=b"b" * 32, key_id="k1"
    ) as log:
        report = await log.verify()
        assert not report.ok
        assert "unknown key_id" in report.reason
    # with the full keyring it verifies
    records = None
    async with AuditLog(
        PostgresBackend(backend.dsn, table=backend.table),
        seal_key=b"b" * 32,
        key_id="k1",
        keyring={"k0": b"a" * 32},
    ) as log:
        records = await log.read()
    assert verify_chain(records, b"b" * 32, keyring={"k0": b"a" * 32, "k1": b"b" * 32}).ok


async def test_append_many_and_checkpoint_against_truncation(backend):
    async with AuditLog(backend) as log:
        await log.append_many([(f"user-{i}", f"action-{i}", "", {"i": i}) for i in range(5)])
        cp = await log.checkpoint()
    # truncate the tail directly in SQL
    conn = await asyncpg.connect(DSN)
    try:
        await conn.execute(f'DELETE FROM "{backend.table}" WHERE seq > 2')
    finally:
        await conn.close()
    from auditchain.checkpoint import Checkpoint
    from auditchain.verify import verify_chain

    async with AuditLog(PostgresBackend(backend.dsn, table=backend.table)) as log:
        records = await log.read()
    anchor = Checkpoint(seq=cp.seq, hash=cp.hash, key_id=cp.key_id)
    report = verify_chain(records, checkpoint=anchor)
    assert not report.ok
    assert "tail truncation" in report.reason
