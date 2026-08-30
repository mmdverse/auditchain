import pytest

from auditchain import AuditLog, JsonlBackend, LogCorruptedError, SqliteBackend


async def _fill(log: AuditLog) -> None:
    await log.append("sara", "login", "admin", metadata={"ip": "10.0.0.1"})
    await log.append("محمد", "update", "سند:۱۲", metadata={"note": "نسخهٔ جدید"})


@pytest.mark.asyncio
async def test_jsonl_roundtrip_and_reopen(tmp_path):
    path = tmp_path / "audit.jsonl"
    async with AuditLog(JsonlBackend(path)) as log:
        await _fill(log)
    async with AuditLog(JsonlBackend(path)) as log:
        assert len(await log.read()) == 2
        report = await log.verify()
        assert report.ok


@pytest.mark.asyncio
async def test_jsonl_appends_are_append_only(tmp_path):
    path = tmp_path / "audit.jsonl"
    async with AuditLog(JsonlBackend(path)) as log:
        await log.append("sara", "login")
    before = path.read_text(encoding="utf-8")
    async with AuditLog(JsonlBackend(path)) as log:
        await log.append("jawad", "logout")
    after = path.read_text(encoding="utf-8")
    assert after.startswith(before)
    assert after.count("\n") == 2


@pytest.mark.asyncio
async def test_jsonl_tamper_is_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    async with AuditLog(JsonlBackend(path)) as log:
        await _fill(log)
    # attacker edits a stored line in place
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1] = (
        lines[1].replace('"اسم"', '"هک"')
        if '"اسم"' in lines[1]
        else lines[1].replace('"action":"update"', '"action":"delete_everything"')
    )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    async with AuditLog(JsonlBackend(path)) as log:
        report = await log.verify()
    assert not report.ok
    assert not report.ok and "modified" in report.reason


@pytest.mark.asyncio
async def test_jsonl_corrupted_line_raises(tmp_path):
    path = tmp_path / "audit.jsonl"
    path.write_text('{"seq": 0, "partial": true}\n', encoding="utf-8")
    with pytest.raises(LogCorruptedError):
        await JsonlBackend(path).load()


@pytest.mark.asyncio
async def test_sqlite_roundtrip_and_reopen(tmp_path):
    path = tmp_path / "audit.sqlite"
    async with AuditLog(SqliteBackend(path)) as log:
        await _fill(log)
    async with AuditLog(SqliteBackend(path)) as log:
        records = await log.read()
        assert len(records) == 2
        assert (await log.verify()).ok


@pytest.mark.asyncio
async def test_sqlite_tamper_is_detected(tmp_path):
    import sqlite3

    path = tmp_path / "audit.sqlite"
    async with AuditLog(SqliteBackend(path)) as log:
        await _fill(log)
    conn = sqlite3.connect(path)
    conn.execute("UPDATE audit_records SET action = 'delete_everything' WHERE seq = 1")
    conn.commit()
    conn.close()
    async with AuditLog(SqliteBackend(path)) as log:
        report = await log.verify()
    assert not report.ok
    assert "modified" in report.reason


@pytest.mark.asyncio
async def test_sqlite_tamper_row_removed(tmp_path):
    import sqlite3

    path = tmp_path / "audit.sqlite"
    async with AuditLog(SqliteBackend(path)) as log:
        await _fill(log)
    conn = sqlite3.connect(path)
    conn.execute("DELETE FROM audit_records WHERE seq = 0")
    conn.commit()
    conn.close()
    async with AuditLog(SqliteBackend(path)) as log:
        report = await log.verify()
    assert not report.ok
    assert "gap" in report.reason or "prev_hash" in report.reason


@pytest.mark.asyncio
async def test_jsonl_legacy_v01_line_without_key_id(tmp_path):
    """A v0.1 JSONL line (sealed, no key_id field) must still verify."""
    path = tmp_path / "audit.jsonl"
    async with AuditLog(JsonlBackend(path), seal_key=b"a" * 32, key_id="k0") as log:
        await log.append("sara", "login")
        await log.append("jawad", "logout")
    # emulate a v0.1 writer: strip the key_id field from every line
    lines = [line.replace('"key_id":"k0",', "") for line in path.read_text().splitlines()]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    async with AuditLog(JsonlBackend(path), seal_key=b"a" * 32) as log:
        assert (await log.verify()).ok


@pytest.mark.asyncio
async def test_jsonl_sealed_records_carry_key_id(tmp_path):
    path = tmp_path / "audit.jsonl"
    async with AuditLog(JsonlBackend(path), seal_key=b"a" * 32, key_id="prod-1") as log:
        await log.append("sara", "login")
    assert '"key_id":"prod-1"' in path.read_text(encoding="utf-8")


@pytest.mark.asyncio
async def test_sqlite_v01_migration_and_verify(tmp_path):
    """A v0.1 SQLite database (no key_id column) must migrate and stay verifiable."""
    import sqlite3

    path = tmp_path / "audit.sqlite"
    # build a v0.1 database by hand: schema without key_id, one sealed record
    conn = sqlite3.connect(path)
    conn.execute(
        "CREATE TABLE audit_records (seq INTEGER PRIMARY KEY, ts TEXT NOT NULL,"
        " actor TEXT NOT NULL, action TEXT NOT NULL, subject TEXT NOT NULL DEFAULT '',"
        " meta TEXT NOT NULL DEFAULT '{}', prev_hash TEXT NOT NULL, hash TEXT NOT NULL)"
    )
    conn.commit()
    async with AuditLog(SqliteBackend(path)) as log:
        await log.append("sara", "login")  # writes with the new schema on init()
    conn.close()
    async with AuditLog(SqliteBackend(path)) as log:
        records = await log.read()
        assert len(records) == 1
        assert (await log.verify()).ok


@pytest.mark.asyncio
async def test_sqlite_append_many_atomic(tmp_path):
    path = tmp_path / "audit.sqlite"
    async with AuditLog(SqliteBackend(path)) as log:
        recs = await log.append_many([(f"u{i}", f"a{i}", "", None) for i in range(4)])
        assert [r.seq for r in recs] == [0, 1, 2, 3]
        assert (await log.verify()).ok
