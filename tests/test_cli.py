import asyncio

from auditchain import AuditLog, JsonlBackend, SqliteBackend
from auditchain.__main__ import main


def _run(args):
    try:
        return main(args), None
    except SystemExit as exc:  # argparse exits with SystemExit for --help
        return exc.code, None


def _fill(log_path, *, sqlite: bool = False, records=1):
    async def _fill_async():
        backend = SqliteBackend(log_path) if sqlite else JsonlBackend(log_path)
        async with AuditLog(backend) as log:
            for i in range(records):
                await log.append("sara", "login" if i % 2 == 0 else "logout")

    asyncio.run(_fill_async())


def test_cli_verify_jsonl_ok(tmp_path):
    path = tmp_path / "audit.jsonl"
    _fill(path)
    assert _run(["verify", str(path)])[0] == 0


def test_cli_verify_detects_tamper(tmp_path):
    path = tmp_path / "audit.jsonl"
    _fill(path, records=2)
    lines = path.read_text(encoding="utf-8").splitlines()
    lines[1] = lines[1].replace('"logout"', '"delete_everything"')
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    assert _run(["verify", str(path)])[0] == 1


def test_cli_verify_sqlite_ok_and_count_mismatch(tmp_path):
    path = tmp_path / "audit.sqlite"
    _fill(path, sqlite=True)
    assert _run(["verify", str(path)])[0] == 0
    assert _run(["verify", str(path), "--expected-count", "5"])[0] == 1


def test_cli_missing_file_exits_2(tmp_path):
    assert _run(["verify", str(tmp_path / "nope.jsonl")])[0] == 2


def test_cli_unknown_extension_needs_format_flag(tmp_path):
    path = tmp_path / "audit.log"
    path.write_text("x\n", encoding="utf-8")
    assert _run(["verify", str(path)])[0] == 2
    assert _run(["verify", str(path), "--format", "jsonl"])[0] == 1  # unparsable line
