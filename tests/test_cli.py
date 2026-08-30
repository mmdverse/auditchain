import asyncio

from auditchain import AuditLog, JsonlBackend, SqliteBackend
from auditchain.__main__ import main


def _run(args):
    try:
        return main(args), None
    except SystemExit as exc:  # argparse exits with SystemExit for --help
        return exc.code, None


def _fill(log_path, *, sqlite: bool = False, records=1, seal_key=None):
    async def _fill_async():
        backend = SqliteBackend(log_path) if sqlite else JsonlBackend(log_path)
        async with AuditLog(backend, seal_key=seal_key) as log:
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


def test_cli_checkpoint_subcommand_and_verify(tmp_path):
    path = tmp_path / "audit.jsonl"
    _fill(path, records=4)
    cp_path = tmp_path / "audit.checkpoint"
    assert _run(["checkpoint", str(path), "--output", str(cp_path)])[0] == 0
    assert cp_path.exists()
    # clean chain against the checkpoint passes
    assert _run(["verify", str(path), "--checkpoint", str(cp_path)])[0] == 0


def test_cli_verify_checkpoint_detects_truncation(tmp_path):
    path = tmp_path / "audit.jsonl"
    _fill(path, records=4)
    cp_path = tmp_path / "audit.checkpoint"
    assert _run(["checkpoint", str(path), "--output", str(cp_path)])[0] == 0
    # drop the last two records (pure tail truncation)
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join(lines[:2]) + "\n", encoding="utf-8")
    assert _run(["verify", str(path), "--checkpoint", str(cp_path)])[0] == 1


def test_cli_checkpoint_signed_flow(tmp_path):
    path = tmp_path / "audit.jsonl"
    key_file = tmp_path / "seal.key"
    key_file.write_bytes(b"a" * 32)
    _fill(path, records=2, seal_key=key_file.read_bytes())
    cp_path = tmp_path / "audit.checkpoint"
    code, _ = _run(
        ["checkpoint", str(path), "--output", str(cp_path), "--seal-key-file", str(key_file)]
    )
    assert code == 0
    # verifying a signed checkpoint without the key is a usage error
    assert _run(["verify", str(path), "--checkpoint", str(cp_path)])[0] == 2
    # with the key it passes
    assert (
        _run(
            [
                "verify",
                str(path),
                "--checkpoint",
                str(cp_path),
                "--seal-key-file",
                str(key_file),
            ]
        )[0]
        == 0
    )
