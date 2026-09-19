"""Ed25519 signatures: authenticity an auditor can check without a forging secret."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace

import pytest

from auditchain import (
    AuditLog,
    JsonlBackend,
    MemoryBackend,
    SignatureError,
    SqliteBackend,
    generate_keypair,
    verify_chain,
)
from auditchain.__main__ import main
from auditchain.records import AuditRecord
from auditchain.signing import (
    load_public_key,
    load_signers,
    record_signing_message,
    sign_record,
    verify_record_signature,
)

cryptography = pytest.importorskip("cryptography", reason="needs the ed25519 extra")

SEAL_KEY = b"0123456789abcdef0123456789abcdef"


async def _signed_log(backend, **kwargs):
    seed, public = generate_keypair()
    log = AuditLog(backend, seal_key=SEAL_KEY, signing_key=seed, **kwargs)
    await log.append("alice", "invoice.approve", "inv-1", metadata={"amount": 100})
    await log.append("bob", "invoice.view", "inv-1")
    return log, public


# ---------------------------------------------------------------- keys and helpers


def test_keypair_roundtrip_and_hex_input() -> None:
    seed, public = generate_keypair()
    assert len(seed) == len(public) == 32
    # hex strings are accepted everywhere raw bytes are
    assert load_public_key(public.hex()).public_bytes_raw() == public
    assert load_public_key(public).public_bytes_raw() == public


def test_bad_key_length_is_rejected() -> None:
    with pytest.raises(SignatureError, match="32 bytes"):
        load_public_key(b"short")


def test_signing_message_binds_seq_hash_and_signer() -> None:
    record = AuditRecord(
        seq=7,
        timestamp="2026-01-01T00:00:00.000000Z",
        actor="a",
        action="b",
        subject="c",
        metadata={},
        prev_hash="0" * 64,
        hash="f" * 64,
        signer_id="auditor-1",
    )
    assert record_signing_message(record) == f"7:{'f' * 64}:auditor-1".encode()


def test_signature_is_not_part_of_the_hashed_payload() -> None:
    """v0.1/v0.2 logs keep verifying: signing must not change what the hash covers."""
    record = AuditRecord(
        seq=0,
        timestamp="t",
        actor="a",
        action="b",
        subject="",
        metadata={},
        prev_hash="0" * 64,
        hash="",
        key_id="k0",
        signer_id="s0",
        signature="deadbeef",
    )
    assert "signature" not in record.to_payload_dict()
    assert "signer_id" not in record.to_payload_dict()
    assert "key_id" not in record.to_payload_dict()


# ---------------------------------------------------------------- signing a log


async def test_signed_log_verifies_with_only_the_public_key() -> None:
    log, public = await _signed_log(MemoryBackend())
    records = await log.read()

    report = verify_chain(records, SEAL_KEY, keyring={"k0": SEAL_KEY}, signers={"s0": public})

    assert report.ok, report.reason
    assert report.signed_records == 2
    # the auditor never saw the private key
    assert all(record.signature for record in records)
    assert all(record.signer_id == "s0" for record in records)


async def test_signed_log_without_signers_is_not_silently_accepted() -> None:
    log, _ = await _signed_log(MemoryBackend())
    records = await log.read()

    # No signers passed: hashes still check out, but nothing claims the records are
    # authentic. That is the documented behaviour of a plain verify.
    report = verify_chain(records, SEAL_KEY, keyring={"k0": SEAL_KEY})

    assert report.ok
    assert report.signed_records == 0


async def test_verifying_with_signers_requires_every_record_to_be_signed() -> None:
    """Otherwise an insider with the seal key could strip signatures and pass."""
    log, public = await _signed_log(MemoryBackend())
    records = await log.read()
    stripped = [records[0]] + [replace(r, signature="") for r in records[1:]]

    report = verify_chain(stripped, SEAL_KEY, keyring={"k0": SEAL_KEY}, signers={"s0": public})

    assert not report.ok
    assert "missing signature" in (report.reason or "")
    assert report.first_error_seq == 1


async def test_unknown_signer_id_is_reported() -> None:
    log, public = await _signed_log(MemoryBackend())
    records = await log.read()

    report = verify_chain(
        records, SEAL_KEY, keyring={"k0": SEAL_KEY}, signers={"someone-else": public}
    )

    assert not report.ok
    assert "unknown signer_id" in (report.reason or "")


async def test_rewritten_record_fails_the_signature_check() -> None:
    """The key scenario: an insider holds the HMAC seal key and can recompute hashes.

    They can make the chain hash-consistent again, but they cannot produce a valid
    Ed25519 signature because they do not hold the signing key.
    """
    log, public = await _signed_log(MemoryBackend())
    records = await log.read()

    forged = replace(records[0], action="invoice.delete")
    # recompute the hash exactly like the library would, with the seal key they hold
    from auditchain import compute_record_hash

    forged = replace(forged, hash=compute_record_hash(forged, SEAL_KEY))

    report = verify_chain(
        [forged] + records[1:], SEAL_KEY, keyring={"k0": SEAL_KEY}, signers={"s0": public}
    )

    assert not report.ok
    assert "signature mismatch" in (report.reason or "")
    assert report.first_error_seq == 0


async def test_a_signature_cannot_be_moved_to_another_record() -> None:
    log, public = await _signed_log(MemoryBackend())
    records = await log.read()

    swapped = [
        replace(records[0], signature=records[1].signature),
        records[1],
    ]
    report = verify_chain(swapped, SEAL_KEY, keyring={"k0": SEAL_KEY}, signers={"s0": public})

    assert not report.ok
    assert report.first_error_seq == 0


async def test_a_signature_from_another_keypair_is_rejected() -> None:
    log, _ = await _signed_log(MemoryBackend())
    _, other_public = generate_keypair()
    records = await log.read()

    report = verify_chain(records, SEAL_KEY, keyring={"k0": SEAL_KEY}, signers={"s0": other_public})

    assert not report.ok
    assert "signature mismatch" in (report.reason or "")


async def test_record_signature_helper_roundtrip() -> None:
    seed, public = generate_keypair()
    record = AuditRecord(
        seq=0,
        timestamp="t",
        actor="a",
        action="b",
        subject="",
        metadata={},
        prev_hash="0" * 64,
        hash="a" * 64,
        signer_id="s0",
    )
    signature = sign_record(record, seed)

    assert verify_record_signature(replace(record, signature=signature), public)
    assert not verify_record_signature(
        replace(record, signature=signature, signer_id="other"), public
    )


def test_empty_signer_id_is_rejected() -> None:
    seed, _ = generate_keypair()
    with pytest.raises(ValueError, match="signer_id"):
        AuditLog(MemoryBackend(), signing_key=seed, signer_id="")


def test_custom_signer_id_is_used() -> None:
    seed, _ = generate_keypair()
    log = AuditLog(MemoryBackend(), signing_key=seed, signer_id="auditor-2026")
    assert log.signer_id == "auditor-2026"


# ---------------------------------------------------------------- log.verify()


async def test_audit_log_verify_checks_its_own_signatures() -> None:
    log, _ = await _signed_log(MemoryBackend())

    report = await log.verify()

    assert report.ok, report.reason
    assert report.signed_records == 2


async def test_audit_log_verify_on_a_rewritten_log_fails() -> None:
    log, public = await _signed_log(MemoryBackend())
    records = await log.read()
    log._last = None  # noqa: SLF001 - simulate a different process reading the file

    tampered = MemoryBackend()
    await tampered.append(replace(records[0], actor="mallory"))
    await tampered.append(records[1])

    reader = AuditLog(tampered, seal_key=SEAL_KEY)
    report = await reader.verify(signers={"s0": public})

    assert not report.ok


async def test_public_key_property_exposes_only_the_public_half() -> None:
    log, public = await _signed_log(MemoryBackend())

    assert log.public_key is not None
    assert log.public_key.public_bytes_raw() == public


async def test_unsigned_log_reports_no_signatures() -> None:
    log = AuditLog(MemoryBackend(), seal_key=SEAL_KEY)
    await log.append("alice", "login")

    assert log.public_key is None
    report = await log.verify()
    assert report.ok
    assert report.signed_records == 0


# ---------------------------------------------------------------- storage roundtrip


async def test_signatures_survive_the_jsonl_backend(tmp_path) -> None:
    path = tmp_path / "audit.jsonl"
    log, public = await _signed_log(JsonlBackend(path))
    await log.close()

    line = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert line["signer_id"] == "s0"
    assert line["signature"]

    reopened = AuditLog(JsonlBackend(path), seal_key=SEAL_KEY)
    report = await reopened.verify(signers={"s0": public})
    assert report.ok, report.reason
    assert report.signed_records == 2


async def test_unsigned_jsonl_lines_gain_no_new_keys(tmp_path) -> None:
    """Old files must not change shape just because signing exists."""
    path = tmp_path / "plain.jsonl"
    log = AuditLog(JsonlBackend(path), seal_key=SEAL_KEY)
    await log.append("alice", "login")
    await log.close()

    line = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert "signer_id" not in line
    assert "signature" not in line


async def test_signatures_survive_the_sqlite_backend(tmp_path) -> None:
    path = tmp_path / "audit.sqlite"
    log, public = await _signed_log(SqliteBackend(path))
    await log.close()

    reopened = AuditLog(SqliteBackend(path), seal_key=SEAL_KEY)
    report = await reopened.verify(signers={"s0": public})
    assert report.ok, report.reason
    assert report.signed_records == 2


async def test_sqlite_migrates_a_database_without_signing_columns(tmp_path) -> None:
    """A database written before signing existed must be upgraded, not rejected."""
    import sqlite3

    path = tmp_path / "old.sqlite"
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE audit_records (
            seq INTEGER PRIMARY KEY, ts TEXT NOT NULL, actor TEXT NOT NULL,
            action TEXT NOT NULL, subject TEXT NOT NULL DEFAULT '',
            meta TEXT NOT NULL DEFAULT '{}', prev_hash TEXT NOT NULL,
            hash TEXT NOT NULL, key_id TEXT NOT NULL DEFAULT ''
        )
        """
    )
    conn.commit()
    conn.close()

    log = AuditLog(SqliteBackend(path), seal_key=SEAL_KEY)
    await log.append("alice", "login")
    records = await log.read()

    assert records[0].signature == ""
    report = await log.verify()
    assert report.ok, report.reason


async def test_append_many_signs_every_record() -> None:
    seed, public = generate_keypair()
    log = AuditLog(MemoryBackend(), seal_key=SEAL_KEY, signing_key=seed)
    await log.append_many([("a", "x", "", None), ("b", "y", "", None), ("c", "z", "", None)])

    report = await log.verify(signers={"s0": public})

    assert report.ok, report.reason
    assert report.signed_records == 3


# ---------------------------------------------------------------- CLI


def test_cli_keygen_writes_a_usable_keypair(tmp_path, capsys) -> None:
    private_path = tmp_path / "signing.key"
    public_path = tmp_path / "signing.pub"

    code = main(["keygen", "--private-out", str(private_path), "--public-out", str(public_path)])

    assert code == 0
    assert len(private_path.read_bytes()) == 32
    assert len(public_path.read_bytes()) == 32
    assert oct(private_path.stat().st_mode)[-3:] == "600"
    assert "public key hex:" in capsys.readouterr().out


def test_cli_keygen_refuses_to_overwrite(tmp_path, capsys) -> None:
    private_path = tmp_path / "signing.key"
    public_path = tmp_path / "signing.pub"
    main(["keygen", "--private-out", str(private_path), "--public-out", str(public_path)])
    capsys.readouterr()

    code = main(["keygen", "--private-out", str(private_path), "--public-out", str(public_path)])

    assert code == 2
    assert "already exists" in capsys.readouterr().err


def test_cli_verify_accepts_signer_files(tmp_path, capsys) -> None:
    log_path = tmp_path / "audit.jsonl"
    _, public = asyncio.run(_write_signed_file(log_path))
    public_path = tmp_path / "signing.pub"
    public_path.write_bytes(public)

    code = main(
        [
            "verify",
            str(log_path),
            "--seal-key-file",
            _write_seal_key(tmp_path),
            "--signer",
            f"s0={public_path}",
        ]
    )

    out = capsys.readouterr().out
    assert code == 0, out
    assert "signatures verified against: s0" in out


def test_cli_verify_fails_when_a_signature_was_stripped(tmp_path, capsys) -> None:
    log_path = tmp_path / "audit.jsonl"
    _, public = asyncio.run(_write_signed_file(log_path))

    lines = log_path.read_text(encoding="utf-8").splitlines()
    second = json.loads(lines[1])
    del second["signature"]
    lines[1] = json.dumps(second, sort_keys=True, separators=(",", ":"))
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    public_path = tmp_path / "signing.pub"
    public_path.write_bytes(public)
    code = main(
        [
            "verify",
            str(log_path),
            "--seal-key-file",
            _write_seal_key(tmp_path),
            "--signer",
            f"s0={public_path}",
        ]
    )

    out = capsys.readouterr().out
    assert code == 1
    assert "missing signature" in out


def test_load_signers_accepts_files_and_hex(tmp_path) -> None:
    seed, public = generate_keypair()
    key_file = tmp_path / "signing.pub"
    key_file.write_bytes(public)

    from_file = load_signers([f"s0={key_file}"])
    from_hex = load_signers([f"s0={public.hex()}"])

    assert from_file["s0"] == public
    assert from_hex["s0"] == public
    with pytest.raises(SignatureError):
        load_signers(["broken"])


async def _write_signed_file(path) -> tuple[None, bytes]:
    """Write a two-record signed log to ``path`` and return its public key."""
    log, public = await _signed_log(JsonlBackend(path))
    await log.close()
    return None, public


def _write_seal_key(tmp_path) -> str:
    path = tmp_path / "seal.key"
    path.write_bytes(SEAL_KEY)
    return str(path)
