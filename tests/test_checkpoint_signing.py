"""Ed25519-signed checkpoints: anchors an outsider can verify with a public key."""

from __future__ import annotations

import asyncio
import json

import pytest

from auditchain import (
    AuditLog,
    MemoryBackend,
    SqliteBackend,
    load_checkpoint,
    save_checkpoint,
)
from auditchain.checkpoint import checkpoint_message, verify_checkpoint_signature
from auditchain.signing import generate_keypair

pytest.importorskip("cryptography", reason="requires the 'ed25519' extra")

SEAL_KEY = b"seal-key-long-enough-for-hmac"
SEED, PUBLIC = generate_keypair()
OTHER_SEED, OTHER_PUBLIC = generate_keypair()


async def _log(n: int = 4, *, signing_key=SEED, seal_key=SEAL_KEY):
    log = AuditLog(
        MemoryBackend(), seal_key=seal_key, signing_key=signing_key, signer_id="anchor-key"
    )
    for i in range(n):
        await log.append("sara", f"action-{i}")
    return log


# ------------------------------------------------------------------ the anchor


def test_checkpoint_is_signed_with_the_logs_signing_key():
    async def run():
        log = await _log()
        checkpoint = await log.checkpoint()
        assert checkpoint.signature_ed25519
        assert checkpoint.signer_id == "anchor-key"
        assert checkpoint.signature  # the HMAC is still there when sealed
        assert checkpoint.merkle_root
        return checkpoint

    checkpoint = asyncio.run(run())
    assert verify_checkpoint_signature(checkpoint, PUBLIC)
    assert not verify_checkpoint_signature(checkpoint, OTHER_PUBLIC)


def test_the_signature_covers_the_merkle_root():
    async def run():
        return await (await _log()).checkpoint()

    checkpoint = asyncio.run(run())
    from dataclasses import replace

    moved = replace(checkpoint, merkle_root="f" * 64)
    assert not verify_checkpoint_signature(moved, PUBLIC)  # the root is inside the message


def test_a_log_without_a_signing_key_writes_an_unsigned_anchor():
    async def run():
        log = await _log(signing_key=None)
        return await log.checkpoint()

    checkpoint = asyncio.run(run())
    assert checkpoint.signature_ed25519 == "" and checkpoint.signer_id == ""
    assert verify_checkpoint_signature(checkpoint, PUBLIC) is False


def test_the_message_is_the_same_one_the_hmac_covers():
    assert checkpoint_message(3, "a" * 64, "k0") == f"3:{'a' * 64}:k0".encode()
    assert checkpoint_message(3, "a" * 64, "k0", "b" * 64) == (
        f"3:{'a' * 64}:k0:{'b' * 64}".encode()
    )


# ------------------------------------------------------------------ the file


def test_signed_checkpoint_round_trips_and_verifies_with_the_public_key(tmp_path):
    async def run():
        return await (await _log()).checkpoint()

    checkpoint = asyncio.run(run())
    path = tmp_path / "audit.checkpoint"
    save_checkpoint(checkpoint, path)

    payload = json.loads(path.read_text())
    assert payload["version"] == 3
    assert payload["signer_id"] == "anchor-key"
    assert payload["signature_ed25519"] == checkpoint.signature_ed25519

    loaded = load_checkpoint(path, public_key=PUBLIC)
    assert loaded.merkle_root == checkpoint.merkle_root
    assert loaded.signature_ed25519 == checkpoint.signature_ed25519


def test_a_signed_checkpoint_refuses_to_load_without_a_key(tmp_path):
    async def run():
        return await (await _log()).checkpoint()

    path = tmp_path / "c.checkpoint"
    save_checkpoint(asyncio.run(run()), path)

    # not with the seal key alone...
    with pytest.raises(ValueError, match="pass the public key"):
        load_checkpoint(path, seal_key=SEAL_KEY)
    # ...and not with nothing at all: an unverified anchor is not an anchor
    with pytest.raises(ValueError, match="pass the public key"):
        load_checkpoint(path)


def test_the_wrong_public_key_is_rejected(tmp_path):
    async def run():
        return await (await _log()).checkpoint()

    path = tmp_path / "c.checkpoint"
    save_checkpoint(asyncio.run(run()), path)
    with pytest.raises(ValueError, match="signature mismatch"):
        load_checkpoint(path, public_key=OTHER_PUBLIC)


def test_editing_the_file_is_detected(tmp_path):
    async def run():
        return await (await _log()).checkpoint()

    path = tmp_path / "c.checkpoint"
    save_checkpoint(asyncio.run(run()), path)

    for field, value in (
        ("merkle_root", "0" * 64),
        ("seq", 99),
        ("hash", "1" * 64),
        ("signer_id", "someone-else"),
    ):
        payload = json.loads(path.read_text())
        payload[field] = value
        path.write_text(json.dumps(payload))
        with pytest.raises(ValueError, match="signature mismatch"):
            load_checkpoint(path, public_key=PUBLIC)


def test_older_checkpoint_formats_still_load(tmp_path):
    """v1 (0.2.0, HMAC only) and v2 (HMAC + root) keep working."""

    async def run():
        log = AuditLog(MemoryBackend(), seal_key=SEAL_KEY)
        for i in range(3):
            await log.append("sara", f"action-{i}")
        return await log.read(), log

    records, log = asyncio.run(run())
    from auditchain.checkpoint import make_checkpoint

    legacy = make_checkpoint(records[-1], SEAL_KEY)  # no root, no Ed25519
    path = tmp_path / "legacy.checkpoint"
    save_checkpoint(legacy, path)
    assert json.loads(path.read_text())["version"] == 1
    assert load_checkpoint(path, SEAL_KEY).hash == legacy.hash

    rooted = make_checkpoint(records[-1], SEAL_KEY, "c" * 64)  # root, HMAC only
    save_checkpoint(rooted, path)
    assert json.loads(path.read_text())["version"] == 2
    assert load_checkpoint(path, SEAL_KEY).merkle_root == "c" * 64


# ------------------------------------------------------------ verify integration


def test_verify_against_a_public_key_verified_anchor():
    async def run():
        log = await _log()
        checkpoint = await log.checkpoint()
        report = await log.verify(checkpoint=checkpoint)
        return checkpoint, report

    checkpoint, report = asyncio.run(run())
    assert report.ok, report
    assert report.merkle_root == checkpoint.merkle_root


def test_sync_facade_signs_its_checkpoints():
    from auditchain import SyncAuditLog

    facade = SyncAuditLog(MemoryBackend(), seal_key=SEAL_KEY, signing_key=SEED)
    facade.append("sara", "login")
    checkpoint = facade.checkpoint()
    assert verify_checkpoint_signature(checkpoint, PUBLIC)
    facade.close()


# ------------------------------------------------------------------------- CLI


def _fill(tmp_path, n=5):
    path = tmp_path / "audit.sqlite"

    async def run():
        log = AuditLog(SqliteBackend(path), seal_key=SEAL_KEY)
        for i in range(n):
            await log.append("sara", f"action-{i}")
        await log.close()

    asyncio.run(run())
    (tmp_path / "seal.key").write_bytes(SEAL_KEY)
    return path


def test_cli_checkpoint_signs_with_ed25519(tmp_path, capsys):
    from auditchain.__main__ import main

    path = _fill(tmp_path)
    (tmp_path / "signing.key").write_bytes(SEED)
    checkpoint_path = tmp_path / "audit.checkpoint"

    rc = main(
        [
            "checkpoint",
            str(path),
            "--seal-key-file",
            str(tmp_path / "seal.key"),
            "--signing-key",
            str(tmp_path / "signing.key"),
            "--signer-id",
            "release-key",
            "--output",
            str(checkpoint_path),
        ]
    )
    out = capsys.readouterr().out
    assert rc == 0 and "Ed25519-signed by release-key" in out

    payload = json.loads(checkpoint_path.read_text())
    assert payload["version"] == 3 and payload["signer_id"] == "release-key"

    # usable on the verify path with the public key only
    assert (
        main(
            [
                "verify",
                str(path),
                "--seal-key-file",
                str(tmp_path / "seal.key"),
                "--checkpoint",
                str(checkpoint_path),
                "--public-key",
                str(tmp_path / "signing.key"),
            ]
        )
        == 2  # a private key is not a public key
    )
    capsys.readouterr()


def test_cli_accepts_the_public_key_as_hex_and_as_a_file(tmp_path, capsys):
    from auditchain.__main__ import main

    path = _fill(tmp_path)
    (tmp_path / "signing.key").write_bytes(SEED)
    (tmp_path / "signing.pub").write_bytes(PUBLIC)
    checkpoint_path = tmp_path / "audit.checkpoint"
    main(
        [
            "checkpoint",
            str(path),
            "--seal-key-file",
            str(tmp_path / "seal.key"),
            "--signing-key",
            str(tmp_path / "signing.key"),
            "--output",
            str(checkpoint_path),
        ]
    )
    capsys.readouterr()

    for key in (str(tmp_path / "signing.pub"), PUBLIC.hex()):
        rc = main(
            [
                "verify",
                str(path),
                "--seal-key-file",
                str(tmp_path / "seal.key"),
                "--checkpoint",
                str(checkpoint_path),
                "--public-key",
                key,
            ]
        )
        assert rc == 0, f"public key as {key!r}"
        assert "OK" in capsys.readouterr().out


def test_cli_verify_proof_with_a_public_key_and_no_seal_key(tmp_path, capsys):
    """The whole point: an auditor with a public key and a proof file, nothing else."""
    from auditchain.__main__ import main

    path = _fill(tmp_path, n=6)
    (tmp_path / "signing.key").write_bytes(SEED)
    (tmp_path / "signing.pub").write_bytes(PUBLIC)
    checkpoint_path = tmp_path / "audit.checkpoint"
    proof_path = tmp_path / "proof.json"

    main(
        [
            "checkpoint",
            str(path),
            "--seal-key-file",
            str(tmp_path / "seal.key"),
            "--signing-key",
            str(tmp_path / "signing.key"),
            "--output",
            str(checkpoint_path),
        ]
    )
    main(["proof", str(path), "--seq", "4", "--output", str(proof_path)])
    capsys.readouterr()

    rc = main(
        [
            "verify-proof",
            str(proof_path),
            "--checkpoint",
            str(checkpoint_path),
            "--public-key",
            str(tmp_path / "signing.pub"),
        ]
    )
    assert rc == 0
    assert "OK" in capsys.readouterr().out


def test_cli_verify_proof_rejects_a_tampered_signed_checkpoint(tmp_path, capsys):
    from auditchain.__main__ import main

    path = _fill(tmp_path)
    (tmp_path / "signing.key").write_bytes(SEED)
    (tmp_path / "signing.pub").write_bytes(PUBLIC)
    checkpoint_path = tmp_path / "audit.checkpoint"
    proof_path = tmp_path / "proof.json"
    main(
        [
            "checkpoint",
            str(path),
            "--signing-key",
            str(tmp_path / "signing.key"),
            "--output",
            str(checkpoint_path),
        ]
    )
    main(["proof", str(path), "--seq", "1", "--output", str(proof_path)])
    capsys.readouterr()

    payload = json.loads(checkpoint_path.read_text())
    payload["merkle_root"] = "e" * 64
    checkpoint_path.write_text(json.dumps(payload))

    rc = main(
        [
            "verify-proof",
            str(proof_path),
            "--checkpoint",
            str(checkpoint_path),
            "--public-key",
            str(tmp_path / "signing.pub"),
        ]
    )
    assert rc == 2
    assert "signature mismatch" in capsys.readouterr().err
