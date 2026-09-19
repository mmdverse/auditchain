"""Tests for Merkle inclusion proofs and Merkle-anchored checkpoints."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace

import pytest

from auditchain import (
    AuditLog,
    MemoryBackend,
    SqliteBackend,
    load_checkpoint,
    merkle_proof,
    merkle_root,
    save_checkpoint,
)
from auditchain.merkle import EMPTY_ROOT, InclusionProof, leaf_hash
from auditchain.verify import verify_chain

SEAL_KEY = b"hunter2-hunter2-hunter2-hunter2"


def _hashes(n: int) -> list[str]:
    """n distinct fake record hashes (64 hex chars each)."""
    return [f"{i:064x}" for i in range(1, n + 1)]


async def _log(n: int = 5, *, sealed: bool = False):
    log = AuditLog(MemoryBackend(), seal_key=SEAL_KEY if sealed else None)
    for i in range(n):
        await log.append("sara", f"action-{i}", metadata={"i": i})
    return log


# --------------------------------------------------------------------------- roots


def test_root_of_an_empty_log_is_defined_and_stable():
    assert merkle_root([]) == EMPTY_ROOT
    assert merkle_root(iter([])) == EMPTY_ROOT


def test_single_record_root_is_the_leaf_hash():
    hashes = _hashes(1)
    assert merkle_root(hashes) == leaf_hash(hashes[0]).hex()
    # ...and never the raw record hash: leaves are domain-separated.
    assert merkle_root(hashes) != hashes[0]


def test_root_is_deterministic_and_order_sensitive():
    hashes = _hashes(7)
    assert merkle_root(hashes) == merkle_root(list(hashes))
    swapped = [hashes[1], hashes[0], *hashes[2:]]
    assert merkle_root(swapped) != merkle_root(hashes)


def test_root_changes_when_a_record_changes():
    hashes = _hashes(6)
    edited = [*hashes]
    edited[3] = "f" * 64
    assert merkle_root(edited) != merkle_root(hashes)


def test_root_of_a_log_matches_the_records_it_covers():
    async def run() -> None:
        log = await _log(9)
        records = await log.read()
        assert await log.merkle_root() == merkle_root([r.hash for r in records])

    asyncio.run(run())


# -------------------------------------------------------------------------- proofs


@pytest.mark.parametrize("size", range(1, 34))
def test_every_record_in_every_size_has_a_valid_proof(size):
    hashes = _hashes(size)
    root = merkle_root(hashes)
    for seq in range(size):
        proof = merkle_proof(hashes, seq)
        assert proof.verify(root), f"size {size} seq {seq}"
        assert proof.root == root
        assert proof.size == size and proof.seq == seq
        assert proof.leaf == hashes[seq]


@pytest.mark.parametrize("size", [1, 2, 3, 4, 5, 8, 9, 16, 17, 1000])
def test_proofs_are_logarithmic_in_size(size):
    proof = merkle_proof(_hashes(size), size // 2)
    assert len(proof.path) <= (size - 1).bit_length()


def test_proof_round_trips_through_json():
    hashes = _hashes(13)
    proof = merkle_proof(hashes, 7)
    restored = InclusionProof.from_json(json.loads(proof.dumps()))
    assert restored == proof
    assert restored.verify(merkle_root(hashes))


def test_seq_outside_the_log_is_rejected():
    hashes = _hashes(4)
    with pytest.raises(ValueError, match="outside the log"):
        merkle_proof(hashes, 4)
    with pytest.raises(ValueError, match="outside the log"):
        merkle_proof(hashes, -1)


def test_fold_rejects_a_proof_that_claims_an_impossible_position():
    proof = merkle_proof(_hashes(8), 2)
    with pytest.raises(ValueError, match="outside a log"):
        replace(proof, seq=9).fold()
    with pytest.raises(ValueError, match="size must be at least 1"):
        replace(proof, size=0).fold()


# ------------------------------------------------------------------- proof tampering


def test_a_different_leaf_does_not_verify():
    hashes = _hashes(8)
    proof = merkle_proof(hashes, 3)
    forged = replace(proof, leaf="e" * 64)
    assert not forged.verify()
    assert not forged.verify(merkle_root(hashes))


def test_a_tampered_sibling_does_not_verify():
    hashes = _hashes(8)
    proof = merkle_proof(hashes, 5)
    path = list(proof.path)
    path[0] = replace(path[0], hash="d" * 64)
    assert not replace(proof, path=tuple(path)).verify(merkle_root(hashes))


def test_a_sibling_on_the_wrong_side_does_not_verify():
    hashes = _hashes(8)
    proof = merkle_proof(hashes, 1)
    path = list(proof.path)
    path[0] = replace(path[0], side="left" if path[0].side == "right" else "right")
    assert not replace(proof, path=tuple(path)).verify(merkle_root(hashes))


def test_an_unknown_side_is_malformed():
    proof = merkle_proof(_hashes(4), 0)
    path = list(proof.path)
    path[0] = replace(path[0], side="middle")
    with pytest.raises(ValueError, match="unknown sibling side"):
        replace(proof, path=tuple(path)).fold()


def test_a_proof_does_not_verify_against_another_logs_root():
    proof = merkle_proof(_hashes(8), 2)
    assert not proof.verify(merkle_root(_hashes(9)))
    assert not proof.verify(merkle_root([_hashes(8)[0]]))


def test_a_proof_cannot_be_replayed_at_a_different_index():
    hashes = _hashes(8)
    proof = merkle_proof(hashes, 2)
    # same path, but claiming it belongs to another position
    moved = replace(proof, seq=3)
    assert not moved.verify(merkle_root(hashes))


def test_missing_and_extra_path_steps_are_rejected():
    hashes = _hashes(8)
    proof = merkle_proof(hashes, 6)
    root = merkle_root(hashes)

    short = replace(proof, path=proof.path[:-1])
    assert not short.verify(root)
    with pytest.raises(ValueError, match="malformed inclusion proof"):
        short.fold()

    long = replace(proof, path=(*proof.path, proof.path[0]))
    assert not long.verify(root)
    with pytest.raises(ValueError, match="malformed inclusion proof"):
        long.fold()

    # a path for a bigger tree cannot be replayed at size 1: the leftover hashes are
    # rejected instead of being ignored
    with pytest.raises(ValueError, match="extra hashes"):
        replace(proof, size=1, seq=0).fold()


def test_a_leaf_cannot_be_passed_off_as_an_interior_node():
    # Interior nodes are hashed with a different prefix, so a raw record hash used as a
    # sibling never folds back to the real root.
    hashes = _hashes(2)
    proof = merkle_proof(hashes, 0)
    forged = replace(proof, path=(replace(proof.path[0], hash=hashes[1]),))
    assert not forged.verify(merkle_root(hashes))


def test_duplicating_the_last_leaf_does_not_reproduce_the_root():
    # The RFC 6962 construction promotes odd nodes instead of duplicating them, so a
    # 3-record log cannot be passed off as a 4-record log (the classic ambiguity).
    hashes = _hashes(3)
    padded = [*hashes, hashes[-1]]
    proof = merkle_proof(padded, 0)
    assert not proof.verify(merkle_root(hashes))
    assert proof.verify(merkle_root(padded))


# -------------------------------------------------------------- log-level integration


def test_inclusion_proof_from_the_log_verifies():
    async def run() -> None:
        log = await _log(11, sealed=True)
        root = await log.merkle_root()
        for seq in range(11):
            proof = await log.inclusion_proof(seq)
            assert proof.verify(root)
            assert proof.leaf == (await log.read())[seq].hash

    asyncio.run(run())


def test_inclusion_proof_out_of_range_on_a_real_log():
    async def run() -> None:
        log = await _log(3)
        with pytest.raises(ValueError, match="outside the log"):
            await log.inclusion_proof(3)

    asyncio.run(run())


# ----------------------------------------------------------------------- checkpoints


def test_checkpoint_carries_the_root_of_everything_behind_it():
    async def run() -> None:
        log = await _log(6, sealed=True)
        checkpoint = await log.checkpoint()
        records = await log.read()
        assert checkpoint.merkle_root == merkle_root([r.hash for r in records])
        report = await log.verify(checkpoint=checkpoint)
        assert report.ok, report
        assert report.merkle_root == checkpoint.merkle_root

    asyncio.run(run())


def test_checkpoint_file_round_trip_keeps_the_root_signed(tmp_path):
    async def run():
        log = await _log(4, sealed=True)
        return await log.checkpoint()

    checkpoint = asyncio.run(run())
    path = tmp_path / "audit.checkpoint"
    save_checkpoint(checkpoint, path)
    payload = json.loads(path.read_text())
    assert payload["version"] == 2
    assert payload["merkle_root"] == checkpoint.merkle_root

    loaded = load_checkpoint(path, SEAL_KEY)
    assert loaded.merkle_root == checkpoint.merkle_root

    # the root is inside the signed message: rewriting it is detected
    payload["merkle_root"] = "a" * 64
    path.write_text(json.dumps(payload))
    with pytest.raises(ValueError, match="checkpoint signature mismatch"):
        load_checkpoint(path, SEAL_KEY)


def test_checkpoint_without_a_root_keeps_the_v2_0_format(tmp_path):
    async def run():
        log = await _log(3, sealed=True)
        records = await log.read()
        return records

    records = asyncio.run(run())
    from auditchain.checkpoint import make_checkpoint

    legacy = make_checkpoint(records[-1], SEAL_KEY)  # no merkle root, as in 0.2.0
    path = tmp_path / "legacy.checkpoint"
    save_checkpoint(legacy, path)
    payload = json.loads(path.read_text())
    assert payload["version"] == 1 and "merkle_root" not in payload
    assert load_checkpoint(path, SEAL_KEY).signature == legacy.signature


def test_a_truncated_log_is_caught_by_the_checkpoint_anchor_and_root():
    async def run() -> None:
        log = await _log(6, sealed=True)
        checkpoint = await log.checkpoint()
        records = await log.read()

        truncated = records[:4]  # the last two records are dropped
        report = verify_chain(truncated, SEAL_KEY, keyring={"k0": SEAL_KEY}, checkpoint=checkpoint)
        assert not report.ok
        assert "truncation" in (report.reason or "")

        # and the root alone is enough for the CLI/verify-proof path: it covers a
        # different prefix, so a proof for the shortened log cannot match it
        shorter_root = merkle_root([r.hash for r in truncated])
        assert shorter_root != checkpoint.merkle_root
        with pytest.raises(ValueError):
            merkle_proof([r.hash for r in truncated], 5)

    asyncio.run(run())


def test_a_rewritten_log_does_not_match_the_signed_root():
    async def run() -> None:
        log = await _log(5, sealed=True)
        checkpoint = await log.checkpoint()
        records = await log.read()

        # An insider with the seal key rebuilds the log: same length, valid chain,
        # every hash recomputed with the real key. The chain check alone accepts this.
        forged = [replace(records[0], actor="mallory")]
        from auditchain.hash import compute_record_hash

        forged[0] = replace(forged[0], hash=compute_record_hash(forged[0], SEAL_KEY))
        for record in records[1:]:
            rebuilt = replace(record, prev_hash=forged[-1].hash)
            forged.append(replace(rebuilt, hash=compute_record_hash(rebuilt, SEAL_KEY)))

        keyring = {"k0": SEAL_KEY}
        assert verify_chain(forged, SEAL_KEY, keyring=keyring).ok  # hashes alone: undetected
        report = verify_chain(forged, SEAL_KEY, keyring=keyring, checkpoint=checkpoint)
        assert not report.ok
        assert report.reason is not None

    asyncio.run(run())


# ------------------------------------------------------------------------------- CLI


def _fill(tmp_path, n=6, *, sealed=True):
    path = tmp_path / "audit.sqlite"

    async def run():
        log = AuditLog(SqliteBackend(path), seal_key=SEAL_KEY if sealed else None, key_id="k0")
        for i in range(n):
            await log.append("sara", f"action-{i}", metadata={"i": i})
        await log.close()

    asyncio.run(run())
    if sealed:
        (tmp_path / "seal.key").write_bytes(SEAL_KEY)
    return path


def test_cli_proof_and_verify_proof_with_a_root(tmp_path, capsys):
    from auditchain.__main__ import main

    path = _fill(tmp_path)
    proof_path = tmp_path / "proof.json"
    assert main(["proof", str(path), "--seq", "3", "--output", str(proof_path)]) == 0
    capsys.readouterr()

    proof = json.loads(proof_path.read_text())
    assert proof["seq"] == 3 and proof["size"] == 6 and len(proof["path"]) <= 3

    # the checkpoint is the natural source of the trusted root
    checkpoint_path = tmp_path / "audit.checkpoint"
    assert (
        main(
            [
                "checkpoint",
                str(path),
                "--seal-key-file",
                str(tmp_path / "seal.key"),
                "--output",
                str(checkpoint_path),
            ]
        )
        == 0
    )
    capsys.readouterr()
    assert proof["root"] == json.loads(checkpoint_path.read_text())["merkle_root"]

    rc = main(
        [
            "verify-proof",
            str(proof_path),
            "--root",
            proof["root"],
        ]
    )
    assert rc == 0 and "OK" in capsys.readouterr().out

    rc = main(
        [
            "verify-proof",
            str(proof_path),
            "--checkpoint",
            str(checkpoint_path),
            "--seal-key-file",
            str(tmp_path / "seal.key"),
        ]
    )
    assert rc == 0
    assert "OK" in capsys.readouterr().out


def test_cli_verify_proof_rejects_a_forged_proof(tmp_path, capsys):
    from auditchain.__main__ import main

    path = _fill(tmp_path)
    proof_path = tmp_path / "proof.json"
    main(["proof", str(path), "--seq", "4", "--output", str(proof_path)])
    capsys.readouterr()

    payload = json.loads(proof_path.read_text())
    root = payload["root"]
    payload["leaf"] = "b" * 64  # swap in another record
    proof_path.write_text(json.dumps(payload))

    rc = main(["verify-proof", str(proof_path), "--root", root])
    assert rc == 1
    assert "FAILED" in capsys.readouterr().err


def test_cli_verify_proof_needs_a_root(tmp_path, capsys):
    from auditchain.__main__ import main

    path = _fill(tmp_path)
    proof_path = tmp_path / "proof.json"
    main(["proof", str(path), "--seq", "0", "--output", str(proof_path)])
    capsys.readouterr()

    assert main(["verify-proof", str(proof_path)]) == 2
    assert "which root" in capsys.readouterr().err


def test_cli_proof_refuses_a_log_that_contradicts_the_checkpoint(tmp_path, capsys):
    from auditchain.__main__ import main

    path = _fill(tmp_path)
    checkpoint_path = tmp_path / "audit.checkpoint"
    main(
        [
            "checkpoint",
            str(path),
            "--seal-key-file",
            str(tmp_path / "seal.key"),
            "--output",
            str(checkpoint_path),
        ]
    )
    capsys.readouterr()

    # extend the log after the checkpoint: the old root no longer covers the log
    async def extend():
        log = AuditLog(SqliteBackend(path), seal_key=SEAL_KEY, key_id="k0")
        await log.append("sara", "action-later")
        await log.close()

    asyncio.run(extend())

    rc = main(
        [
            "proof",
            str(path),
            "--seq",
            "0",
            "--checkpoint",
            str(checkpoint_path),
            "--seal-key-file",
            str(tmp_path / "seal.key"),
        ]
    )
    assert rc == 2
    assert "merkle root mismatch" in capsys.readouterr().err


def test_cli_verify_proof_rejects_a_proof_beyond_the_checkpoint(tmp_path, capsys):
    from auditchain.__main__ import main

    path = _fill(tmp_path, n=8)
    proof_path = tmp_path / "proof.json"
    main(["proof", str(path), "--seq", "7", "--output", str(proof_path)])
    capsys.readouterr()

    # checkpoint the first five records only
    short = tmp_path / "short.sqlite"

    async def build_short():
        log = AuditLog(SqliteBackend(short), seal_key=SEAL_KEY, key_id="k0")
        for i in range(5):
            await log.append("sara", f"action-{i}")
        await log.close()

    asyncio.run(build_short())
    checkpoint_path = tmp_path / "short.checkpoint"
    main(
        [
            "checkpoint",
            str(short),
            "--seal-key-file",
            str(tmp_path / "seal.key"),
            "--output",
            str(checkpoint_path),
        ]
    )
    capsys.readouterr()

    rc = main(
        [
            "verify-proof",
            str(proof_path),
            "--checkpoint",
            str(checkpoint_path),
            "--seal-key-file",
            str(tmp_path / "seal.key"),
        ]
    )
    assert rc == 2
    assert "beyond the checkpoint" in capsys.readouterr().err


def test_cli_verify_proof_against_an_unsigned_checkpoint(tmp_path, capsys):
    from auditchain.__main__ import main

    path = _fill(tmp_path, sealed=False)
    proof_path = tmp_path / "proof.json"
    main(["proof", str(path), "--seq", "2", "--output", str(proof_path)])
    capsys.readouterr()

    checkpoint_path = tmp_path / "audit.checkpoint"
    main(["checkpoint", str(path), "--output", str(checkpoint_path)])
    capsys.readouterr()
    assert json.loads(checkpoint_path.read_text())["merkle_root"]

    assert main(["verify-proof", str(proof_path), "--checkpoint", str(checkpoint_path)]) == 0
    assert "OK" in capsys.readouterr().out
