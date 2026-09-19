"""Command line interface: ``python -m auditchain verify|checkpoint|proof <log>``."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from .backends import JsonlBackend, SqliteBackend, StorageBackend
from .checkpoint import Checkpoint, load_checkpoint, save_checkpoint
from .log import AuditLog
from .merkle import InclusionProof
from .signing import (
    SignatureError,
    describe_signers,
    generate_keypair,
    load_signers,
)
from .verify import VerifyReport

_JSONL_SUFFIXES = {".jsonl", ".ndjson"}
_SQLITE_SUFFIXES = {".sqlite", ".sqlite3", ".db"}


def _build_backend(path: Path, fmt: str) -> StorageBackend:
    if fmt == "jsonl":
        return JsonlBackend(path)
    return SqliteBackend(path)


def _detect_format(path: Path, fmt: str) -> str:
    if fmt != "auto":
        return fmt
    suffix = path.suffix.lower()
    if suffix in _JSONL_SUFFIXES:
        return "jsonl"
    if suffix in _SQLITE_SUFFIXES:
        return "sqlite"
    raise ValueError(f"cannot detect the storage format of {path}; pass --format jsonl|sqlite")


def _read_seal_key(seal_key_file: Path | None) -> bytes | None:
    return seal_key_file.read_bytes() if seal_key_file is not None else None


async def _verify(
    path: Path,
    fmt: str,
    expected_count: int | None,
    seal_key_file: Path | None,
    checkpoint_file: Path | None,
    signers: dict[str, object] | None = None,
) -> VerifyReport:
    backend = _build_backend(path, fmt)
    seal_key = _read_seal_key(seal_key_file)
    checkpoint = load_checkpoint(checkpoint_file, seal_key) if checkpoint_file is not None else None
    log = AuditLog(backend, seal_key=seal_key)
    try:
        return await log.verify(
            expected_count=expected_count, checkpoint=checkpoint, signers=signers
        )
    finally:
        await log.close()


async def _checkpoint(
    path: Path, fmt: str, output: Path | None, seal_key_file: Path | None
) -> Path:
    backend = _build_backend(path, fmt)
    seal_key = _read_seal_key(seal_key_file)
    log = AuditLog(backend, seal_key=seal_key)
    try:
        cp = await log.checkpoint()
    finally:
        await log.close()
    out = output if output is not None else Path(str(path) + ".checkpoint")
    save_checkpoint(cp, out)
    if cp.signature:
        print(f"checkpoint written to {out}: seq {cp.seq} (signed)")
    else:
        print(f"checkpoint written to {out}: seq {cp.seq} (unsigned — log has no seal key)")
    return out


async def _proof(
    path: Path, fmt: str, seq: int, checkpoint: Checkpoint | None, seal_key_file: Path | None
) -> InclusionProof:
    """Build an inclusion proof, refusing to prove a log that contradicts the checkpoint."""
    backend = _build_backend(path, fmt)
    log = AuditLog(backend, seal_key=_read_seal_key(seal_key_file))
    try:
        proof = await log.inclusion_proof(seq)
        if (
            checkpoint is not None
            and checkpoint.merkle_root
            and checkpoint.merkle_root != proof.root
        ):
            raise ValueError(
                "merkle root mismatch: the log does not match the checkpoint; "
                "refusing to produce a proof"
            )
    finally:
        await log.close()
    return proof


def _verify_proof(
    proof_path: Path, root: str | None, checkpoint_file: Path | None, seal_key_file: Path | None
) -> bool:
    proof = InclusionProof.load(proof_path)
    expected = root
    if expected is None and checkpoint_file is not None:
        checkpoint = load_checkpoint(checkpoint_file, _read_seal_key(seal_key_file))
        if not checkpoint.merkle_root:
            raise ValueError(f"{checkpoint_file} carries no merkle root to check against")
        if proof.seq > checkpoint.seq:
            raise ValueError(
                f"the proof is for seq {proof.seq}, beyond the checkpoint (seq {checkpoint.seq})"
            )
        if proof.size != checkpoint.seq + 1:
            raise ValueError(
                f"the proof covers {proof.size} record(s) but the checkpoint covers "
                f"{checkpoint.seq + 1}"
            )
        expected = checkpoint.merkle_root
    if expected is None:
        raise ValueError("pass --root HEX or --checkpoint to say which root to check against")
    return proof.verify(expected)


def _keygen(private_out: Path, public_out: Path, force: bool) -> int:
    """Write a new Ed25519 keypair: private seed plus the shareable public key."""
    for path in (private_out, public_out):
        if path.exists() and not force:
            print(f"error: {path} already exists (pass --force to overwrite)", file=sys.stderr)
            return 2

    seed, public = generate_keypair()
    private_out.parent.mkdir(parents=True, exist_ok=True)
    public_out.parent.mkdir(parents=True, exist_ok=True)
    private_out.write_bytes(seed)
    # The signing key must not be readable by anyone else; the public key is meant
    # to be shared, so it keeps the default permissions.
    private_out.chmod(0o600)
    public_out.write_bytes(public)
    print(f"private key: {private_out} (keep it secret, mode 600)")
    print(f"public key:  {public_out} (give this to whoever verifies the log)")
    print(f"public key hex: {public.hex()}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="auditchain",
        description="Tamper-evident, hash-chained audit logs.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    verify_parser = subparsers.add_parser(
        "verify", help="verify the integrity of an audit log (exit code 1 on failure)"
    )
    verify_parser.add_argument("path", type=Path, help="path to the audit log file")
    verify_parser.add_argument(
        "--format",
        choices=["auto", "jsonl", "sqlite"],
        default="auto",
        help="storage format (default: auto by file extension)",
    )
    verify_parser.add_argument(
        "--expected-count",
        type=int,
        default=None,
        help="fail if the log does not contain exactly this many records",
    )
    verify_parser.add_argument(
        "--checkpoint",
        type=Path,
        default=None,
        help="verify against this checkpoint anchor (detects tail truncation)",
    )
    verify_parser.add_argument(
        "--seal-key-file",
        type=Path,
        default=None,
        help="read the HMAC seal key from this file",
    )
    verify_parser.add_argument(
        "--signer",
        action="append",
        default=[],
        metavar="NAME=PATH|HEX",
        help="verify Ed25519 signatures against this public key (file or hex); "
        "repeat for several signers",
    )

    checkpoint_parser = subparsers.add_parser(
        "checkpoint", help="write a checkpoint anchor of the current chain"
    )
    checkpoint_parser.add_argument("path", type=Path, help="path to the audit log file")
    checkpoint_parser.add_argument(
        "--format",
        choices=["auto", "jsonl", "sqlite"],
        default="auto",
        help="storage format (default: auto by file extension)",
    )
    checkpoint_parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="where to write the checkpoint (default: <path>.checkpoint)",
    )
    checkpoint_parser.add_argument(
        "--seal-key-file",
        type=Path,
        default=None,
        help="sign the checkpoint with this HMAC seal key",
    )

    proof_parser = subparsers.add_parser(
        "proof", help="prove that one record is part of the log (Merkle inclusion proof)"
    )
    proof_parser.add_argument("path", type=Path, help="path to the audit log file")
    proof_parser.add_argument("--seq", type=int, required=True, help="sequence number to prove")
    proof_parser.add_argument(
        "--format",
        choices=["auto", "jsonl", "sqlite"],
        default="auto",
        help="storage format (default: auto by file extension)",
    )
    proof_parser.add_argument(
        "--checkpoint",
        type=Path,
        default=None,
        help="compare the log against this checkpoint first (refuses on mismatch)",
    )
    proof_parser.add_argument(
        "--seal-key-file", type=Path, default=None, help="seal key needed to open the checkpoint"
    )
    proof_parser.add_argument(
        "--output", type=Path, default=None, help="write the proof here (default: stdout)"
    )

    verify_proof_parser = subparsers.add_parser(
        "verify-proof",
        help="check an inclusion proof against a root (exit code 1 on failure)",
    )
    verify_proof_parser.add_argument("proof", type=Path, help="path to the proof JSON file")
    verify_proof_parser.add_argument(
        "--root", default=None, help="the trusted Merkle root to check against (hex)"
    )
    verify_proof_parser.add_argument(
        "--checkpoint",
        type=Path,
        default=None,
        help="take the trusted root from this signed checkpoint",
    )
    verify_proof_parser.add_argument(
        "--seal-key-file",
        type=Path,
        default=None,
        help="seal key needed to open a signed checkpoint",
    )

    keygen_parser = subparsers.add_parser(
        "keygen", help="generate an Ed25519 keypair for signing records"
    )
    keygen_parser.add_argument(
        "--private-out",
        type=Path,
        default=Path("auditchain-signing.key"),
        help="where to write the private key (default: auditchain-signing.key)",
    )
    keygen_parser.add_argument(
        "--public-out",
        type=Path,
        default=Path("auditchain-signing.pub"),
        help="where to write the public key (default: auditchain-signing.pub)",
    )
    keygen_parser.add_argument("--force", action="store_true", help="overwrite existing key files")

    args = parser.parse_args(argv)

    try:
        if args.command == "verify":
            fmt = _detect_format(args.path, args.format)
            if not args.path.exists():
                print(f"error: {args.path} does not exist", file=sys.stderr)
                return 2
            signers = load_signers(args.signer) if args.signer else None
            report = asyncio.run(
                _verify(
                    args.path,
                    fmt,
                    args.expected_count,
                    args.seal_key_file,
                    args.checkpoint,
                    signers,
                )
            )
            print(report)
            if report.ok and signers:
                print(f"signatures verified against: {describe_signers(signers)}")
            return 0 if report.ok else 1

        if args.command == "proof":
            fmt = _detect_format(args.path, args.format)
            if not args.path.exists():
                print(f"error: {args.path} does not exist", file=sys.stderr)
                return 2
            seal_key = _read_seal_key(args.seal_key_file)
            checkpoint = (
                load_checkpoint(args.checkpoint, seal_key) if args.checkpoint is not None else None
            )
            proof = asyncio.run(_proof(args.path, fmt, args.seq, checkpoint, args.seal_key_file))
            if args.output is not None:
                proof.save(args.output)
                print(f"proof for seq {proof.seq} written to {args.output}")
            else:
                print(proof.dumps(indent=2))
            return 0

        if args.command == "verify-proof":
            ok = _verify_proof(args.proof, args.root, args.checkpoint, args.seal_key_file)
            proof = InclusionProof.load(args.proof)
            if ok:
                print(f"OK: record {proof.seq} is part of the log of {proof.size} record(s)")
                print(f"merkle root: {proof.root}")
            else:
                print("FAILED: the proof does not match the trusted root", file=sys.stderr)
            return 0 if ok else 1

        if args.command == "keygen":
            return _keygen(args.private_out, args.public_out, args.force)

        if args.command == "checkpoint":
            fmt = _detect_format(args.path, args.format)
            if not args.path.exists():
                print(f"error: {args.path} does not exist", file=sys.stderr)
                return 2
            asyncio.run(_checkpoint(args.path, fmt, args.output, args.seal_key_file))
            return 0
    except SignatureError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
