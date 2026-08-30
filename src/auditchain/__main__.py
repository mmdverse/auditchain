"""Command line interface: ``python -m auditchain verify <log>``."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

from .backends import JsonlBackend, SqliteBackend, StorageBackend
from .log import AuditLog
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


async def _verify(
    path: Path, fmt: str, expected_count: int | None, seal_key_file: Path | None
) -> VerifyReport:
    backend = _build_backend(path, fmt)
    seal_key = seal_key_file.read_bytes() if seal_key_file is not None else None
    log = AuditLog(backend, seal_key=seal_key)
    try:
        return await log.verify(expected_count=expected_count)
    finally:
        await log.close()


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
        "--seal-key-file",
        type=Path,
        default=None,
        help="read the HMAC seal key from this file",
    )

    args = parser.parse_args(argv)

    if args.command == "verify":
        try:
            fmt = _detect_format(args.path, args.format)
        except ValueError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
        if not args.path.exists():
            print(f"error: {args.path} does not exist", file=sys.stderr)
            return 2
        try:
            report = asyncio.run(_verify(args.path, fmt, args.expected_count, args.seal_key_file))
        except Exception as exc:  # noqa: BLE001 - CLI boundary
            print(f"error: {exc}", file=sys.stderr)
            return 2
        print(report)
        return 0 if report.ok else 1

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
