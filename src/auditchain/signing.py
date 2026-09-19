"""Optional Ed25519 signatures for records and checkpoints.

HMAC (see :mod:`auditchain.hash`) proves authenticity only to parties that hold the
seal key — and anyone who can verify can also forge, because it is the same secret.
Ed25519 splits that in two: the writer keeps a private key and signs, while auditors
hold only the public key, so they can verify a log without being able to rewrite it.

The ``cryptography`` package is an optional dependency:

.. code-block:: bash

    pip install "auditchain[ed25519]"

Keys are raw 32-byte values. ``str`` keys are read as hex, which is what the
``auditchain keygen`` command prints.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .records import AuditRecord

try:  # pragma: no cover - exercised by the import-error test
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
        PublicFormat,
    )

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:  # pragma: no cover
    CRYPTOGRAPHY_AVAILABLE = False

INSTALL_HINT = (
    'Ed25519 signatures require the cryptography package: pip install "auditchain[ed25519]"'
)

_PRIVATE_KEY_LENGTH = 32
_PUBLIC_KEY_LENGTH = 32


class SignatureError(Exception):
    """Raised for signature-related configuration problems."""


class SignatureUnavailableError(SignatureError):
    """Raised when Ed25519 is used without the optional dependency installed."""


def _require_cryptography() -> None:
    if not CRYPTOGRAPHY_AVAILABLE:
        raise SignatureUnavailableError(INSTALL_HINT)


def _key_bytes(key: Any, *, expected_length: int, kind: str) -> bytes:
    """Normalize a raw/hex key into bytes of the expected length."""
    if isinstance(key, str):
        try:
            key = bytes.fromhex(key.strip())
        except ValueError as exc:
            raise SignatureError(f"{kind} must be raw bytes or hex") from exc
    if not isinstance(key, (bytes, bytearray)):
        raise SignatureError(f"{kind} must be bytes or a hex string")
    key = bytes(key)
    if len(key) != expected_length:
        raise SignatureError(f"{kind} must be {expected_length} bytes, got {len(key)}")
    return key


def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a new keypair as ``(private_seed, public_key)``, both raw 32 bytes."""
    _require_cryptography()
    private_key = Ed25519PrivateKey.generate()
    seed = private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    public = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return seed, public


def load_private_key(key: Any) -> Any:
    """Accept a raw/hex seed or an ``Ed25519PrivateKey`` and return a private key."""
    _require_cryptography()
    if isinstance(key, Ed25519PrivateKey):
        return key
    return Ed25519PrivateKey.from_private_bytes(
        _key_bytes(key, expected_length=_PRIVATE_KEY_LENGTH, kind="private key")
    )


def load_public_key(key: Any) -> Any:
    """Accept a raw/hex public key or an ``Ed25519PublicKey`` and return a public key."""
    _require_cryptography()
    if isinstance(key, Ed25519PublicKey):
        return key
    return Ed25519PublicKey.from_public_bytes(
        _key_bytes(key, expected_length=_PUBLIC_KEY_LENGTH, kind="public key")
    )


def record_signing_message(record: AuditRecord) -> bytes:
    """The bytes covered by a record signature: ``seq:hash:signer_id``.

    The hash already commits to the previous hash and the payload, so signing it binds
    the record to its place in the chain. The sequence number and signer id are
    included so a signature cannot be lifted onto another record or attributed to
    another key.
    """
    return f"{record.seq}:{record.hash}:{record.signer_id}".encode()


def sign_record(record: AuditRecord, private_key: Any) -> str:
    """Return the hex Ed25519 signature for ``record``."""
    key = load_private_key(private_key)
    return key.sign(record_signing_message(record)).hex()


def verify_record_signature(record: AuditRecord, public_key: Any) -> bool:
    """Check a record's signature against a public key. Never raises on a bad signature."""
    key = load_public_key(public_key)
    try:
        key.verify(bytes.fromhex(record.signature), record_signing_message(record))
    except (InvalidSignature, ValueError):
        return False
    return True


def load_signers(specs: Sequence[str]) -> dict[str, bytes]:
    """Parse ``name=path`` pairs (as passed to the CLI) into a signer map.

    ``path`` may also be a hex public key directly, which is handy in CI where the key
    lives in a secret rather than a file.
    """
    signers: dict[str, bytes] = {}
    for spec in specs:
        name, _, value = spec.partition("=")
        name = name.strip()
        value = value.strip()
        if not name or not value:
            raise SignatureError(f"expected name=path or name=hex, got {spec!r}")
        if Path(value).is_file():
            signers[name] = Path(value).read_bytes()
        else:
            signers[name] = _key_bytes(value, expected_length=_PUBLIC_KEY_LENGTH, kind="public key")
    return signers


def describe_signers(signers: Mapping[str, Any] | None) -> str:
    """Human-readable summary of a signer map, for CLI output."""
    if not signers:
        return "no signers"
    return ", ".join(sorted(signers))
