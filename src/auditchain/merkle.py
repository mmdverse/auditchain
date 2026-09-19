"""Merkle inclusion proofs over a batch of records.

The hash chain proves that *nothing* in the log was changed — but checking it means
holding every record. A Merkle tree adds the other half: given a root that someone
trusted (a checkpoint, published or exchanged out of band), a single record can be
proven to be part of that exact log with ~log2(n) hashes and without disclosing the
rest of the records.

The tree follows RFC 6962 (the Certificate Transparency construction): leaves are
``SHA256(0x00 || record_hash)``, internal nodes are ``SHA256(0x01 || left || right)``,
and a node with an odd number of children is *promoted* rather than duplicated. The
domain prefix stops a leaf hash from being read as an interior node, and promoting
instead of duplicating removes the classic "duplicate the last node" ambiguity, so a
proof cannot be replayed at another size.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"
EMPTY_ROOT = hashlib.sha256(b"").hexdigest()


def _as_int(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"malformed inclusion proof: {field_name} must be an integer")
    return value


def _as_str(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"malformed inclusion proof: {field_name} must be a string")
    return value


def leaf_hash(record_hash: str) -> bytes:
    """Hash a record hash into a tree leaf."""
    return hashlib.sha256(LEAF_PREFIX + bytes.fromhex(record_hash)).digest()


def _node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(NODE_PREFIX + left + right).digest()


def _split(size: int) -> int:
    """Largest power of two strictly below ``size`` (RFC 6962 split point)."""
    k = 1
    while k * 2 < size:
        k *= 2
    return k


def _subtree_root(leaves: Sequence[bytes]) -> bytes:
    if len(leaves) == 1:
        return leaves[0]
    k = _split(len(leaves))
    return _node_hash(_subtree_root(leaves[:k]), _subtree_root(leaves[k:]))


def merkle_root(record_hashes: Iterable[str]) -> str:
    """Merkle root of a list of record hashes (hex). Empty batch → ``EMPTY_ROOT``."""
    leaves = [leaf_hash(h) for h in record_hashes]
    if not leaves:
        return EMPTY_ROOT
    return _subtree_root(leaves).hex()


@dataclass(frozen=True, slots=True)
class ProofStep:
    """One sibling on the way from the leaf to the root.

    Steps are ordered bottom-up: ``path[0]`` is the sibling closest to the leaf and the
    last step combines with the root's other child.
    """

    side: str  # "left" or "right": where the sibling sits relative to the running hash
    hash: str

    def to_json(self) -> dict[str, str]:
        return {"side": self.side, "hash": self.hash}


@dataclass(frozen=True, slots=True)
class InclusionProof:
    """Proof that the record at ``seq`` is part of a log of ``size`` records."""

    seq: int
    size: int
    leaf: str  # the record hash being proven
    root: str  # the root this proof folds to
    path: tuple[ProofStep, ...] = field(default_factory=tuple)

    def to_json(self) -> dict[str, object]:
        return {
            "version": 1,
            "seq": self.seq,
            "size": self.size,
            "leaf": self.leaf,
            "root": self.root,
            "path": [step.to_json() for step in self.path],
        }

    def dumps(self, *, indent: int | None = None) -> str:
        return json.dumps(self.to_json(), sort_keys=True, indent=indent)

    def save(self, path: str | Path) -> None:
        Path(path).write_text(self.dumps(indent=2) + "\n", encoding="utf-8")

    @classmethod
    def from_json(cls, payload: Mapping[str, Any]) -> InclusionProof:
        raw_path = payload.get("path", [])
        if not isinstance(raw_path, list):
            raise ValueError("malformed inclusion proof: path must be a list")
        try:
            path = tuple(
                ProofStep(side=_as_str(step["side"], "side"), hash=_as_str(step["hash"], "hash"))
                for step in raw_path
            )
            return cls(
                seq=_as_int(payload["seq"], "seq"),
                size=_as_int(payload["size"], "size"),
                leaf=_as_str(payload["leaf"], "leaf"),
                root=_as_str(payload["root"], "root"),
                path=path,
            )
        except (KeyError, TypeError) as exc:
            raise ValueError(f"malformed inclusion proof: {exc}") from exc

    @classmethod
    def load(cls, path: str | Path) -> InclusionProof:
        return cls.from_json(json.loads(Path(path).read_text(encoding="utf-8")))

    def fold(self) -> str:
        """Recompute the root from the leaf and the path; raise if the path is malformed."""
        if self.size < 1:
            raise ValueError("proof size must be at least 1")
        if not 0 <= self.seq < self.size:
            raise ValueError(f"seq {self.seq} is outside a log of {self.size} record(s)")
        steps = list(self.path)
        try:
            # the proof discloses the record hash; the tree leaf is its hash under the
            # leaf prefix, exactly as it was built
            root = _fold(self.seq, self.size, leaf_hash(self.leaf), steps)
        except (ValueError, IndexError) as exc:
            raise ValueError(f"malformed inclusion proof: {exc}") from exc
        if steps:
            raise ValueError("malformed inclusion proof: extra hashes in the path")
        return root.hex()

    def verify(self, root: str | None = None) -> bool:
        """True if the path folds to ``root`` (or to the proof's own root when omitted)."""
        expected = self.root if root is None else root
        try:
            return self.fold() == expected.lower()
        except ValueError:
            return False


def _fold(index: int, size: int, leaf: bytes, steps: list[ProofStep]) -> bytes:
    """Walk the path bottom-up, mirroring the split rule used to build the tree.

    Levels are consumed from the top of the tree downwards, so the sibling for the
    current (outer) level is the last step left on the path.
    """
    if size == 1:
        return leaf
    step = steps.pop()
    if step.side not in ("left", "right"):
        raise ValueError(f"unknown sibling side {step.side!r}")
    sibling = bytes.fromhex(step.hash)
    k = _split(size)
    if index < k:
        if step.side != "right":
            raise ValueError("sibling side does not match the tree position")
        return _node_hash(_fold(index, k, leaf, steps), sibling)
    if step.side != "left":
        raise ValueError("sibling side does not match the tree position")
    return _node_hash(sibling, _fold(index - k, size - k, leaf, steps))


def merkle_proof(record_hashes: Sequence[str], seq: int) -> InclusionProof:
    """Build an inclusion proof for the record at position ``seq`` (0-based)."""
    if not 0 <= seq < len(record_hashes):
        raise ValueError(f"seq {seq} is outside the log ({len(record_hashes)} records)")
    leaves = [leaf_hash(h) for h in record_hashes]
    path: list[ProofStep] = []
    _collect(leaves, seq, path)
    path.reverse()  # the proof reads from the leaf up to the root
    return InclusionProof(
        seq=seq,
        size=len(record_hashes),
        leaf=record_hashes[seq],
        root=_subtree_root(leaves).hex(),
        path=tuple(path),
    )


def _collect(leaves: Sequence[bytes], index: int, path: list[ProofStep]) -> None:
    if len(leaves) == 1:
        return
    k = _split(len(leaves))
    if index < k:
        path.append(ProofStep("right", _subtree_root(leaves[k:]).hex()))
        _collect(leaves[:k], index, path)
    else:
        path.append(ProofStep("left", _subtree_root(leaves[:k]).hex()))
        _collect(leaves[k:], index - k, path)
