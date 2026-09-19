# Verifying an audit log you do not own

*How an auditor, a customer or a regulator checks a log without getting the keys, the
database, or even the records.*

The person who needs to trust an audit log is almost never the person who runs it. They
are the auditor who shows up once a quarter, the customer asking whether the access
record is real, the regulator with a deadline. Handing them the database is both
impractical and dangerous: it exposes every record to someone who only needs to check
one, and it usually means handing over a credential that can also write.

This page is the workflow for the other side — verifying a log with artifacts that are
useless to anyone who wants to forge one.

## What the verifier needs

Three things, none of which is a secret:

| Artifact | What it gives them | How it travels |
|---|---|---|
| The public key | proves *who* wrote each record | a few lines in a config or a published fingerprint |
| The Merkle root | an anchor they can trust without trusting the log | one hex line, published hourly |
| An inclusion proof | proves one record is in that anchored log | ~log₂n hashes — 1,150 bytes for a 7,342-record log |

None of these lets the verifier write, re-seal, or forge anything. That is the whole
point: the sealing key and the signing key never leave the operator.

Two artifacts are **not** on that list, on purpose:

- **the seal key** — the verifier should not have it, because holding it also means being
  able to re-seal the log;
- **the signed checkpoint file** — its HMAC signature is what lets the *operator* prove
  later that they did not swap the anchor themselves, and checking that signature needs
  the seal key. For an outsider the anchor travels as the root in plain hex, published
  somewhere the log's writer cannot rewrite (see the note at the end).

## The workflow

**1. The operator certifies a state of the log.**

```bash
auditchain keygen --private-out signing.key --public-out signing.pub
auditchain checkpoint audit.sqlite --seal-key-file seal.key --output audit.checkpoint
```

The checkpoint says: *at this moment, the record at sequence 7,341 had this hash, and
everything up to it hashes to this Merkle root*. It is signed, and it is stored outside
the log — in a different system, a git repository, a transparency log. Anywhere the
log's own writer cannot rewrite later.

**2. The operator publishes the checkpoint** (web page, S3 object with a retention
policy, a commit in a public repository) and keeps the log itself where it is.

**3. The verifier checks the whole log, occasionally, if they have it.**

```bash
auditchain verify audit.sqlite --signer s0=signing.pub --checkpoint audit.checkpoint --seal-key-file seal.key
```

...or, without the seal key (they should not have it) and without the log:

**4. The verifier checks a single record, on demand.**

The operator produces the proof (their log, their checkpoint), and sends only the proof
file:

```bash
auditchain proof audit.sqlite --seq 7341 --checkpoint audit.checkpoint \
  --seal-key-file seal.key --output 7341.proof
# 7341.proof is 13 hashes for that 7,342-record log (1,150 bytes on disk);
# no other record and no key is in the file
```

The verifier checks it against the root they got from the published anchor — with no
key, no log, and no access to the system:

```bash
auditchain verify-proof 7341.proof --root 9f2c1e...b7a4     # the published hex root
```

Exit code `0` means the record is in the log that produced the published root. Exit code
`1` means it is not — or that the proof was altered on the way.

The same two steps in code:

```python
from auditchain import InclusionProof

proof = InclusionProof.load("7341.proof")
assert proof.verify(published_root)
assert proof.seq == 7341 and proof.size == 7342   # position and log size are committed
```

If the verifier *does* get the full log (a quarterly audit, say), they can recompute
everything themselves:

```python
from auditchain import merkle_root

assert merkle_root([record.hash for record in records]) == published_root
```

## What each failure means

| Output | What happened |
|---|---|
| `signature mismatch: the record was rewritten without the signing key` | someone edited a record and recomputed the chain — with the seal key, but without the signing key |
| `missing signature: the record is not signed` | signatures were stripped, or records were appended by a writer that does not sign |
| `checkpoint anchor mismatch` | the log was rebuilt, extended or truncated after the anchor was signed |
| `merkle root mismatch` | same, but caught by the content root rather than the tail hash |
| `the proof does not match the trusted root` | the record you were shown is not in the anchored log |
| `FAILED at seq N: prev_hash mismatch` | a record was removed, reordered or inserted in the middle |

## What this proves — and what it does not

**Proves.** Every record is unchanged since it was written. Records cannot be inserted,
removed, reordered or moved. Every signed record really came from the holder of the
signing key. Each verified proof shows a specific record is part of a specific anchored
state.

**Does not prove.** *Freshness*: an inclusion proof says "this record is in the log with
this root", and an old proof of an old root stays true forever. The timestamp inside the
record is written by the operator, so treat it as a claim unless the checkpoint was
published somewhere with an independent clock. A chain also cannot show that a record
was *never going to be deleted* — only that it was there when the anchor was signed.

**Still the operator's job.** Protecting the signing key. Publishing checkpoints on a
schedule so the gap between anchors stays small. Backing up the log. The library makes
the evidence verifiable; it cannot make anyone look at it.

## A minute-by-minute recipe

For a system that logs a few thousand events a day:

```bash
# hourly, by cron
auditchain checkpoint /var/lib/app/audit.sqlite \
  --seal-key-file /etc/app/seal.key --output /var/lib/app/checkpoints/$(date -u +%Y%m%dT%H%M)
# then ship the file somewhere the log's writer cannot touch
aws s3 cp /var/lib/app/checkpoints/ s3://audit-anchors/ --recursive --storage-class STANDARD_IA
```

```bash
# quarterly, by an auditor with no access to the application at all
auditchain verify-proof 7341.proof --root 9f2c1e...b7a4   # from the published anchor
```

That is the asymmetry worth building: the operator needs the keys to write; the auditor
needs nothing but a root they can check, on hardware they control.

## Where this stands today

The pieces above are what the library does now. One gap is worth naming instead of
hiding:

- **Record signatures are verifiable with a public key** (`auditchain verify --signer
  s0=signing.pub`) — the write side is asymmetric.
- **The anchor is not, yet.** A checkpoint's signature is HMAC, so checking it needs the
  seal key; that is why an outsider takes the root as a plain hex value and relies on
  *where* it was published for authenticity (a repository they do not control, an
  object-lock bucket, a transparency log). Signing checkpoints with the Ed25519 key
  instead would close the gap and let an auditor verify the anchor with the same public
  key they already have — until then, choose the publishing channel accordingly.
