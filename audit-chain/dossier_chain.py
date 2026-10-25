"""Defense-Dossier: hash-chain wrapper over the hardened AuditLog.

What this is
------------
The demo (defense_dossier_demo.py, NOT modified, NOT imported here) anchors
leaves in a Merkle tree: Leaf -> content_hash() -> leaf_hash() -> root.
This wrapper adds a second, independent layer next to it: a per-record
hash chain (Sonnet's hardened AuditLog) over the same leaves. The Merkle
tree answers "is this leaf in the batch, and is the batch anchored?";
the chain answers "in which order were records appended, and was any of
them altered or reordered afterwards?". Neither replaces the other.

Mapping: one demo Leaf -> one chain event (schema v1)
----------------------------------------------------
event = {
    "v": 1,                          # wrapper schema version
    "kind": "leaf",
    "submitter_id": leaf.submitter_id,   # str
    "role": leaf.role,                   # str
    "period": leaf.period,               # int
    "claimed_date": leaf.claimed_date,   # str
    "content": leaf.content,             # demo content verbatim (plain JSON)
    "content_hash": leaf.content_hash(), # demo's own hash, not recomputed here
    "leaf_hash": leaf.leaf_hash(),       # demo's own hash, binds chain to Merkle leaf
    "signature": leaf.signature,         # str or None
    "ingestion_ts": leaf.ingestion_ts,   # finite float
}
append_leaf() accepts a demo Leaf object (duck-typed: it calls its
content_hash()/leaf_hash() methods) or a plain dict with exactly these
fields. It never reimplements the demo's hashing: for objects it trusts
the demo's own methods; for dicts it requires the caller to supply the
hashes. That way a drift between demo hashing and wrapper hashing is
impossible by construction.

Validation, in order
--------------------
1. Wrapper text check: total length of ALL string keys and string values
   in the event must fit MAX_TEXT (1_000_000), and the walk itself is
   capped at MAX_NODES (100_000) so shared-reference DAGs and cycles
   are rejected fast instead of expanding forever. This closes a hole in the
   hardened module itself: there the limit is only enforced when a string
   VALUE is popped, so an event made of one huge KEY with numeric leaves
   slips through. The hardened file is kept byte-identical to Sonnet's
   version; the fix lives here, at the wrapper layer.
2. Hardened checks: exact types (no subclasses, so Tagged/StrictInt are
   rejected), depth <= 64, nodes <= 100_000, ints in [-2**63, 2**64 - 1],
   finite floats, plain JSON only. Anything else raises TypeError/ValueError
   at append time and is never recorded. The wrapper never coerces:
   coercion (int keys -> str, tuple -> list, NaN) was the original
   defect family of file A, and silent coercion is refused on principle.

What this does NOT do
---------------------
- It does not modify defense_dossier_demo.py, its Merkle tree, its
  reconciliation, its access control, or its mock signer/TSA/anchor.
- It does not sign, timestamp, or anchor anything: anchor_package()
  only RETURNS the pair (merkle_root, chain_head) for the caller's
  TSA/anchor adapters to consume.
- It does not verify Merkle proofs: use the demo's verify_merkle_proof()
  for that. verify_leaf_binding() only checks that chain events match
  demo leaves field by field (it catches a re-hashed chain built over
  substituted content, which chain verify alone cannot see).

API
---
DossierChain: append(event), append_leaf(leaf), head(), records(),
  verify(records=None, anchor=None), anchor_package(merkle_root),
  verify_leaf_binding(records, leaves) [static].
AuditLog = DossierChain, verify = hardened verify: this module can be
  run through effects_matrix.py directly (it passes 41/41, like the
  hardened module it wraps).

Only the standard library is used.
"""
from __future__ import annotations

import importlib.util
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location(
    "dd_audit_log_hardened", os.path.join(_HERE, "audit_log_hardened.py")
)
_hardened = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_hardened)

HardenedAuditLog = _hardened.AuditLog
verify = _hardened.verify
MAX_TEXT = _hardened.MAX_TEXT
MAX_NODES = _hardened.MAX_NODES

_LEAF_FIELDS = (
    "submitter_id", "role", "period", "claimed_date", "content",
    "content_hash", "leaf_hash", "signature", "ingestion_ts",
)


def _total_text(event) -> int:
    """Sum of lengths of all string keys and string values, iterative.

    Raises TypeError on any value that is not plain JSON (None, bool,
    int, float, str, list, dict with str keys) and ValueError as soon
    as the node cap or the text cap is exceeded. The node cap matters:
    without it a shared-reference DAG (2**40 expanded nodes) or a cycle
    would make this walk expand forever; the hardened check caps nodes
    too, but it runs after this one, so this walk must cap itself.
    """
    total = 0
    nodes = 0
    stack = [event]
    while stack:
        value = stack.pop()
        nodes += 1
        if nodes > MAX_NODES:
            raise ValueError("event has too many nodes")
        kind = type(value)
        if value is None or kind is bool or kind is int or kind is float:
            continue
        if kind is str:
            total += len(value)
            if total > MAX_TEXT:
                raise ValueError("event text is too long")
            continue
        if kind is list:
            stack.extend(value)
            continue
        if kind is dict:
            for key, item in value.items():
                if type(key) is not str:
                    raise TypeError("dict keys must be str")
                total += len(key)
                if total > MAX_TEXT:
                    raise ValueError("event text is too long")
                stack.append(item)
            continue
        raise TypeError("unsupported type: " + kind.__name__)
    return total


def _check_text(event) -> None:
    _total_text(event)


def leaf_event(leaf) -> dict:
    """Build a v1 chain event from a demo Leaf (object or dict)."""
    if isinstance(leaf, dict):
        missing = [f for f in _LEAF_FIELDS if f not in leaf]
        if missing:
            raise ValueError("leaf dict is missing fields: %s" % ",".join(missing))
        fields = {f: leaf[f] for f in _LEAF_FIELDS}
    else:
        try:
            fields = {f: getattr(leaf, f) for f in _LEAF_FIELDS
                      if f not in ("content_hash", "leaf_hash")}
            fields["content_hash"] = leaf.content_hash()
            fields["leaf_hash"] = leaf.leaf_hash()
        except AttributeError as exc:
            raise TypeError(
                "leaf must provide submitter_id, role, period, claimed_date, "
                "content, signature, ingestion_ts and content_hash()/leaf_hash()"
            ) from exc
    return {"v": 1, "kind": "leaf", **fields}


class DossierChain:
    """Hash chain over Defense-Dossier leaves (see module docstring)."""

    def __init__(self) -> None:
        self._log = HardenedAuditLog()

    def append(self, event: dict) -> str:
        """Append a raw plain-JSON event (matrix-compatible)."""
        _check_text(event)
        return self._log.append(event)

    def append_leaf(self, leaf) -> str:
        """Append one demo Leaf as a v1 event; returns the record hash."""
        return self.append(leaf_event(leaf))

    def head(self) -> str:
        """Hash of the last record, "" for an empty chain."""
        return self._log.head()

    def records(self) -> list:
        """Independent copy of the chain records."""
        return self._log.records()

    def verify(self, records=None, anchor=None):
        """None if the chain is intact, else the first bad position,
        or len(records) on anchor mismatch (see hardened verify)."""
        if records is None:
            records = self.records()
        return verify(records, anchor)

    def anchor_package(self, merkle_root: str) -> dict:
        """Dual anchor for the caller's TSA/anchor adapters.

        Returns (not signs, not timestamps, not anchors):
        the Merkle root of the batch and the chain head over the same
        leaves, plus the record count.
        """
        return {
            "merkle_root": merkle_root,
            "chain_head": self.head(),
            "records": len(self.records()),
        }

    @staticmethod
    def verify_leaf_binding(records, leaves):
        """Check chain events against demo leaves, field by field.

        Returns None if every record matches its leaf (content,
        content_hash, leaf_hash and all metadata). Otherwise the first
        mismatching position; if the lengths differ, the first position
        past the shorter side. This catches content substitution even
        in a freshly re-hashed chain, which chain verify alone cannot.
        """
        records = list(records)
        leaves = list(leaves)
        for i in range(max(len(records), len(leaves))):
            if i >= len(records) or i >= len(leaves):
                return i
            event = records[i]["event"]
            leaf = leaves[i]
            try:
                expected = leaf_event(leaf)
            except (TypeError, ValueError):
                return i
            if event != expected:
                return i
        return None


# Matrix-compatible aliases: effects_matrix.py needs AuditLog + verify.
AuditLog = DossierChain

__all__ = [
    "DossierChain", "AuditLog", "verify", "leaf_event",
    "HardenedAuditLog", "MAX_TEXT", "MAX_NODES",
]
