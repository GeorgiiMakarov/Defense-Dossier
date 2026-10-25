"""Tests for dossier_chain.py. Read-only against the demo repo: the demo
module is imported, never modified; all writes go to the wrapper objects.

Run: python3 test_dossier_chain.py [path/to/effects_matrix.py]
If the matrix path is missing, the matrix part is skipped (SKIP, not fail).
"""
import importlib.util
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEMO = os.path.expanduser(
    "~/workspace/repos/Defense-Dossier/defense_dossier_demo.py")
MATRIX_DEFAULT = os.path.expanduser(
    "~/workspace/user/files/effects_matrix_1_9wnb.py")

sys.path.insert(0, HERE)
import dossier_chain as dc  # noqa: E402


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check(name, cond):
    print(("PASS " if cond else "FAIL ") + name)
    if not cond:
        raise SystemExit(1)


def main():
    demo = load(DEMO, "defense_dossier_demo")
    leaves = demo.make_synthetic_leaves()
    check("demo leaves: 8 (4 developer + 4 inspector)", len(leaves) == 8)

    # 1. Full demo flow through the wrapper.
    chain = dc.DossierChain()
    hashes = [chain.append_leaf(leaf) for leaf in leaves]
    check("8 appends, distinct hashes", len(set(hashes)) == 8)
    check("head matches last hash", chain.head() == hashes[-1])
    check("own records verify None", chain.verify() is None)
    check("binding: events match leaves", chain.verify_leaf_binding(chain.records(), leaves) is None)

    # 2. Dual anchor: Merkle root (demo) + chain head (wrapper).
    leaf_hashes = [leaf.leaf_hash() for leaf in leaves]
    levels = demo.build_merkle_tree(leaf_hashes)
    root = levels[-1][0]
    pkg = chain.anchor_package(root)
    check("anchor package: root + head + count",
          pkg["merkle_root"] == root and pkg["chain_head"] == chain.head()
          and pkg["records"] == 8)
    proof = demo.merkle_proof(levels, 2)
    check("demo Merkle proof still valid",
          demo.verify_merkle_proof(leaf_hashes[2], proof, root))

    # 3. Tamper: content change -> chain index; re-hashed chain -> binding.
    recs = chain.records()
    recs[2]["event"]["content"] = {**recs[2]["event"]["content"], "spend_pct": 45}
    check("tampered content detected at 2", chain.verify(recs) == 2)
    check("binding detects tampered content at 2",
          dc.DossierChain.verify_leaf_binding(recs, leaves) == 2)
    # Attacker rebuilds the chain over substituted content: chain verify
    # passes (fresh hashes), but binding must still catch it.
    evil = dc.DossierChain()
    for leaf in leaves:
        evil.append_leaf(leaf)
    evil_recs = evil.records()
    victim = demo.Leaf(submitter_id=leaves[2].submitter_id, role=leaves[2].role,
                       period=leaves[2].period,
                       content={**leaves[2].content, "spend_pct": 45},
                       claimed_date=leaves[2].claimed_date,
                       ingestion_ts=leaves[2].ingestion_ts,
                       signature=leaves[2].signature)
    rebuilt = dc.DossierChain()
    for i, leaf in enumerate(leaves):
        rebuilt.append_leaf(victim if i == 2 else leaf)
    check("re-hashed chain verifies clean (expected)",
          rebuilt.verify() is None)
    check("binding catches re-hashed substitution at 2",
          dc.DossierChain.verify_leaf_binding(rebuilt.records(), leaves) == 2)
    check("binding length mismatch reported",
          dc.DossierChain.verify_leaf_binding(chain.records()[:5], leaves) == 5)

    # 4. Dict-form leaves work; raw events work (matrix path uses these).
    raw = dc.DossierChain()
    raw.append({"n": 0, "tag": "e0"})
    check("raw dict event appends", raw.verify() is None)
    dict_leaf = {
        "submitter_id": leaves[0].submitter_id, "role": leaves[0].role,
        "period": leaves[0].period, "claimed_date": leaves[0].claimed_date,
        "content": leaves[0].content, "content_hash": leaves[0].content_hash(),
        "leaf_hash": leaves[0].leaf_hash(), "signature": leaves[0].signature,
        "ingestion_ts": leaves[0].ingestion_ts,
    }
    d2 = dc.DossierChain()
    d2.append_leaf(dict_leaf)
    check("dict-form leaf matches object-form hash",
          d2.records()[0]["hash"] == chain.records()[0]["hash"])

    # 5. Wrapper-layer limits: the key-text hole is closed here.
    try:
        dc.DossierChain().append({"K" * 2_000_000: 1})
        huge_key_rejected = False
    except ValueError:
        huge_key_rejected = True
    check("huge-key-only event rejected by wrapper", huge_key_rejected)
    for name, event in [
        ("Tagged dict", None),
    ]:
        pass
    # Subclass rejection comes from the hardened layer (kept verbatim).
    class Tagged(dict):
        def __eq__(self, other):
            return dict.__eq__(self, other) and (
                not isinstance(other, Tagged) or self.tag == other.tag)
    tagged = Tagged(a=1)
    tagged.tag = 1
    try:
        dc.DossierChain().append(tagged)
        tagged_rejected = False
    except TypeError:
        tagged_rejected = True
    check("Tagged dict rejected", tagged_rejected)

    # 6. Effects matrix against the wrapper module itself.
    matrix = sys.argv[1] if len(sys.argv) > 1 else MATRIX_DEFAULT
    if not os.path.exists(matrix):
        print("SKIP matrix run (file not found: %s)" % matrix)
        return
    proc = subprocess.run(
        [sys.executable, matrix, "--json", os.path.join(HERE, "dossier_chain.py")],
        capture_output=True, text=True, timeout=300)
    results = json.loads(proc.stdout)
    key = "dossier_chain.py"
    total = sum(results[key].values())
    failed = [eid for eid, ok in results[key].items() if not ok]
    check("matrix against wrapper: 41/41 (failed: %s)" % failed, total == 41)
    print("ALL GREEN")


if __name__ == "__main__":
    main()
