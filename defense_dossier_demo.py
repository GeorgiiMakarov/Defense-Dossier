import hashlib
import json
import time
from dataclasses import dataclass, field
from typing import Optional

@dataclass
class Leaf:
    submitter_id: str
    role: str
    period: int
    content: dict
    claimed_date: str
    ingestion_ts: float = field(default_factory=time.time)
    signature: Optional[str] = None

    def content_hash(self) -> str:
        payload = json.dumps(self.content, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def leaf_hash(self) -> str:
        record = {
            "content_hash": self.content_hash(),
            "submitter_id": self.submitter_id,
            "role": self.role,
            "signature": self.signature,
            "ingestion_ts": self.ingestion_ts,
        }
        payload = json.dumps(record, sort_keys=True, ensure_ascii=False)
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

def mock_ecp_sign(submitter_id: str, content_hash: str) -> str:
    raw = f"MOCK-SIGNATURE:{submitter_id}:{content_hash}".encode()
    return hashlib.sha256(raw).hexdigest()[:16]

def _hash_pair(a: str, b: str) -> str:
    return hashlib.sha256((a + b).encode("utf-8")).hexdigest()

def build_merkle_tree(leaf_hashes):
    levels = [leaf_hashes[:]]
    current = leaf_hashes[:]
    while len(current) > 1:
        nxt = []
        for i in range(0, len(current), 2):
            left = current[i]
            right = current[i + 1] if i + 1 < len(current) else current[i]
            nxt.append(_hash_pair(left, right))
        levels.append(nxt)
        current = nxt
    return levels

def merkle_proof(levels, index):
    proof = []
    idx = index
    for level in levels[:-1]:
        is_right = idx % 2 == 1
        sibling_idx = idx - 1 if is_right else idx + 1
        if sibling_idx < len(level):
            proof.append((level[sibling_idx], "L" if is_right else "R"))
        idx //= 2
    return proof

def verify_merkle_proof(leaf_hash, proof, root):
    current = leaf_hash
    for sibling, side in proof:
        current = _hash_pair(sibling, current) if side == "L" else _hash_pair(current, sibling)
    return current == root

def mock_rfc3161_timestamp(root_hash: str) -> dict:
    return {
        "root": root_hash,
        "tsa": "MOCK-НУЦ-РК-TSA",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "token": hashlib.sha256(f"MOCK-TSA-TOKEN:{root_hash}".encode()).hexdigest()[:24],
    }

def mock_public_anchor(root_hash: str) -> dict:
    return {
        "root": root_hash,
        "anchor_type": "MOCK-PUBLIC-ANCHOR",
        "ref": "0x" + hashlib.sha256(f"MOCK-ANCHOR-REF:{root_hash}".encode()).hexdigest(),
    }

DISCREPANCY_THRESHOLD_PCT = 15

def reconcile(developer_leaves, inspector_leaves):
    by_period_dev = {l.period: l.content["spend_pct"] for l in developer_leaves}
    by_period_insp = {l.period: l.content["physical_progress_pct"] for l in inspector_leaves}
    results = []
    for period in sorted(set(by_period_dev) & set(by_period_insp)):
        dev_pct = by_period_dev[period]
        insp_pct = by_period_insp[period]
        gap = dev_pct - insp_pct
        flagged = abs(gap) > DISCREPANCY_THRESHOLD_PCT
        results.append({
            "period": period,
            "developer_spend_pct": dev_pct,
            "inspector_physical_pct": insp_pct,
            "gap_pct": gap,
            "flagged": flagged,
        })
    return results

VIEW_RULES = {
    "public": {"period", "claimed_date", "role", "verified"},
    "bank": {"period", "claimed_date", "role", "verified", "spend_pct", "physical_progress_pct", "gap_pct", "flagged"},
    "kzk": {"period", "claimed_date", "role", "verified", "spend_pct", "physical_progress_pct", "gap_pct", "flagged", "submitter_id"},
    "internal": None,
}

def access_control_view(record: dict, viewer_role: str) -> dict:
    allowed = VIEW_RULES.get(viewer_role)
    if allowed is None:
        return dict(record)
    return {k: v for k, v in record.items() if k in allowed}

@dataclass
class AuthToken:
    holder: str
    bound_role: str

def issue_token(holder: str, bound_role: str) -> AuthToken:
    return AuthToken(holder=holder, bound_role=bound_role)

def public_api_endpoint(record: dict, token: AuthToken, requested_role: str = None) -> dict:
    return access_control_view(record, token.bound_role)

def make_synthetic_leaves():
    developer_data = [
        {"period": 1, "spend_pct": 22, "doc": "Акт КС-2 №1, накладные на арматуру"},
        {"period": 2, "spend_pct": 41, "doc": "Акт КС-2 №2, накладные на бетон"},
        {"period": 3, "spend_pct": 68, "doc": "Акт КС-2 №3, накладные на кладку"},
        {"period": 4, "spend_pct": 83, "doc": "Акт КС-2 №4, накладные на фасад"},
    ]
    inspector_data = [
        {"period": 1, "physical_progress_pct": 20, "doc": "Полевой отчёт: фундамент залит"},
        {"period": 2, "physical_progress_pct": 38, "doc": "Полевой отчёт: коробка 1 этаж"},
        {"period": 3, "physical_progress_pct": 44, "doc": "Полевой отчёт: коробка 2 этаж"},
        {"period": 4, "physical_progress_pct": 79, "doc": "Полевой отчёт: фасад начат"},
    ]
    leaves = []
    for d in developer_data:
        preview_hash = hashlib.sha256(json.dumps(d, sort_keys=True).encode()).hexdigest()
        leaf = Leaf(submitter_id="developer_obj17", role="developer", period=d["period"], content=d, claimed_date=f"2026-P{d['period']}")
        leaf.signature = mock_ecp_sign(leaf.submitter_id, preview_hash)
        leaves.append(leaf)
    for i in inspector_data:
        preview_hash = hashlib.sha256(json.dumps(i, sort_keys=True).encode()).hexdigest()
        leaf = Leaf(submitter_id="inspector_independent_llp", role="inspector", period=i["period"], content=i, claimed_date=f"2026-P{i['period']}")
        leaf.signature = mock_ecp_sign(leaf.submitter_id, preview_hash)
        leaves.append(leaf)
    return leaves

def run_demo():
    print("=" * 70)
    print("DEFENSE DOSSIER — синтетическое демо (1 объект, 4 периода)")
    print("=" * 70)
    leaves = make_synthetic_leaves()
    developer_leaves = [l for l in leaves if l.role == "developer"]
    inspector_leaves = [l for l in leaves if l.role == "inspector"]
    print(f"\n[1] Батч: {len(leaves)} листьев")
    leaf_hashes = [l.leaf_hash() for l in leaves]
    levels = build_merkle_tree(leaf_hashes)
    root = levels[-1][0]
    print(f"[2] Merkle root: {root}")
    ts = mock_rfc3161_timestamp(root)
    print(f"[3] RFC 3161 (MOCK): {ts['tsa']}, {ts['timestamp']}")
    anchor = mock_public_anchor(root)
    print(f"[4] Анкер (MOCK): {anchor['anchor_type']}")
    print(f"\n[5] Reconciliation (порог {DISCREPANCY_THRESHOLD_PCT}%)")
    print("-" * 70)
    for r in reconcile(developer_leaves, inspector_leaves):
        flag = "РАСХОЖДЕНИЕ" if r["flagged"] else "OK"
        print(f" Период {r['period']}: {r['developer_spend_pct']}% vs {r['inspector_physical_pct']}% -> {flag} ({r['gap_pct']:+.0f}%)")
    print(f"\n[6] Merkle-proof")
    target_leaf = next(l for l in leaves if l.role == "developer" and l.period == 3)
    target_index = leaves.index(target_leaf)
    proof = merkle_proof(levels, target_index)
    is_valid = verify_merkle_proof(target_leaf.leaf_hash(), proof, root)
    print(f" Проверка листа P3: {'ПОДТВЕРЖДЕНО' if is_valid else 'ОШИБКА'}")
    print(f"\n[7] Подделка")
    tampered = Leaf(submitter_id=target_leaf.submitter_id, role=target_leaf.role, period=target_leaf.period, content={**target_leaf.content, "spend_pct": 45}, claimed_date=target_leaf.claimed_date, ingestion_ts=target_leaf.ingestion_ts, signature=target_leaf.signature)
    tampered_valid = verify_merkle_proof(tampered.leaf_hash(), proof, root)
    print(f" 68 -> 45: {'ОТКЛОНЕНО' if not tampered_valid else 'ОШИБКА'}")
    print(f"\n[8] Access Control Service")
    period3 = next(r for r in reconcile(developer_leaves, inspector_leaves) if r["period"] == 3)
    full_record = {"period": 3, "claimed_date": "2026-P3", "role": "reconciliation", "verified": True, "spend_pct": 68, "physical_progress_pct": 44, "gap_pct": 24, "flagged": True, "submitter_id": "developer_obj17"}
    for role in ("public", "bank", "kzk"):
        print(f" {role}: {access_control_view(full_record, role)}")
    print(f"\n[9] Bypass-resistance")
    public_token = issue_token("dolshik_ivanov", "public")
    attempted = public_api_endpoint(full_record, public_token, requested_role="kzk")
    print(f" Токен public просит kzk -> получает: {attempted}")

if __name__ == "__main__":
    run_demo()
