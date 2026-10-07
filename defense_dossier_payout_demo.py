#!/usr/bin/env python3
"""
Defense-Dossier — банковский сценарий: проверяемый след выплат продавцам.

Синтетическое демо: один расчётный цикл (2026-W40), 5 продавцов.
Ядро (SHA-256, Merkle-дерево, Merkle-proof, доступ) — из defense_dossier_demo
БЕЗ ИЗМЕНЕНИЙ: сценарий — это данные поверх того же ядра.

Адаптеры (подпись / штамп времени / анкер) — заглушки. Банк подменяет
своими реализациями без правок ядра:
    signer -> ЭЦП по ГОСТ (КриптоПро)
    tsa    -> штамп времени аккредитованного УЦ (RFC 3161)
    anchor -> внутренний реестр банка

Запуск:  python3 defense_dossier_payout_demo.py     # только stdlib
"""
import hashlib
import time

from defense_dossier_demo import (
    Leaf,
    Signer,
    TimestampAuthority,
    Anchor,
    build_merkle_tree,
    merkle_proof,
    verify_merkle_proof,
    AuthToken,
    issue_token,
)

# ---------------------------------------------------------------------------
# Адаптеры для российского контура. Синтетика — значение по умолчанию.
# ---------------------------------------------------------------------------

class SyntheticGostSigner(Signer):
    """Заглушка вместо ЭЦП по ГОСТ (КриптоПро): детерминированная псевдо-подпись."""
    def sign(self, submitter_id: str, content_hash: str) -> str:
        raw = f"MOCK-GOST-SIGNATURE:{submitter_id}:{content_hash}".encode()
        return hashlib.sha256(raw).hexdigest()[:16]


class SyntheticAccreditedCaTsa(TimestampAuthority):
    """Заглушка вместо штампа времени аккредитованного УЦ (RFC 3161)."""
    def timestamp(self, root_hash: str) -> dict:
        return {
            "root": root_hash,
            "tsa": "MOCK-Аккредитованный-УЦ-TSA",
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime()),
            "token": hashlib.sha256(f"MOCK-CA-TSA-TOKEN:{root_hash}".encode()).hexdigest()[:24],
        }


class SyntheticBankRegistryAnchor(Anchor):
    """Заглушка вместо внутреннего реестра банка."""
    def anchor(self, root_hash: str) -> dict:
        return {
            "root": root_hash,
            "anchor_type": "MOCK-ВНУТРЕННИЙ-РЕЕСТР-БАНКА",
            "ref": "0x" + hashlib.sha256(f"MOCK-BANK-REGISTRY:{root_hash}".encode()).hexdigest(),
        }


signer: Signer = SyntheticGostSigner()
tsa: TimestampAuthority = SyntheticAccreditedCaTsa()
anchor: Anchor = SyntheticBankRegistryAnchor()

CYCLE = "2026-W40"

# Начисления на стороне платформы (поток 1): отчёт реализации -> баланс продавца
PLATFORM_ACCRUALS = [
    {"payout_id": "WB-2026W40-001", "seller_id": "seller_1", "amount_rub": 96500,
     "doc": "Отчёт реализации №40, заявка REQ-9001"},
    {"payout_id": "WB-2026W40-002", "seller_id": "seller_2", "amount_rub": 142300,
     "doc": "Отчёт реализации №40, заявка REQ-9002"},
    {"payout_id": "WB-2026W40-003", "seller_id": "seller_3", "amount_rub": 184500,
     "doc": "Отчёт реализации №40, заявка REQ-9003"},
    {"payout_id": "WB-2026W40-004", "seller_id": "seller_4", "amount_rub": 58750,
     "doc": "Отчёт реализации №40, заявка REQ-9004"},
    {"payout_id": "WB-2026W40-005", "seller_id": "seller_5", "amount_rub": 210000,
     "doc": "Отчёт реализации №40, заявка REQ-9005"},
]

# Перечисления на стороне банка (поток 2). В payout 003 сумма умышленно
# отличается: расхождение, которое должна найти сверка.
BANK_TRANSFERS = [
    {"payout_id": "WB-2026W40-001", "seller_id": "seller_1", "amount_rub": 96500,
     "doc": "Платёжное поручение №7701, зачислено на р/с"},
    {"payout_id": "WB-2026W40-002", "seller_id": "seller_2", "amount_rub": 142300,
     "doc": "Платёжное поручение №7702, зачислено на р/с"},
    {"payout_id": "WB-2026W40-003", "seller_id": "seller_3", "amount_rub": 182000,
     "doc": "Платёжное поручение №7703, зачислено на р/с"},
    {"payout_id": "WB-2026W40-004", "seller_id": "seller_4", "amount_rub": 58750,
     "doc": "Платёжное поручение №7704, зачислено на р/с"},
    {"payout_id": "WB-2026W40-005", "seller_id": "seller_5", "amount_rub": 210000,
     "doc": "Платёжное поручение №7705, зачислено на р/с"},
]

VIEW_RULES_PAYOUT = {
    # продавец проверяет только свою выплату: служебных хешей чужих данных нет
    "public": {"payout_id", "seller_id", "amount_rub", "verified"},
    # банк/комплаенс: плюс реквизиты операции
    "bank": {"payout_id", "seller_id", "amount_rub", "verified", "request_doc",
             "transfer_doc", "discrepancy_rub", "flagged"},
    # внутренняя роль: всё, включая подателя записи
    "internal": None,
}


def payout_view(record: dict, viewer_role: str) -> dict:
    allowed = VIEW_RULES_PAYOUT.get(viewer_role)
    if allowed is None:
        return dict(record)
    return {k: v for k, v in record.items() if k in allowed}


def make_payout_leaves():
    leaves = []
    for a in PLATFORM_ACCRUALS:
        content = {"event": "accrual", "cycle": CYCLE, **a}
        leaf = Leaf(submitter_id="platform_wb", role="platform",
                    period=40, content=content, claimed_date=f"{CYCLE}")
        leaf.signature = signer.sign(leaf.submitter_id, leaf.content_hash())
        leaves.append(leaf)
    for t in BANK_TRANSFERS:
        content = {"event": "transfer", "cycle": CYCLE, **t}
        leaf = Leaf(submitter_id="wb_bank_ops", role="bank",
                    period=40, content=content, claimed_date=f"{CYCLE}")
        leaf.signature = signer.sign(leaf.submitter_id, leaf.content_hash())
        leaves.append(leaf)
    return leaves


def reconcile_payouts(platform_leaves, bank_leaves):
    acc = {l.content["payout_id"]: l.content["amount_rub"] for l in platform_leaves}
    trn = {l.content["payout_id"]: l.content["amount_rub"] for l in bank_leaves}
    results = []
    for pid in sorted(set(acc) & set(trn)):
        gap = trn[pid] - acc[pid]
        results.append({
            "payout_id": pid,
            "accrued_rub": acc[pid],
            "transferred_rub": trn[pid],
            "discrepancy_rub": gap,
            "flagged": gap != 0,
        })
    return results


def run_demo():
    print("=" * 70)
    print("DEFENSE DOSSIER — банковский сценарий: выплаты продавцам")
    print(f"Цикл {CYCLE}, 5 продавцов, синтетика. Ядро — без изменений.")
    print("=" * 70)

    leaves = make_payout_leaves()
    platform_leaves = [l for l in leaves if l.role == "platform"]
    bank_leaves = [l for l in leaves if l.role == "bank"]

    print(f"\n[1] Батч: {len(leaves)} листьев "
          f"({len(platform_leaves)} начисления платформы + {len(bank_leaves)} перечисления банка)")
    leaf_hashes = [l.leaf_hash() for l in leaves]
    levels = build_merkle_tree(leaf_hashes)
    root = levels[-1][0]
    print(f"[2] Merkle root: {root}")

    ts = tsa.timestamp(root)
    print(f"[3] Штамп времени (MOCK): {ts['tsa']}, {ts['timestamp']}")
    anch = anchor.anchor(root)
    print(f"[4] Анкер (MOCK): {anch['anchor_type']}")

    print("\n[5] Сверка потоков: начисления платформы vs перечисления банка")
    print("-" * 70)
    rec = reconcile_payouts(platform_leaves, bank_leaves)
    for r in rec:
        flag = "РАСХОЖДЕНИЕ" if r["flagged"] else "OK"
        print(f" {r['payout_id']}: начислено {r['accrued_rub']} vs "
              f"перечислено {r['transferred_rub']} -> {flag} ({r['discrepancy_rub']:+d} руб.)")

    print("\n[6] Merkle-proof: продавец сам проверяет свою выплату")
    target = next(l for l in bank_leaves if l.content["payout_id"] == "WB-2026W40-002")
    proof = merkle_proof(levels, leaves.index(target))
    ok = verify_merkle_proof(target.leaf_hash(), proof, root)
    print(f" {target.content['payout_id']}, {target.content['amount_rub']} руб.: "
          f"{'ПОДТВЕРЖДЕНО' if ok else 'ОШИБКА'} (доступ к системам банка не нужен)")

    print("\n[7] Подделка: сумма в записи изменена задним числом")
    tampered = Leaf(
        submitter_id="wb_bank_ops",
        role="bank", period=40,
        content={**target.content, "amount_rub": 140000},
        claimed_date=target.claimed_date,
        ingestion_ts=target.ingestion_ts, signature=target.signature,
    )
    tampered_ok = verify_merkle_proof(tampered.leaf_hash(), proof, root)
    print(f" 142300 -> 140000 руб.: {'ОТКЛОНЕНО' if not tampered_ok else 'ОШИБКА'}")

    print("\n[8] Access Control: кто что видит по выплате WB-2026W40-003")
    r3 = next(r for r in rec if r["payout_id"] == "WB-2026W40-003")
    full_record = {
        "payout_id": "WB-2026W40-003", "seller_id": "seller_3",
        "amount_rub": 182000, "verified": True,
        "request_doc": "Заявка REQ-9003 (портал продавца)",
        "transfer_doc": "Платёжное поручение №7703",
        "discrepancy_rub": r3["discrepancy_rub"], "flagged": r3["flagged"],
        "submitter_id": "wb_bank_ops",
    }
    for role in ("public", "bank", "internal"):
        print(f" {role}: {payout_view(full_record, role)}")

    print("\n[9] Bypass-resistance")
    seller_token: AuthToken = issue_token("seller_3", "public")
    attempted = payout_view(full_record, seller_token.bound_role)
    print(f" Токен public просит internal -> получает: {attempted}")


if __name__ == "__main__":
    run_demo()
