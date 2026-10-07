#!/usr/bin/env python3
"""
Defense-Dossier — банковский сценарий: проверяемый след выплат продавцам.

Синтетическое демо: один расчётный цикл (2026-W40), 6 продавцов.
Использует ТОЛЬКО публичный API ядра defense_dossier_demo (main):
    Leaf, build_merkle_tree, merkle_proof, verify_merkle_proof,
    mock_ecp_sign, mock_rfc3161_timestamp, mock_public_anchor,
    issue_token, AuthToken.
Ядро не меняется: сценарий выплат — это данные и тонкая обёртка поверх.

Честные границы (см. также README):
  - Подписи/штампы/анкер — заглушки ядра (mock_*), точки подключения
    настоящих адаптеров. В пилоте сюда встают ЭЦП по ГОСТ (КриптоПро),
    штамп времени аккредитованного УЦ (RFC 3161) и внутренний реестр банка.
    Пути проверки подписи (verify) в ядре пока нет — подделка в демо
    ловится сменой содержимого записи, не сломом подписи.
  - Два потока (начисления платформы / перечисления банка) в демо идут одним
    процессом в один батч. Merkle доказывает включение записи и её
    неизменность, а не независимость контуров. Сверка находит расхождения
    между потоками до обращений продавцов.
  - В leaf_hash входит логическое время документа (фиксированная шкала
    синтетического цикла), а не wall-clock хоста, — корень батча одинаков
    при каждом запуске. В пилоте сюда кладётся время документа / sequence.

Запуск:  python3 defense_dossier_payout_demo.py     # только stdlib
"""
from defense_dossier_demo import (
    Leaf,
    build_merkle_tree,
    merkle_proof,
    verify_merkle_proof,
    mock_ecp_sign,
    mock_rfc3161_timestamp,
    mock_public_anchor,
    issue_token,
)

CYCLE = "2026-W40"

# Логическое время документов синтетического цикла (не wall-clock хоста):
# корень батча одинаков при каждом запуске.
_DOC_TS_BASE = 1767225600.0  # 2026-01-01T00:00:00Z

# Поток 1 — начисления на стороне платформы (отчёт реализации -> баланс).
# WB-2026W40-006: начисление есть, перечисления нет — типичный кейс
# «заявка без платёжки», который обязана найти сверка.
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
    {"payout_id": "WB-2026W40-006", "seller_id": "seller_6", "amount_rub": 73000,
     "doc": "Отчёт реализации №40, заявка REQ-9006 (перечисление ещё не проведено)"},
]

# Поток 2 — перечисления на стороне банка. В payout 003 сумма умышленно
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
    # продавец: только своя выплата, без чужих данных и служебных полей
    "public": {"payout_id", "seller_id", "amount_rub", "verified"},
    # банк/комплаенс: плюс реквизиты операции и результат сверки
    "bank": {"payout_id", "seller_id", "amount_rub", "verified", "request_doc",
             "transfer_doc", "discrepancy_rub", "flagged"},
    # внутренняя роль: всё, включая подателя записи
    "internal": None,
}


def payout_view(record: dict, viewer_role: str) -> dict:
    # Неизвестная роль (в т.ч. опечатка) -> самая строгая маска, а не полный доступ.
    allowed = VIEW_RULES_PAYOUT.get(viewer_role, VIEW_RULES_PAYOUT["public"])
    if allowed is None:
        return dict(record)
    return {k: v for k, v in record.items() if k in allowed}


def seller_self_check(record: dict, seller_id: str) -> dict:
    """Продавец видит только свою выплату: фильтр по seller_id, не только по роли."""
    if record.get("seller_id") != seller_id:
        return {"denied": True, "reason": "чужая выплата недоступна"}
    return payout_view(record, "public")


def payout_api_endpoint(record: dict, token, requested_role: str = None) -> dict:
    # Запрошенная роль игнорируется: решает роль, привязанная к токену.
    return payout_view(record, token.bound_role)


def make_payout_leaves():
    leaves = []
    for seq, a in enumerate(PLATFORM_ACCRUALS):
        content = {"event": "accrual", "cycle": CYCLE, **a}
        leaf = Leaf(submitter_id="platform_wb", role="platform",
                    period=40, content=content, claimed_date=CYCLE,
                    event_ts=_DOC_TS_BASE + seq)
        leaf.signature = mock_ecp_sign(leaf.submitter_id, leaf.content_hash())
        leaves.append(leaf)
    for seq, t in enumerate(BANK_TRANSFERS):
        content = {"event": "transfer", "cycle": CYCLE, **t}
        leaf = Leaf(submitter_id="wb_bank_ops", role="bank",
                    period=40, content=content, claimed_date=CYCLE,
                    event_ts=_DOC_TS_BASE + seq + 0.5)
        leaf.signature = mock_ecp_sign(leaf.submitter_id, leaf.content_hash())
        leaves.append(leaf)
    return leaves


def reconcile_payouts(platform_leaves, bank_leaves):
    # union, как в ядре: выплата без пары в другом потоке — тоже красный флаг,
    # а не молча потерянная запись.
    acc = {l.content["payout_id"]: l.content["amount_rub"] for l in platform_leaves}
    trn = {l.content["payout_id"]: l.content["amount_rub"] for l in bank_leaves}
    results = []
    for pid in sorted(set(acc) | set(trn)):
        a, t = acc.get(pid), trn.get(pid)
        if a is None or t is None:
            results.append({
                "payout_id": pid, "accrued_rub": a, "transferred_rub": t,
                "discrepancy_rub": None, "flagged": True,
                "reason": "missing_counterpart",
            })
            continue
        gap = t - a
        results.append({
            "payout_id": pid, "accrued_rub": a, "transferred_rub": t,
            "discrepancy_rub": gap, "flagged": gap != 0,
            "reason": "amount_mismatch" if gap != 0 else "ok",
        })
    return results


def run_demo():
    print("=" * 70)
    print("DEFENSE DOSSIER — банковский сценарий: выплаты продавцам")
    print(f"Цикл {CYCLE}, 6 продавцов, синтетика. Только публичный API ядра.")
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

    ts = mock_rfc3161_timestamp(root)
    # Нейтральная подпись мока: без привязки к юрисдикции (ядро нейтрально,
    # у стройка-демо своя метка). Пояснение про контур — строкой ниже.
    print(f"[3] Штамп времени (MOCK): MOCK-TSA, {ts['timestamp']}")
    print("     Для российского контура сюда подключается штамп аккредитованного УЦ.")
    anch = mock_public_anchor(root)
    print(f"[4] Анкер (MOCK): {anch['anchor_type']}")
    print("     Для российского контура — внутренний реестр банка.")

    print("\n[5] Сверка потоков: начисления платформы vs перечисления банка")
    print("-" * 70)
    rec = reconcile_payouts(platform_leaves, bank_leaves)
    for r in rec:
        if r["reason"] == "missing_counterpart":
            print(f" {r['payout_id']}: начислено {r['accrued_rub']} vs "
                  f"перечислено {r['transferred_rub']} -> НЕТ ПАРЫ (флаг)")
        else:
            flag = "РАСХОЖДЕНИЕ" if r["flagged"] else "OK"
            print(f" {r['payout_id']}: начислено {r['accrued_rub']} vs "
                  f"перечислено {r['transferred_rub']} -> {flag} ({r['discrepancy_rub']:+d} руб.)")

    print("\n[6] Merkle-proof: продавец сам проверяет свою выплату")
    target = next(l for l in bank_leaves if l.content["payout_id"] == "WB-2026W40-002")
    proof = merkle_proof(levels, leaves.index(target))
    ok = verify_merkle_proof(target.leaf_hash(), proof, root)
    print(f" {target.content['payout_id']}, {target.content['amount_rub']} руб.: "
          f"{'ПОДТВЕРЖДЕНО' if ok else 'ОШИБКА'} (доступ к системам банка не нужен)")
    print(f" seller_2 смотрит свою выплату: {seller_self_check(_record_of(rec, target), 'seller_2')}")
    other = next(l for l in bank_leaves if l.content["payout_id"] == "WB-2026W40-003")
    print(f" seller_2 смотрит чужую (003):  {seller_self_check(_record_of(rec, other), 'seller_2')}")

    print("\n[7] Подделка: сумма в записи изменена задним числом")
    tampered = Leaf(
        submitter_id="wb_bank_ops", role="bank", period=40,
        content={**target.content, "amount_rub": 140000},
        claimed_date=target.claimed_date,
        event_ts=target.event_ts, signature=target.signature,
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
    for role in ("public", "bank", "internal", "piblic"):
        print(f" {role}: {payout_view(full_record, role)}")

    print("\n[9] Bypass-resistance: токен public просит internal")
    seller_token = issue_token("seller_3", "public")
    attempted = payout_api_endpoint(full_record, seller_token, requested_role="internal")
    print(f" запрошена internal -> получено: {attempted}")


def _record_of(rec, leaf):
    r = next(x for x in rec if x["payout_id"] == leaf.content["payout_id"])
    return {
        "payout_id": leaf.content["payout_id"], "seller_id": leaf.content["seller_id"],
        "amount_rub": leaf.content["amount_rub"], "verified": True,
        "discrepancy_rub": r["discrepancy_rub"], "flagged": r["flagged"],
        "submitter_id": leaf.submitter_id,
    }


if __name__ == "__main__":
    run_demo()
