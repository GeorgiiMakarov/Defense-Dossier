#!/usr/bin/env python3
"""Минимальные тесты Defense-Dossier (только stdlib).

Запуск:  python3 -m unittest discover -s tests -v

Покрывают гарантии, на которых стоит питч:
  - дерево строится, proof проверяется, подделка отсекается;
  - нет коллизии непарного узла [A,B,C] == [A,B,C,C] (CVE-2012-2459);
  - корень воспроизводим между прогонами (логическое время, не wall-clock);
  - сверка выплат: union + missing_counterpart, расхождение 003;
  - access control fail-closed: неизвестная роль -> public-маска.
"""
import unittest

from defense_dossier_demo import (
    Leaf,
    build_merkle_tree,
    merkle_proof,
    verify_merkle_proof,
    access_control_view,
    public_api_endpoint,
    issue_token,
    make_synthetic_leaves,
)

import defense_dossier_payout_demo as payout


def _leaf(cid, amount, ts=1767225600.0):
    return Leaf(submitter_id="t", role="reconciliation", period=40,
                content={"payout_id": cid, "amount_rub": amount},
                claimed_date="2026-W40", ingestion_ts=ts)


def _root(leaves):
    return build_merkle_tree([l.leaf_hash() for l in leaves])[-1][0]


class TestMerkle(unittest.TestCase):
    def test_proof_roundtrip_even_and_odd(self):
        for n in (4, 8, 5, 11):  # чётные и нечётные размеры
            leaves = [_leaf(f"P{i}", 100 + i, ts=1767225600.0 + i) for i in range(n)]
            levels = build_merkle_tree([l.leaf_hash() for l in leaves])
            root = levels[-1][0]
            for idx, leaf in enumerate(leaves):
                proof = merkle_proof(levels, idx)
                self.assertTrue(verify_merkle_proof(leaf.leaf_hash(), proof, root),
                                f"proof failed for leaf {idx} of {n}")

    def test_no_odd_leaf_collision(self):
        # [A,B,C] и [A,B,C,C] обязаны давать РАЗНЫЕ корни.
        # Дублирование непарного узла (Bitcoin-стиль) давало коллизию.
        base = [_leaf(f"P{i}", 100) for i in range(1, 4)]
        dup = base + [_leaf("P3", 100)]
        self.assertNotEqual(_root(base), _root(dup),
                            "odd-leaf duplication collision: [A,B,C] == [A,B,C,C]")

    def test_tamper_rejected(self):
        leaves = [_leaf(f"P{i}", 100 + i) for i in range(4)]
        levels = build_merkle_tree([l.leaf_hash() for l in leaves])
        root = levels[-1][0]
        proof = merkle_proof(levels, 1)
        forged = _leaf("P1", 999999)  # тот же payout_id, другая сумма
        self.assertFalse(verify_merkle_proof(forged.leaf_hash(), proof, root))


class TestDeterminism(unittest.TestCase):
    def test_core_root_stable(self):
        self.assertEqual(_root(make_synthetic_leaves()),
                         _root(make_synthetic_leaves()))

    def test_payout_root_stable(self):
        self.assertEqual(_root(payout.make_payout_leaves()),
                         _root(payout.make_payout_leaves()))


class TestPayoutReconcile(unittest.TestCase):
    def setUp(self):
        leaves = payout.make_payout_leaves()
        platform = [l for l in leaves if l.content["event"] == "accrual"]
        bank = [l for l in leaves if l.content["event"] == "transfer"]
        self.results = {r["payout_id"]: r for r in payout.reconcile_payouts(platform, bank)}

    def test_flagged_003(self):
        r = self.results["WB-2026W40-003"]
        self.assertTrue(r["flagged"])
        self.assertEqual(r["discrepancy_rub"], -2500)
        self.assertEqual(r["reason"], "amount_mismatch")

    def test_missing_counterpart_006(self):
        # Начисление без перечисления — флаг, а не молча потерянная запись.
        r = self.results["WB-2026W40-006"]
        self.assertTrue(r["flagged"])
        self.assertEqual(r["reason"], "missing_counterpart")
        self.assertIsNone(r["transferred_rub"])

    def test_ok_not_flagged(self):
        r = self.results["WB-2026W40-001"]
        self.assertFalse(r["flagged"])
        self.assertEqual(r["reason"], "ok")


class TestAccessControl(unittest.TestCase):
    RECORD = {"period": 3, "spend_pct": 68, "physical_progress_pct": 44,
              "submitter_id": "developer_obj17", "verified": True,
              "claimed_date": "2026-P3", "role": "reconciliation"}

    def test_unknown_role_fail_closed(self):
        # Опечатка роли ("piblic") — public-маска, НЕ полная запись.
        view = access_control_view(self.RECORD, "piblic")
        self.assertEqual(set(view), {"period", "claimed_date", "role", "verified"})

    def test_internal_still_full(self):
        self.assertEqual(access_control_view(self.RECORD, "internal"), self.RECORD)

    def test_endpoint_ignores_requested_role(self):
        # Решает роль, привязанная к токену, а не запрошенная клиентом.
        token = issue_token("seller_2", "public")
        got = public_api_endpoint(self.RECORD, token, requested_role="internal")
        self.assertEqual(got, access_control_view(self.RECORD, "public"))

    def test_payout_seller_isolation(self):
        rec = {"payout_id": "WB-2026W40-003", "seller_id": "seller_3",
               "amount_rub": 182000, "verified": True}
        self.assertTrue(payout.seller_self_check(rec, "seller_2")["denied"])
        own = payout.seller_self_check(rec, "seller_3")
        self.assertNotIn("denied", own)
        self.assertEqual(own["amount_rub"], 182000)


if __name__ == "__main__":
    unittest.main()
