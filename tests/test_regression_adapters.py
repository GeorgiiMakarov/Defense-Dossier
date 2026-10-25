#!/usr/bin/env python3
"""Регрессионные тесты к порту адаптеров подписи/TSA/анкера.

Запуск:  python3 -m unittest discover -s tests -v   (из корня репо)

Покрытие (только stdlib):
  - сверка основного демо: период только в одном потоке помечен
    (в существующем наборе такой тест есть только для payout-сверки);
  - вывод демо детерминирован при фиксированном времени TSA;
  - вывод демо подтверждает путь verified-из-проверки;
  - адаптеры: моки делегируют Synthetic*-классам, а банк может
    подменить реализации без правок ядра.

Не дублируются (уже есть в tests/test_defense_dossier.py):
  - неизвестная роль -> public-маска (test_unknown_role_fail_closed);
  - [A,B,C] и [A,B,C,C] дают разные корни (test_no_odd_leaf_collision).

Порядок по задаче: тесты написаны ДО порта. До порта тесты адаптеров
падают (классов Signer/SyntheticSigner и инстансов demo.signer/tsa/
anchor ещё нет), тесты поведения проходят. После порта всё зелёное.
"""
import contextlib
import io
import time
import unittest
from unittest import mock

import defense_dossier_demo as demo
from defense_dossier_demo import (
    Leaf,
    mock_ecp_sign,
    mock_public_anchor,
    mock_rfc3161_timestamp,
    reconcile,
    run_demo,
)

_FIXED_GMTIME = time.struct_time((2026, 1, 1, 0, 0, 0, 3, 1, -1))


def _dev(period, spend):
    return Leaf(submitter_id="developer_obj17", role="developer",
                period=period, content={"spend_pct": spend, "doc": "x"},
                claimed_date=f"2026-P{period}",
                event_ts=1767225600.0 + period)


def _insp(period, phys):
    return Leaf(submitter_id="inspector_independent_llp", role="inspector",
                period=period, content={"physical_progress_pct": phys, "doc": "y"},
                claimed_date=f"2026-P{period}",
                event_ts=1767225600.0 + period + 0.5)


def _run_demo_fixed_tsa():
    """Вывод run_demo() при фиксированном времени TSA."""
    buf = io.StringIO()
    with mock.patch.object(time, "gmtime", return_value=_FIXED_GMTIME):
        with contextlib.redirect_stdout(buf):
            run_demo()
    return buf.getvalue()


class TestMainReconcileSingleStream(unittest.TestCase):
    def test_period_only_in_developer_flagged(self):
        results = {r["period"]: r for r in reconcile(
            [_dev(1, 22), _dev(2, 41)], [_insp(1, 20)])}
        self.assertEqual(results[2]["gap_pct"], None)
        self.assertTrue(results[2]["flagged"])
        self.assertEqual(results[2]["reason"], "missing_counterpart")
        self.assertIsNone(results[2]["inspector_physical_pct"])
        self.assertFalse(results[1]["flagged"])

    def test_period_only_in_inspector_flagged(self):
        results = {r["period"]: r for r in reconcile(
            [_dev(1, 22)], [_insp(1, 20), _insp(2, 38)])}
        self.assertEqual(results[2]["gap_pct"], None)
        self.assertTrue(results[2]["flagged"])
        self.assertEqual(results[2]["reason"], "missing_counterpart")
        self.assertIsNone(results[2]["developer_spend_pct"])


class TestDemoOutputDeterminism(unittest.TestCase):
    def test_run_demo_stable_with_fixed_tsa_time(self):
        out1 = _run_demo_fixed_tsa()
        out2 = _run_demo_fixed_tsa()
        self.assertEqual(out1, out2)
        self.assertIn("2026-01-01T00:00:00Z", out1)

    def test_run_demo_proof_lines(self):
        out = _run_demo_fixed_tsa()
        # verified в демо берётся из проверки Merkle-доказательства,
        # а не захардкожен: лист P3 подтверждается, подделка отсекается.
        self.assertIn("Проверка листа P3: ПОДТВЕРЖДЕНО", out)
        self.assertIn("68 -> 45: ОТКЛОНЕНО", out)


class TestAdapters(unittest.TestCase):
    def test_mock_sign_delegates(self):
        from defense_dossier_demo import Signer, SyntheticSigner
        self.assertIsInstance(demo.signer, SyntheticSigner)
        self.assertEqual(mock_ecp_sign("s", "h"),
                         SyntheticSigner().sign("s", "h"))
        with self.assertRaises(NotImplementedError):
            Signer().sign("s", "h")

    def test_custom_signer_substitution(self):
        from defense_dossier_demo import Signer

        class BankSigner(Signer):
            def sign(self, submitter_id, content_hash):
                return "BANK-SIG"

        old = demo.signer
        try:
            demo.signer = BankSigner()
            self.assertEqual(mock_ecp_sign("s", "h"), "BANK-SIG")
        finally:
            demo.signer = old

    def test_mock_tsa_delegates(self):
        from defense_dossier_demo import SyntheticTSA, TimestampAuthority
        self.assertIsInstance(demo.tsa, SyntheticTSA)
        got = mock_rfc3161_timestamp("root")
        want = SyntheticTSA().timestamp("root")
        for key in ("root", "tsa", "token"):  # timestamp — wall-clock, не сравниваем
            self.assertEqual(got[key], want[key])
        with self.assertRaises(NotImplementedError):
            TimestampAuthority().timestamp("root")

    def test_custom_tsa_substitution(self):
        from defense_dossier_demo import TimestampAuthority

        class BankTSA(TimestampAuthority):
            def timestamp(self, root_hash):
                return {"root": root_hash, "tsa": "BANK-TSA"}

        old = demo.tsa
        try:
            demo.tsa = BankTSA()
            self.assertEqual(mock_rfc3161_timestamp("r")["tsa"], "BANK-TSA")
        finally:
            demo.tsa = old

    def test_mock_anchor_delegates(self):
        from defense_dossier_demo import Anchor, SyntheticAnchor
        self.assertIsInstance(demo.anchor, SyntheticAnchor)
        self.assertEqual(mock_public_anchor("root"),
                         SyntheticAnchor().anchor("root"))
        with self.assertRaises(NotImplementedError):
            Anchor().anchor("root")

    def test_custom_anchor_substitution(self):
        from defense_dossier_demo import Anchor

        class BankAnchor(Anchor):
            def anchor(self, root_hash):
                return {"root": root_hash, "anchor_type": "BANK-ANCHOR"}

        old = demo.anchor
        try:
            demo.anchor = BankAnchor()
            self.assertEqual(mock_public_anchor("r")["anchor_type"], "BANK-ANCHOR")
        finally:
            demo.anchor = old


if __name__ == "__main__":
    unittest.main()
