"""
Unit tests for ModSecurity operators.
"""
import unittest
from waf_core.operators import OperatorEvaluator


class TestModSecurityOperators(unittest.TestCase):

    def setUp(self):
        self.evaluator = OperatorEvaluator()

    def test_rx_operator(self):
        matched, data = self.evaluator.evaluate("@rx", r"admin'--", "select * from users where user='admin'--")
        self.assertTrue(matched)
        self.assertEqual(data, "admin'--")

        matched, _ = self.evaluator.evaluate("@rx", r"^[0-9]+$", "hello123")
        self.assertFalse(matched)

    def test_negated_rx(self):
        matched, _ = self.evaluator.evaluate("!@rx", r"^[0-9]+$", "abc")
        self.assertTrue(matched)

    def test_contains_operator(self):
        matched, data = self.evaluator.evaluate("@contains", "../", "some/path/../secret")
        self.assertTrue(matched)
        self.assertEqual(data, "../")

    def test_pm_operator(self):
        matched, data = self.evaluator.evaluate("@pm", "sqlmap nikto acunetix", "Mozilla/5.0 sqlmap/1.5")
        self.assertTrue(matched)
        self.assertEqual(data, "sqlmap")

    def test_numeric_operators(self):
        matched, _ = self.evaluator.evaluate("@ge", "5", 5)
        self.assertTrue(matched)

        matched, _ = self.evaluator.evaluate("@ge", "5", 4)
        self.assertFalse(matched)

        matched, _ = self.evaluator.evaluate("@gt", "10", 15)
        self.assertTrue(matched)

    def test_ip_match(self):
        matched, _ = self.evaluator.evaluate("@ipMatch", "192.168.1.0/24", "192.168.1.55")
        self.assertTrue(matched)

        matched, _ = self.evaluator.evaluate("@ipMatch", "10.0.0.1", "10.0.0.2")
        self.assertFalse(matched)


if __name__ == "__main__":
    unittest.main()
