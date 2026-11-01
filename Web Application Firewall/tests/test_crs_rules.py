"""
Integration tests for OWASP Core Rule Set evaluation in the ModSecurity Engine.
"""
import os
import unittest
from waf_core.engine import ModSecurityEngine
from waf_core.models import Transaction


class TestCRSRules(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        rules_dir = os.path.join(os.path.dirname(__file__), "..", "rules")
        cls.engine = ModSecurityEngine(rules_dir=rules_dir)

    def test_benign_traffic(self):
        tx = Transaction(
            method="GET",
            uri="/products?category=electronics&sort=price_asc",
            path="/products",
            query_string="category=electronics&sort=price_asc",
            query_params={"category": ["electronics"], "sort": ["price_asc"]},
            headers={"Host": "example.com", "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        )
        self.engine.process_transaction(tx)
        self.assertFalse(tx.is_blocked)
        self.assertEqual(tx.response_status, 200)
        self.assertEqual(tx.anomaly_score, 0)

    def test_sql_injection_boolean_bypass(self):
        tx = Transaction(
            method="POST",
            uri="/login",
            path="/login",
            headers={"Host": "example.com"},
            body_params={"username": ["admin' OR 1=1 --"], "password": ["secret"]},
            raw_body="username=admin%27+OR+1%3D1+--&password=secret",
        )
        self.engine.process_transaction(tx)
        self.assertTrue(tx.is_blocked)
        self.assertEqual(tx.response_status, 403)
        self.assertGreaterEqual(tx.anomaly_score, 5)
        matched_rule_ids = [m.rule_id for m in tx.matches]
        self.assertTrue(any(rid in (942100, 942120) for rid in matched_rule_ids))

    def test_sql_injection_union_select(self):
        tx = Transaction(
            method="GET",
            uri="/search?query=book%20UNION%20SELECT%20username,password%20FROM%20users",
            path="/search",
            query_string="query=book UNION SELECT username,password FROM users",
            query_params={"query": ["book UNION SELECT username,password FROM users"]},
            headers={"Host": "example.com"},
        )
        self.engine.process_transaction(tx)
        self.assertTrue(tx.is_blocked)
        self.assertEqual(tx.response_status, 403)
        self.assertIn(942110, [m.rule_id for m in tx.matches])

    def test_xss_script_tag(self):
        tx = Transaction(
            method="GET",
            uri="/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E",
            path="/search",
            query_string="q=<script>alert(document.cookie)</script>",
            query_params={"q": ["<script>alert(document.cookie)</script>"]},
            headers={"Host": "example.com"},
        )
        self.engine.process_transaction(tx)
        self.assertTrue(tx.is_blocked)
        self.assertEqual(tx.response_status, 403)
        self.assertIn(941100, [m.rule_id for m in tx.matches])

    def test_xss_event_handler(self):
        tx = Transaction(
            method="POST",
            uri="/comments",
            path="/comments",
            headers={"Host": "example.com"},
            body_params={"comment": ['<img src="x" onerror="alert(1)">']},
            raw_body='comment=<img src="x" onerror="alert(1)">',
        )
        self.engine.process_transaction(tx)
        self.assertTrue(tx.is_blocked)
        self.assertIn(941110, [m.rule_id for m in tx.matches])

    def test_rce_command_chaining(self):
        tx = Transaction(
            method="POST",
            uri="/ping",
            path="/ping",
            headers={"Host": "example.com"},
            body_params={"ip": ["127.0.0.1; cat /etc/passwd"]},
            raw_body="ip=127.0.0.1%3B+cat+%2Fetc%2Fpasswd",
        )
        self.engine.process_transaction(tx)
        self.assertTrue(tx.is_blocked)
        self.assertIn(932100, [m.rule_id for m in tx.matches])

    def test_lfi_path_traversal(self):
        tx = Transaction(
            method="GET",
            uri="/view?file=../../../../windows/win.ini",
            path="/view",
            query_string="file=../../../../windows/win.ini",
            query_params={"file": ["../../../../windows/win.ini"]},
            headers={"Host": "example.com"},
        )
        self.engine.process_transaction(tx)
        self.assertTrue(tx.is_blocked)
        self.assertTrue(any(m.rule_id in (930100, 930110) for m in tx.matches))

    def test_ssrf_cloud_metadata(self):
        tx = Transaction(
            method="GET",
            uri="/proxy?target=http://169.254.169.254/latest/meta-data/",
            path="/proxy",
            query_string="target=http://169.254.169.254/latest/meta-data/",
            query_params={"target": ["http://169.254.169.254/latest/meta-data/"]},
            headers={"Host": "example.com"},
        )
        self.engine.process_transaction(tx)
        self.assertTrue(tx.is_blocked)
        self.assertIn(944100, [m.rule_id for m in tx.matches])

    def test_scanner_user_agent(self):
        tx = Transaction(
            method="GET",
            uri="/",
            path="/",
            headers={"Host": "example.com", "User-Agent": "sqlmap/1.5.2#stable (http://sqlmap.org)"},
        )
        self.engine.process_transaction(tx)
        self.assertTrue(tx.is_blocked)
        self.assertIn(913100, [m.rule_id for m in tx.matches])

    def test_detection_only_mode(self):
        self.engine.engine_mode = "DetectionOnly"
        tx = Transaction(
            method="GET",
            uri="/search?q=<script>alert(1)</script>",
            path="/search",
            query_string="q=<script>alert(1)</script>",
            query_params={"q": ["<script>alert(1)</script>"]},
            headers={"Host": "example.com"},
        )
        self.engine.process_transaction(tx)
        # In DetectionOnly, rules trigger but request is not blocked
        self.assertFalse(tx.is_blocked)
        self.assertEqual(tx.response_status, 200)
        self.assertGreaterEqual(tx.anomaly_score, 5)
        # Reset mode
        self.engine.engine_mode = "On"


if __name__ == "__main__":
    unittest.main()
