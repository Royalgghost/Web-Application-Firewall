"""
End-to-End integration tests for Flask WAF application.
"""
import unittest
from app import create_app


class TestFlaskWAF(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.client = cls.app.test_client()

    def test_benign_request_passes(self):
        resp = self.client.get("/app/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Controlled Environment", resp.data)

    def test_sqli_attack_blocked(self):
        resp = self.client.post(
            "/app/login",
            data={"username": "admin' OR 1=1 --", "password": "any"},
        )
        self.assertEqual(resp.status_code, 403)
        self.assertIn(b"ModSecurity WAF", resp.data)
        self.assertIn(b"Access Denied", resp.data)

    def test_xss_attack_blocked(self):
        resp = self.client.get("/app/search?q=<script>alert(1)</script>")
        self.assertEqual(resp.status_code, 403)
        self.assertIn(b"ModSecurity WAF", resp.data)

    def test_rce_attack_blocked(self):
        resp = self.client.post("/app/ping", data={"ip": "127.0.0.1; whoami"})
        self.assertEqual(resp.status_code, 403)
        self.assertIn(b"ModSecurity WAF", resp.data)

    def test_lfi_attack_blocked(self):
        resp = self.client.get("/app/view-file?file=../../../../etc/passwd")
        self.assertEqual(resp.status_code, 403)
        self.assertIn(b"ModSecurity WAF", resp.data)

    def test_api_simulate(self):
        payload = {
            "method": "POST",
            "uri": "/login",
            "headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "body": "username=admin'+OR+1=1+--",
        }
        resp = self.client.post("/api/simulate", json=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["is_blocked"])
        self.assertEqual(data["status"], 403)
        self.assertGreaterEqual(data["anomaly_score"], 5)
        self.assertIn("trace_steps", data)
        self.assertIn("sec_audit_log", data)

    def test_api_stats(self):
        resp = self.client.get("/api/stats")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("total_requests", data)
        self.assertIn("blocked_requests", data)
        self.assertIn("attack_categories", data)

    def test_api_benchmark(self):
        resp = self.client.post("/api/benchmark")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertIn("metrics", data)
        self.assertGreater(data["metrics"]["total_tests"], 25)
        self.assertGreaterEqual(data["metrics"]["accuracy"], 95.0)


if __name__ == "__main__":
    unittest.main()
