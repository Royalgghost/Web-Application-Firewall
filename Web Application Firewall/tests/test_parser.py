"""
Unit tests for ModSecurity configuration parser.
"""
import unittest
from waf_core.parser import ModSecurityParser


class TestModSecurityParser(unittest.TestCase):

    def setUp(self):
        self.parser = ModSecurityParser()

    def test_parse_basic_secrule(self):
        rule_str = (
            'SecRule ARGS "@rx <script>" '
            '"id:1001,phase:2,block,msg:\'Basic XSS\',severity:\'CRITICAL\',setvar:\'tx.anomaly_score=+5\'"'
        )
        rules = self.parser.parse_string(rule_str)
        self.assertEqual(len(rules), 1)
        rule = rules[0]
        self.assertEqual(rule.id, 1001)
        self.assertEqual(rule.variables, ["ARGS"])
        self.assertEqual(rule.operator, "@rx")
        self.assertEqual(rule.pattern, "<script>")
        self.assertEqual(rule.actions.msg, "Basic XSS")
        self.assertEqual(rule.actions.severity, "CRITICAL")
        self.assertTrue(rule.actions.block)
        self.assertIn("tx.anomaly_score=+5", rule.actions.setvars)

    def test_parse_multiline_with_backslash(self):
        rule_str = (
            'SecRule REQUEST_HEADERS:User-Agent \\\n'
            '    "@rx sqlmap" \\\n'
            '    "id:1002,phase:1,block,msg:\'Scanner\',t:none,t:lowercase"'
        )
        rules = self.parser.parse_string(rule_str)
        self.assertEqual(len(rules), 1)
        rule = rules[0]
        self.assertEqual(rule.id, 1002)
        self.assertEqual(rule.variables, ["REQUEST_HEADERS:User-Agent"])
        self.assertEqual(rule.pattern, "sqlmap")
        self.assertEqual(len(rule.actions.transformations), 2)
        self.assertEqual(rule.actions.transformations[0].name, "none")
        self.assertEqual(rule.actions.transformations[1].name, "lowercase")

    def test_parse_sec_action(self):
        action_str = 'SecAction "id:900000,phase:1,pass,nolog,setvar:\'tx.inbound_anomaly_score_threshold=5\'"'
        rules = self.parser.parse_string(action_str)
        self.assertEqual(len(rules), 1)
        rule = rules[0]
        self.assertEqual(rule.id, 900000)
        self.assertEqual(rule.actions.phase, 1)
        self.assertIn("tx.inbound_anomaly_score_threshold=5", rule.actions.setvars)


if __name__ == "__main__":
    unittest.main()
