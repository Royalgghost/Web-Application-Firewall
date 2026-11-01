"""
Unit tests for ModSecurity transformations.
"""
import unittest
from waf_core.transformations import apply_transformations


class TestModSecurityTransformations(unittest.TestCase):

    def test_lowercase(self):
        res = apply_transformations("SELECT * FROM USERS", ["lowercase"])
        self.assertEqual(res, "select * from users")

    def test_url_decode(self):
        res = apply_transformations("%3Cscript%3Ealert%281%29%3C%2Fscript%3E", ["urlDecode"])
        self.assertEqual(res, "<script>alert(1)</script>")

    def test_html_entity_decode(self):
        res = apply_transformations("&lt;script&gt;", ["htmlEntityDecode"])
        self.assertEqual(res, "<script>")

    def test_remove_whitespace(self):
        res = apply_transformations("u n i o n   s e l e c t", ["removeWhitespace"])
        self.assertEqual(res, "unionselect")

    def test_chained_transformations(self):
        raw = "%3CSCRIPT%3Ealert%28%27XSS%27%29%3C%2FSCRIPT%3E"
        res = apply_transformations(raw, ["none", "urlDecode", "lowercase"])
        self.assertEqual(res, "<script>alert('xss')</script>")


if __name__ == "__main__":
    unittest.main()
