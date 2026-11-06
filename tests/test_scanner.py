import unittest

from asn1nul.corpus import outcome, synthetic_rows, upstream_rows
from asn1nul.lexer import strip_comments, tokens
from asn1nul.scanner import scan


class Synthetic(unittest.TestCase):
    def test_rules_match_hand_expectations(self):
        for r in synthetic_rows():
            with self.subTest(file=r["file"]):
                self.assertEqual(r["scanner"], r["expect"])

    def test_limitations_are_labelled(self):
        good = {"detected", "correct_safe", "agrees_unknown"}
        for r in synthetic_rows():
            if outcome(r["truth"], r["scanner"]) not in good:
                self.assertTrue(r["limitation"], r["file"])


class Upstream(unittest.TestCase):
    def setUp(self):
        self.rows = list(upstream_rows())

    def test_every_pre_fix_unsafe_function_detected(self):
        for r in self.rows:
            if r["side"] == "pre" and r["truth"] == "UNSAFE":
                self.assertEqual(r["scanner"], "UNSAFE", r["function"])

    def test_no_false_positive_after_fix(self):
        for r in self.rows:
            if r["side"] == "post":
                self.assertNotEqual(outcome(r["truth"], r["scanner"]), "false_positive", r["function"])

    def test_corpus_size(self):
        self.assertEqual(len(self.rows), 26)


class Lexer(unittest.TestCase):
    def test_comment_and_string(self):
        src = 'a = "/* not a comment */"; /* x->data */ b = 1; // y->data\n'
        self.assertNotIn("x->data", strip_comments(src))
        self.assertIn('"/* not a comment */"', strip_comments(src))
        self.assertEqual([t[1] for t in tokens("p->data[0]")], ["p", "->", "data", "[", "0", "]"])

    def test_width_star_consumes_argument(self):
        r = scan('void f(BIO *o, ASN1_STRING *s, int w) { BIO_printf(o, "%*s", w, s->data); }')
        self.assertEqual(r.verdict, "UNSAFE")


if __name__ == "__main__":
    unittest.main()
