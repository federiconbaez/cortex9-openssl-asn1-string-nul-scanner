import unittest

from asn1nul.corpus import outcome, synthetic_rows, upstream_rows
from asn1nul.lexer import strip_comments, tokens
from asn1nul.scanner import BOUNDED, UNKNOWN, WARN, scan


class Synthetic(unittest.TestCase):
    def test_rules_match_hand_expectations(self):
        for r in synthetic_rows():
            with self.subTest(file=r["file"]):
                self.assertEqual(r["scanner"], r["expect"])

    def test_disagreements_with_truth_are_labelled(self):
        good = {"warned", "no_warning_on_safe", "unknown_on_unknown"}
        for r in synthetic_rows():
            if outcome(r["truth"], r["scanner"]) not in good:
                self.assertTrue(r["limitation"], r["file"])

    def test_false_safe_probes_never_bounded(self):
        probes = [r for r in synthetic_rows() if r["limitation"].startswith("heuristic false-safe probe")]
        self.assertEqual(len(probes), 10)
        for r in probes:
            self.assertNotEqual(r["scanner"], BOUNDED, r["file"])

    def test_no_truth_unsafe_is_bounded(self):
        for r in synthetic_rows():
            if r["truth"] == "UNSAFE":
                self.assertNotEqual(r["scanner"], BOUNDED, r["file"])


class Rules(unittest.TestCase):
    def v(self, src):
        return scan(src).verdict

    def test_length_of_same_origin_only(self):
        self.assertEqual(self.v('void f(BIO *o, ASN1_STRING *s) { BIO_printf(o, "%.*s", s->length, s->data); }'), BOUNDED)
        self.assertEqual(self.v('void f(BIO *o, ASN1_STRING *s, ASN1_STRING *t) { BIO_printf(o, "%.*s", t->length, s->data); }'), UNKNOWN)

    def test_length_var_rebound(self):
        src = 'void f(BIO *o, ASN1_STRING *s, int k) { int n = s->length; n = k; BIO_printf(o, "%.*s", n, s->data); }'
        self.assertEqual(self.v(src), UNKNOWN)

    def test_ia5_offset_len_for_derived_pointer(self):
        src = 'int f(ASN1_IA5STRING *u) { const char *h = (char *)u->data + 2; return memchr(h, 58, IA5_OFFSET_LEN(u, h)) != NULL; }'
        self.assertEqual(self.v(src), BOUNDED)

    def test_width_star_consumes_argument(self):
        self.assertEqual(self.v('void f(BIO *o, ASN1_STRING *s, int w) { BIO_printf(o, "%*s", w, s->data); }'), WARN)


class Upstream(unittest.TestCase):
    """Regression on the TUNED upstream corpus (not an independent evaluation)."""

    def setUp(self):
        self.rows = list(upstream_rows())

    def test_regression_pre_fix_unsafe_functions_warned(self):
        for r in self.rows:
            if r["side"] == "pre" and r["truth"] == "UNSAFE":
                self.assertEqual(r["scanner"], WARN, r["function"])

    def test_regression_post_side_no_warning(self):
        for r in self.rows:
            if r["side"] == "post":
                self.assertNotEqual(r["scanner"], WARN, r["function"])

    def test_corpus_size(self):
        self.assertEqual(len(self.rows), 26)


class Lexer(unittest.TestCase):
    def test_comment_and_string(self):
        src = 'a = "/* not a comment */"; /* x->data */ b = 1; // y->data\n'
        self.assertNotIn("x->data", strip_comments(src))
        self.assertIn('"/* not a comment */"', strip_comments(src))
        self.assertEqual([t[1] for t in tokens("p->data[0]")], ["p", "->", "data", "[", "0", "]"])


if __name__ == "__main__":
    unittest.main()
