# Limitations

- **Lexical and intraprocedural.** The scanner uses no preprocessor
  (macros are not expanded), no types and no control flow. Guards in
  earlier statements, such as `if (len == 0) return;`, are not seen. A
  length test anywhere in the same statement counts as a guard.
- **Source heuristic.** Every `->data` / `.data` member is treated as
  ASN1 string data, which gives false positives on unrelated structs.
  Values from other APIs are not sources, such as the output of
  `ASN1_STRING_to_UTF8`, which OpenSSL NUL-terminates.
- **Length heuristic.** Any identifier matching `/len|length/` counts as
  a length, so a wrong length variable would still give `SAFE`. `SAFE`
  means "the rules found a length", not "proven in bounds".
- **Curated lists.** The sink, length-taking and propagator lists were
  curated, partly from this same fix series (for example `ia5casecmp`,
  `X509V3_add_value_uchar`, `sk_OPENSSL_STRING_find`). They are not
  exhaustive.
- **Not a held-out evaluation.** The rules were adjusted after looking at
  the upstream corpus, so its numbers measure fit, not generalisation.
  The synthetic corpus is the rule specification.
- **Scope.** The scanner covers only NUL-termination assumptions. It
  does not cover other ASN.1 parsing bugs or the TS `imprint_len` change.
  It does not prove the absence of over-reads.
- **CI.** The workflow runs the tests on Python 3.10–3.13, regenerates
  `results/` and compares it byte by byte. See the Actions page for run
  status.
