# Limitations

- **A heuristic, not a verifier.** No label is a proof.
  `NUL_SINK_WARNING` flags a pattern, which may be harmless if the bytes
  are NUL-terminated by construction. `BOUNDED_PATTERN` means only that
  the bound is syntactically tied to the same origin object. It assumes
  `length >= 0`, does not check that the bound or the pointer is
  unchanged between the test and the use, and does not check that a loop
  body leaves its index alone.
- **No flow analysis.** Guards in earlier statements, early returns,
  `||` chains and aliasing through other variables are not followed.
  Those cases stay `UNKNOWN` on purpose rather than being approximated.
- **Lexical only.** Macros are not expanded (a false negative, `s21`).
  There are no types, so every `->data` / `.data` is treated as ASN1 data
  (a false positive, `s20`). Values from other APIs, such as
  `ASN1_STRING_to_UTF8` output, are not sources.
- **Curated lists.** The NUL-scanning, length-taking and propagator lists
  were curated, partly from this fix series. They are not exhaustive.
- **Tuned corpus.** The rules were adjusted after looking at the upstream
  corpus. Its counts measure fit, not generalisation. The absence of
  warnings on the post side is not evidence of absence of false
  positives. The synthetic corpus is the rule specification, and the
  `s22`–`s31` probes document the false-safe patterns the rules
  deliberately refuse.
- **Scope.** The scanner covers only NUL-termination assumptions. It does
  not cover other ASN.1 parsing bugs or the TS `imprint_len` change.
- **CI.** The workflow runs the tests on Python 3.10–3.13, regenerates
  `results/` and compares it byte by byte. See the Actions page for run
  status.
