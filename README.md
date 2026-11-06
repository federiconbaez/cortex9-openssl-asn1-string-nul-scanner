# cortex9-openssl-asn1-string-nul-scanner

A lexical, intraprocedural scanner for C code that passes `ASN1_STRING`
bytes to operations assuming NUL termination. This is the bug class of
CVE-2021-3712 (OpenSSL advisory of 2021-08-24, "Read buffer overruns
processing ASN.1 strings", fixed in 1.1.1l).

**It is not grep and not a compiler.** The scanner does the following:

- It tokenizes C (dropping comments and preprocessor lines) and splits
  statements.
- It tracks *sources* in source order: `->data`,
  `ASN1_STRING_get0_data`, `X509_alias_get0` and others, plus variables
  derived from them by cast, offset or `strchr`.
- It tracks *length expressions* and length out-parameters.
- It classifies each use as `UNSAFE`, `SAFE` or `UNKNOWN`:
  - `UNSAFE`: `%s` without precision, or a NUL-scanning function;
  - `SAFE`: `%.*s` or a length-taking function bounded by a length, or a
    length-guarded dereference;
  - `UNKNOWN`: anything the rules cannot decide.

The function verdict is the worst finding: `UNSAFE` > `UNKNOWN` >
`SAFE` > `NO_SOURCE`. No code is compiled or executed.

## Corpora and results (`results/`)

### Upstream

The upstream corpus has 13 functions × {pre, post} = 26 cases. The
functions are taken from unmodified OpenSSL files at the parent and fix
commit of each 1.1.1l fix:

- d9d838ddc0ed, 174ba8048a7f, 5f54e57406ca, 23446958685a, 8393de42498f,
  bb4d2ed40914, 2d0e5d4a4a5d;
- 5478387c14e0, labelled out of scope.

Each case was hand-labelled from the diffs before running the scanner.

| side | outcome | count |
|---|---|---|
| pre | detected (truth UNSAFE → scanner UNSAFE) | 10 / 10 |
| pre | correct_safe (truth SAFE) | 2 |
| post | correct_safe | 9 |
| post | unknown_on_safe (scanner could not prove a fixed function safe) | 3 |
| post | false_positive | 0 |
| both | out_of_scope (TS imprint_len) | 1 + 1 |

The three `UNKNOWN` cases after the fix need guards the lexical rules do
not track:

- **i2v_GENERAL_NAME:** `p[0]` is guarded by an earlier `length == 4`
  test.
- **nc_dns:** `*baseptr` is guarded by an earlier `return` on
  `length == 0`.
- **nc_email:** `strncmp` is bounded by a pointer difference.

### Synthetic

The synthetic corpus has 21 hand-written snippets, which are the rule
specification. The scanner matches the rule expectation in 21 / 21. Four
documented limitations are included:

- a literal precision (`%.8s`);
- an unguarded `*p` that is really an over-read;
- any `->data` taken as ASN1 data (a false positive);
- a sink hidden in a macro (a false negative).

**Honesty notes:**

- The rules were adjusted after seeing the upstream corpus, by adding
  `IA5_OFFSET_LEN`/`ASN1_STRING_length` as length computations,
  length-variable assignment and for-loop index bounds. The upstream
  numbers are therefore **not** a held-out evaluation.
- The `SAFE` results are rule-level claims, not proofs.

## Usage

```sh
PYTHONPATH=src python3 -m asn1nul scan fixtures/synthetic/s01_printf_s.c
PYTHONPATH=src python3 -m asn1nul scan fixtures/upstream/c5b2c075feea-crypto_x509_t_x509.c --function X509_aux_print
PYTHONPATH=src python3 -m asn1nul corpus
PYTHONPATH=src python3 -m unittest discover -s tests -v
python3 scripts/gen_results.py /tmp/out && diff -r results /tmp/out
```

See [SOURCES.md](SOURCES.md), [LIMITATIONS.md](LIMITATIONS.md),
[PRACTICE.md](PRACTICE.md) (Spanish) and [README.es.md](README.es.md).

License: Apache-2.0 for this project's code and docs. The files in
`fixtures/upstream/*.c` are unmodified OpenSSL sources under the
OpenSSL/SSLeay license (`fixtures/upstream/LICENSE.OpenSSL`).
