# cortex9-openssl-asn1-string-nul-scanner

A lexical, intraprocedural **warning heuristic** for C code that passes
`ASN1_STRING` bytes to operations assuming NUL termination. This is the
bug class of CVE-2021-3712 (OpenSSL advisory of 2021-08-24, fixed in
1.1.1l). No code is compiled or executed. **It does not prove anything
safe or unsafe.**

## Labels

| Label | Meaning |
|---|---|
| `NUL_SINK_WARNING` | The ASN1 bytes reach `%s` without precision, or a NUL-scanning function. This is a warning about a pattern, **not** proof of a real over-read: the buffer may be NUL-terminated by construction. |
| `BOUNDED_PATTERN` | The use matches a recognised pattern whose bound is syntactically tied to the **same origin object**. Examples: `%.*s` with `s->length` for `s->data`, `OPENSSL_strndup(p, s->length)`, `IA5_OFFSET_LEN(s, q)` for a derived pointer `q`, `for (i < s->length)` body indices, and `s->length > 0 && *p`. It is **not** a safety claim. It assumes `length >= 0` and that nothing between the bound and the use changes it. |
| `UNKNOWN` | The rules cannot tie the use to a bound. This is the honest default. |
| `NO_SOURCE` | No ASN1 source was recognised. |

The function verdict is the worst label found. Sources, origins and the
accepted bound forms are specified in the docstring of
`src/asn1nul/scanner.py`.

The scanner does not do flow analysis. A length test in an earlier
statement, a `||` chain or a merely length-named identifier stays
`UNKNOWN`.

## Corpora and results (`results/`)

### Upstream (tuned, not independent)

The corpus has 13 functions × {pre, post}, taken from unmodified OpenSSL
files at the parent and fix commit of each 1.1.1l fix. Labels were set by
hand from the diffs. The rules were adjusted after looking at this
corpus, so the numbers below measure fit to it, not accuracy on other
code.

| side | outcome | count |
|---|---|---|
| pre | `warned` (hand label UNSAFE) | 10 |
| pre | hand label SAFE, no warning | 2 |
| post | no warning | 8 |
| post | `UNKNOWN` on a fixed function | 4 |
| both | out of scope (TS imprint_len) | 1 + 1 |

There is no `NUL_SINK_WARNING` on the post side of this corpus. That is
**not** evidence that the scanner has no false positives. See the
synthetic `s20` case, a known false positive.

The four `UNKNOWN` results after the fix come from bounds the rules
deliberately do not accept (see `results/upstream_findings.csv`):

- **i2v_GENERAL_NAME:** `p[0..3]` is read after an earlier
  `length == 4 / 16` test in another statement.
- **nc_dns, nc_email, nc_uri:**
  - `ia5ncasecmp` compares two strings of *different* origins using one
    origin's length. The fix relies on an earlier `dns->length <
    base->length` check, which the rules do not follow.
  - Some sizes are pointer differences or computed variables
    (`emlat - emlptr`, `hostlen`).
  - Some dereferences are guarded only in earlier statements or by `||`
    chains.

### Synthetic (rule specification)

The synthetic corpus has 31 hand-written snippets, and the scanner gives
the expected label in all 31. It includes 10 probes for heuristic
**false-safe** cases, each of which must not be `BOUNDED_PATTERN`:

- a length larger than the buffer;
- a negative printf precision;
- `p[i]` with `i <= length`;
- `p[length]`;
- an `unrelated_len` identifier;
- another object's length;
- a guard that does not dominate the read;
- a `||` guard;
- a loop index used after the loop;
- a derived pointer with the full length.

The synthetic corpus also keeps the known limitations: a literal
precision, an unguarded `*p`, any `->data` treated as ASN1 (a false
positive), and a macro-hidden sink (a false negative).

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
