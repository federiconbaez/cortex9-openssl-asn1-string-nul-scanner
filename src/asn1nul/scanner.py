"""Intraprocedural lexical scan for ASN1_STRING data reaching NUL-assuming sinks.

Sources (pointer into ASN1 string bytes, NUL not guaranteed):
  any `X->data` / `X.data` member (heuristic), ASN1_STRING_get0_data(),
  ASN1_STRING_data(), X509_alias_get0(), X509_keyid_get0(); variables
  assigned from them (optionally cast, offset, or via strchr/strrchr/
  memchr/ia5memchr/ia5memrchr) in source order; reassignment from a
  non-source clears the variable.
Length expressions: contain an identifier matching /len|length/ or
  `IA5_OFFSET_LEN`, or a variable filled by X509_alias_get0(x, &v) /
  X509_keyid_get0(x, &v), or assigned from a length expression
  (`v = ASN1_STRING_length(...)`, `n = s->length`).
Findings per use:
  UNSAFE  - `%s` without precision, or an argument to a NUL-scanning function
  SAFE    - `%.*s` / length-taking function with a length expression,
            or a dereference in a statement that also tests a length
  UNKNOWN - anything else the rules cannot decide (literal precision,
            non-length size, unmodelled callee, unguarded dereference)
Function verdict: UNSAFE > UNKNOWN > SAFE > NO_SOURCE.
"""
import re
from dataclasses import dataclass, field

from .lexer import tokens

SOURCE_CALLS = {"ASN1_STRING_get0_data", "ASN1_STRING_data", "X509_alias_get0", "X509_keyid_get0"}
LEN_OUT_CALLS = {"X509_alias_get0": 1, "X509_keyid_get0": 1}
POINTER_PROPAGATORS = {"strchr", "strrchr", "memchr", "ia5memchr", "ia5memrchr"}
NUL_SINKS = {"strlen", "strcpy", "strcat", "strdup", "OPENSSL_strdup", "BUF_strdup", "strchr", "strrchr",
             "strcmp", "strcasecmp", "strstr", "strtol", "strtoul", "atoi", "puts", "BIO_puts", "fputs",
             "X509V3_add_value", "X509V3_add_value_uchar", "sk_OPENSSL_STRING_find", "ia5casecmp"}
# function -> index of the size argument
LEN_TAKING = {"strndup": 1, "OPENSSL_strndup": 1, "memchr": 2, "memcpy": 2, "memcmp": 2, "memmove": 2,
              "strncmp": 2, "strncasecmp": 2, "ia5ncasecmp": 2, "x509v3_add_len_value_uchar": 2,
              "BIO_write": 2, "ASN1_STRING_set": 2, "OPENSSL_memdup": 1}
# take a pointer and an ASN1 string, length derived inside (macro in v3_ncons.c)
SELF_BOUNDED = {"ia5memchr", "ia5memrchr"}
NEUTRAL = {"OPENSSL_free", "sizeof", "if", "while", "for", "switch", "return",
           "IA5_OFFSET_LEN", "ASN1_STRING_length"}  # length computations, not reads
PRINTF = re.compile(r"(?:^|_)(?:v?s?n?printf)$|printf$")
CONV = re.compile(r"%([-+ #0]*)(\*|\d+)?(?:\.(\*|\d+))?(hh|h|ll|l|L|q|j|z|t)?([diouxXeEfFgGaAcspn%])")


@dataclass
class Finding:
    line: int
    kind: str      # UNSAFE | SAFE | UNKNOWN
    rule: str
    text: str


@dataclass
class Report:
    verdict: str
    findings: list = field(default_factory=list)


def _split_statements(toks):
    stmt, depth = [], 0
    for t in toks:
        if t[1] == "(":
            depth += 1
        elif t[1] == ")":
            depth -= 1
        if depth == 0 and t[1] in (";", "{", "}"):
            if stmt:
                yield stmt
            stmt = []
            continue
        stmt.append(t)
    if stmt:
        yield stmt


def _match_paren(toks, i):
    depth = 0
    for j in range(i, len(toks)):
        if toks[j][1] == "(":
            depth += 1
        elif toks[j][1] == ")":
            depth -= 1
            if depth == 0:
                return j
    return len(toks) - 1


def _split_args(toks):
    args, cur, depth = [], [], 0
    for t in toks:
        if t[1] in "([":
            depth += 1
        elif t[1] in ")]":
            depth -= 1
        if depth == 0 and t[1] == ",":
            args.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur or args:
        args.append(cur)
    return args


def _text(toks):
    return " ".join(t[1] for t in toks)


class _Scan:
    def __init__(self):
        self.tainted, self.lenvars, self.findings = set(), set(), []
        self.bounded_idx = set()

    def is_len(self, toks):
        for k, t in enumerate(toks):
            if t[0] == "id" and (re.search(r"len|length", t[1], re.I) or t[1] == "IA5_OFFSET_LEN"
                                 or t[1] in self.lenvars):
                return True
        return False

    def is_tainted(self, toks):
        """True if the expression (outside nested calls other than sources/propagators) points into ASN1 data."""
        k = 0
        while k < len(toks):
            kind, v, _ = toks[k]
            if v in ("->", ".") and k + 1 < len(toks) and toks[k + 1][1] == "data":
                nxt = toks[k + 2][1] if k + 2 < len(toks) else ""
                if nxt != "[":
                    return True
            if kind == "id" and k + 1 < len(toks) and toks[k + 1][1] == "(":
                end = _match_paren(toks, k + 1)
                if v in SOURCE_CALLS:
                    return True
                if v in POINTER_PROPAGATORS:
                    inner = _split_args(toks[k + 2:end])
                    if inner and self.is_tainted(inner[0]):
                        return True
                    if v in SELF_BOUNDED and inner and self.is_tainted(inner[0][:]) is False:
                        pass
                if v in ("ia5memrchr",) or (v == "ia5memchr"):
                    inner = _split_args(toks[k + 2:end])
                    if inner and any(self.is_tainted(a) for a in inner[:2]):
                        return True
                k = end + 1
                continue
            if kind == "id" and v in self.tainted:
                prev = toks[k - 1][1] if k else ""
                nxt = toks[k + 1][1] if k + 1 < len(toks) else ""
                if prev != "*" and nxt != "[":
                    return True
                if prev == "*" and k >= 2 and toks[k - 2][1] == "(":
                    # a cast like (char *)p
                    return True
            if v == "&" and k + 3 < len(toks) and toks[k + 2][1] in ("->", ".") and toks[k + 3][1] == "data":
                return True
            k += 1
        return False

    def add(self, line, kind, rule, toks):
        self.findings.append(Finding(line, kind, rule, _text(toks)[:160]))

    def statement(self, st):
        line = st[0][2]
        # length out-params
        for k, t in enumerate(st):
            if t[1] in LEN_OUT_CALLS and k + 1 < len(st) and st[k + 1][1] == "(":
                args = _split_args(st[k + 2:_match_paren(st, k + 1)])
                a = args[LEN_OUT_CALLS[t[1]]] if len(args) > LEN_OUT_CALLS[t[1]] else []
                if len(a) == 2 and a[0][1] == "&" and a[1][0] == "id":
                    self.lenvars.add(a[1][1])
        if st and st[0][1] == "for" and len(st) > 1 and st[1][1] == "(":
            self._for_bounds(st)
        self.calls(st, line)
        self.derefs(st, line)
        # assignment / initialisation (first top-level '=')
        depth = 0
        for k, t in enumerate(st):
            if t[1] in "([":
                depth += 1
            elif t[1] in ")]":
                depth -= 1
            elif t[1] == "=" and depth == 0 and k > 0 and st[k - 1][0] == "id":
                lhs, rhs = st[k - 1][1], st[k + 1:]
                if self.is_tainted(rhs):
                    self.tainted.add(lhs)
                else:
                    self.tainted.discard(lhs)
                if any(x[1] == "ASN1_STRING_length" for x in rhs) or (
                        self.is_len(rhs) and not self.is_tainted(rhs)):
                    self.lenvars.add(lhs)
                else:
                    self.lenvars.discard(lhs)
                break

    def calls(self, st, line):
        k = 0
        while k < len(st):
            kind, v, ln = st[k]
            if kind == "id" and k + 1 < len(st) and st[k + 1][1] == "(":
                end = _match_paren(st, k + 1)
                args = _split_args(st[k + 2:end])
                self.call(v, args, ln, st[k:end + 1])
                # also scan nested calls inside the arguments
                for a in args:
                    self.calls(a, ln)
                k = end + 1
                continue
            k += 1

    def call(self, name, args, line, whole):
        if name in SOURCE_CALLS or name in NEUTRAL:
            return
        tainted = [i for i, a in enumerate(args) if self.is_tainted(a)]
        if PRINTF.search(name):
            fmt_i = next((i for i, a in enumerate(args) if a and a[0][0] == "str"), None)
            if fmt_i is None:
                if tainted:
                    self.add(line, "UNKNOWN", f"{name}: non-literal format", whole)
                return
            fmt = "".join(t[1][1:-1] for t in args[fmt_i] if t[0] == "str")
            ai = fmt_i + 1
            for m in CONV.finditer(fmt):
                flags, width, prec, _, conv = m.groups()
                if conv == "%":
                    continue
                if width == "*":
                    ai += 1
                prec_arg = None
                if prec == "*":
                    prec_arg = args[ai] if ai < len(args) else []
                    ai += 1
                if ai >= len(args):
                    break
                if conv == "s" and ai in tainted:
                    if prec is None:
                        self.add(line, "UNSAFE", f"{name}: %s without precision", whole)
                    elif prec == "*" and self.is_len(prec_arg):
                        self.add(line, "SAFE", f"{name}: %.*s with length", whole)
                    else:
                        self.add(line, "UNKNOWN", f"{name}: %.{prec}s precision not a length", whole)
                ai += 1
            return
        if not tainted:
            return
        if name in NUL_SINKS:
            self.add(line, "UNSAFE", f"{name}: NUL-scanning sink", whole)
        elif name in LEN_TAKING:
            n = LEN_TAKING[name]
            if n < len(args) and self.is_len(args[n]):
                self.add(line, "SAFE", f"{name}: bounded by length", whole)
            else:
                self.add(line, "UNKNOWN", f"{name}: size not a length expression", whole)
        elif name in POINTER_PROPAGATORS or name in SELF_BOUNDED:
            if name in SELF_BOUNDED:
                self.add(line, "SAFE", f"{name}: bounded by IA5_OFFSET_LEN/length", whole)
        else:
            self.add(line, "UNKNOWN", f"{name}: tainted pointer escapes to unmodelled callee", whole)

    def _for_bounds(self, st):
        """for (init; i < LEN; ...): remember i as an index bounded by a length test."""
        end = _match_paren(st, 1)
        hdr = st[2:end]
        parts, cur = [], []
        for t in hdr:
            if t[1] == ";":
                parts.append(cur)
                cur = []
            else:
                cur.append(t)
        parts.append(cur)
        if len(parts) >= 2:
            cond = parts[1]
            for k in range(len(cond) - 1):
                if cond[k][0] == "id" and cond[k + 1][1] in ("<", "<=") and self.is_len(cond[k + 2:]):
                    self.bounded_idx.add(cond[k][1])

    def derefs(self, st, line):
        guard = any(t[0] == "id" and (re.search(r"length|len$", t[1]) or t[1] in self.lenvars or
                                      t[1] == "IA5_OFFSET_LEN") for t in st)
        for k, (kind, v, ln) in enumerate(st):
            hit = False
            if kind == "id" and v in self.tainted:
                prev = st[k - 1][1] if k else ""
                before = st[k - 2][1] if k >= 2 else ""
                nxt = st[k + 1][1] if k + 1 < len(st) else ""
                unary_star = prev == "*" and (k < 2 or st[k - 2][0] not in ("id", "num") and before not in (")", "]"))
                cast_star = prev == "*" and before == "char"
                if (unary_star and not cast_star) or nxt == "[":
                    hit = True
            if v == "data" and k >= 1 and st[k - 1][1] in ("->", ".") and k + 1 < len(st) and st[k + 1][1] == "[":
                hit = True
            if hit and not guard and nxt_index_bounded(st, k, self.bounded_idx):
                self.add(ln, "SAFE", "index bounded by a length-tested for loop", st[max(0, k - 3):k + 4])
                continue
            if hit:
                self.add(ln, "SAFE" if guard else "UNKNOWN",
                         "dereference with a length test in the statement" if guard else "unguarded dereference",
                         st[max(0, k - 3):k + 4])


def nxt_index_bounded(st, k, bounded):
    """st[k] is `p` or `data` followed by `[ i ]` with i a bounded loop index."""
    if k + 3 < len(st) and st[k + 1][1] == "[" and st[k + 2][0] == "id" and st[k + 3][1] == "]":
        return st[k + 2][1] in bounded
    return False


def scan(src: str) -> Report:
    toks = tokens(src)
    s = _Scan()
    for st in _split_statements(toks):
        s.statement(st)
    kinds = {f.kind for f in s.findings}
    verdict = ("UNSAFE" if "UNSAFE" in kinds else "UNKNOWN" if "UNKNOWN" in kinds
               else "SAFE" if "SAFE" in kinds else "NO_SOURCE")
    return Report(verdict, s.findings)
