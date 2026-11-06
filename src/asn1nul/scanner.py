"""Intraprocedural lexical scan for ASN1_STRING data reaching NUL-assuming operations.

This is a heuristic warning tool, not a verifier. Labels:
  NUL_SINK_WARNING  - the bytes reach `%s` without precision or a function that
                      scans for NUL. A warning about a code pattern, NOT proof
                      that a real over-read happens (the buffer may be
                      NUL-terminated by construction).
  BOUNDED_PATTERN   - the use matches a recognised bounding pattern whose bound
                      is syntactically tied to the SAME origin object (see
                      below). It does NOT mean "safe": it assumes length >= 0
                      and that nothing between the bound and the use changes it.
  UNKNOWN           - the rules cannot relate the use to a bound.
Function verdict: NUL_SINK_WARNING > UNKNOWN > BOUNDED_PATTERN > NO_SOURCE.

Origins. A pointer is tainted with an origin:
  `X->data` / `X.data`            -> origin X (text of the base expression)
  ASN1_STRING_get0_data(X) / ASN1_STRING_data(X) -> origin X
  X509_alias_get0(x, &v) / X509_keyid_get0(x, &v) -> origin "alias(x)", and v
                                     becomes a length of that origin
Assignments copy origin; casts are ignored; `p + k`, `&X->data[k]`, and
strchr/strrchr/memchr/ia5memchr/ia5memrchr results are DERIVED pointers of
the same origin (they point inside, so the origin's full length is no
longer a valid bound for them).
Bound expressions accepted for a pointer of origin X (after removing casts
and outer parentheses; any other arithmetic -> UNKNOWN):
  base pointer:    X->length, X.length, ASN1_STRING_length(X), a variable v
                   last assigned exactly one of those (or filled by the
                   alias/keyid out-parameter for that origin)
  derived pointer: IA5_OFFSET_LEN(X, that_pointer) only
Dereferences `*p` / `p[0]` are BOUNDED_PATTERN only when, in the same
condition, a test `X->length > 0` (or `!= 0`, `>= 1`) precedes them joined
by `&&` at the same nesting level. `p[i]` is BOUNDED_PATTERN only inside the
body of `for (...; i < B; ...)` where B is an accepted bound for p's origin;
`<=` is not accepted. The rules do not check that the body leaves i or the
bound unchanged (documented limitation). Everything else is UNKNOWN.
"""
import re
from dataclasses import dataclass, field

from .lexer import tokens

WARN, BOUNDED, UNKNOWN, NONE = "NUL_SINK_WARNING", "BOUNDED_PATTERN", "UNKNOWN", "NO_SOURCE"
SOURCE_CALLS = {"ASN1_STRING_get0_data", "ASN1_STRING_data"}
ALIAS_CALLS = {"X509_alias_get0", "X509_keyid_get0"}
POINTER_PROPAGATORS = {"strchr", "strrchr", "memchr", "ia5memchr", "ia5memrchr"}
NUL_SINKS = {"strlen", "strcpy", "strcat", "strdup", "OPENSSL_strdup", "BUF_strdup", "strchr", "strrchr",
             "strcmp", "strcasecmp", "strstr", "strtol", "strtoul", "atoi", "puts", "BIO_puts", "fputs",
             "X509V3_add_value", "X509V3_add_value_uchar", "sk_OPENSSL_STRING_find", "ia5casecmp"}
LEN_TAKING = {"strndup": 1, "OPENSSL_strndup": 1, "memchr": 2, "memcpy": 2, "memcmp": 2, "memmove": 2,
              "strncmp": 2, "strncasecmp": 2, "ia5ncasecmp": 2, "x509v3_add_len_value_uchar": 2,
              "BIO_write": 2, "ASN1_STRING_set": 2, "OPENSSL_memdup": 1}
SELF_BOUNDED = {"ia5memchr": 0, "ia5memrchr": 0}   # bound computed from the ASN1 object argument
NEUTRAL = {"OPENSSL_free", "sizeof", "if", "while", "for", "switch", "return", "IA5_OFFSET_LEN",
           "ASN1_STRING_length"}
PRINTF = re.compile(r"printf$")
CONV = re.compile(r"%([-+ #0]*)(\*|\d+)?(?:\.(\*|\d+))?(hh|h|ll|l|L|q|j|z|t)?([diouxXeEfFgGaAcspn%])")


@dataclass
class Finding:
    line: int
    kind: str
    rule: str
    text: str


@dataclass
class Report:
    verdict: str
    findings: list = field(default_factory=list)


@dataclass(frozen=True)
class Taint:
    origin: str
    derived: bool


def _match(toks, i, o="(", c=")"):
    depth = 0
    for j in range(i, len(toks)):
        if toks[j][1] == o:
            depth += 1
        elif toks[j][1] == c:
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


_TYPEWORDS = {"char", "unsigned", "signed", "const", "int", "size_t", "void", "long", "short", "uint8_t"}


def _strip(toks):
    """Remove leading casts `(type *)` and redundant outer parentheses."""
    toks = list(toks)
    changed = True
    while changed and toks:
        changed = False
        if toks[0][1] == "(":
            end = _match(toks, 0)
            inner = toks[1:end]
            if end == len(toks) - 1:
                toks, changed = inner, True
            elif inner and all(t[1] in _TYPEWORDS or t[1] == "*" or t[0] == "id" for t in inner) \
                    and any(t[1] in _TYPEWORDS or t[1] == "*" for t in inner):
                toks, changed = toks[end + 1:], True
    return toks


def _member(toks, name):
    """If toks is `BASE -> name` or `BASE . name`, return BASE text, else None."""
    if len(toks) >= 3 and toks[-1][1] == name and toks[-2][1] in ("->", "."):
        base = toks[:-2]
        if all(t[0] == "id" or t[1] in ("->", ".") for t in base):
            return _text(base)
    return None


class _Scan:
    def __init__(self):
        self.taint = {}        # var -> Taint
        self.lens = {}         # var -> origin
        self.loop_idx = []     # stack of (brace_depth, var, origin)
        self.stmt_idx = []     # (var, origin) bounded only within the current statement
        self.findings = []

    # ---- expressions -------------------------------------------------
    def taint_of(self, toks):
        e = _strip(toks)
        if not e:
            return None
        m = _member(e, "data")
        if m:
            return Taint(m, False)
        if e[0][0] == "id" and len(e) > 1 and e[1][1] == "(" and _match(e, 1) == len(e) - 1:
            args = _split_args(e[2:-1])
            if e[0][1] in SOURCE_CALLS and args:
                return Taint(_text(_strip(args[0])), False)
            if e[0][1] in ALIAS_CALLS and args:
                return Taint(f"alias({_text(args[0])})", False)
            if e[0][1] in POINTER_PROPAGATORS and args:
                idx = 1 if e[0][1] == "ia5memchr" else 0
                t = self.taint_of(args[idx]) if len(args) > idx else None
                if e[0][1] == "ia5memrchr":
                    o = _text(_strip(args[0]))
                    return Taint(o, True)
                return Taint(t.origin, True) if t else None
            return None
        if len(e) == 1 and e[0][0] == "id" and e[0][1] in self.taint:
            return self.taint[e[0][1]]
        if e[0][1] == "&" and len(e) > 1:
            inner = _strip(e[1:])
            for k in range(len(inner)):
                if inner[k][1] == "[":
                    m = _member(inner[:k], "data")
                    if m:
                        return Taint(m, True)
                    if k == 1 and inner[0][1] in self.taint:
                        return Taint(self.taint[inner[0][1]].origin, True)
        # pointer arithmetic p + k / p - k
        for k, t in enumerate(e):
            if t[1] in ("+", "-") and k > 0:
                left = self.taint_of(e[:k])
                if left:
                    return Taint(left.origin, True)
        return None

    def bound_origin(self, toks):
        """Origin for which toks is an accepted bound of a BASE pointer, else None."""
        e = _strip(toks)
        m = _member(e, "length")
        if m:
            return m
        if len(e) == 1 and e[0][0] == "id" and e[0][1] in self.lens:
            return self.lens[e[0][1]]
        if len(e) >= 4 and e[0][1] == "ASN1_STRING_length" and e[1][1] == "(" and _match(e, 1) == len(e) - 1:
            return _text(_strip(e[2:-1]))
        return None

    def bounds(self, taint, toks):
        if taint is None:
            return False
        e = _strip(toks)
        if taint.derived:
            if len(e) >= 4 and e[0][1] == "IA5_OFFSET_LEN" and e[1][1] == "(" and _match(e, 1) == len(e) - 1:
                args = _split_args(e[2:-1])
                return len(args) == 2 and _text(_strip(args[0])) == taint.origin
            return False
        return self.bound_origin(e) == taint.origin

    def add(self, line, kind, rule, toks):
        self.findings.append(Finding(line, kind, rule, _text(toks)[:160]))

    # ---- statements --------------------------------------------------
    def statement(self, st, depth, opens_block):
        line = st[0][2]
        self.stmt_idx = []
        if st[0][1] == "for" and len(st) > 1 and st[1][1] == "(":
            self.for_header(st, depth, opens_block)
        for k, t in enumerate(st):
            if t[1] in ALIAS_CALLS and k + 1 < len(st) and st[k + 1][1] == "(":
                args = _split_args(st[k + 2:_match(st, k + 1)])
                if len(args) > 1 and len(args[1]) == 2 and args[1][0][1] == "&" and args[1][1][0] == "id":
                    self.lens[args[1][1][1]] = f"alias({_text(args[0])})"
        self.calls(st, line)
        self.derefs(st, line)
        self.assign(st)

    def assign(self, st):
        depth = 0
        for k, t in enumerate(st):
            if t[1] in "([":
                depth += 1
            elif t[1] in ")]":
                depth -= 1
            elif t[1] == "=" and depth == 0 and k > 0 and st[k - 1][0] == "id":
                lhs, rhs = st[k - 1][1], st[k + 1:]
                cut = next((j for j, x in enumerate(rhs) if x[1] == "," and _depth0(rhs, j)), len(rhs))
                rhs = rhs[:cut]
                tt = self.taint_of(rhs)
                if tt:
                    self.taint[lhs] = tt
                else:
                    self.taint.pop(lhs, None)
                bo = self.bound_origin(rhs)
                if bo:
                    self.lens[lhs] = bo
                else:
                    self.lens.pop(lhs, None)
                # `int i, n = s->length` : continue with the remainder
                if cut < len(st[k + 1:]):
                    self.assign(st[k + 1 + cut + 1:])
                return

    def for_header(self, st, depth, opens_block):
        end = _match(st, 1)
        parts, cur = [], []
        for t in st[2:end]:
            if t[1] == ";":
                parts.append(cur)
                cur = []
            else:
                cur.append(t)
        parts.append(cur)
        if len(parts) >= 2 and len(parts[1]) >= 3 and parts[1][0][0] == "id" and parts[1][1][1] == "<":
            o = self.bound_origin(parts[1][2:])
            if o:
                if opens_block:
                    self.loop_idx.append((depth + 1, parts[1][0][1], o))
                else:
                    self.stmt_idx.append((parts[1][0][1], o))

    def close_block(self, depth):
        self.loop_idx = [x for x in self.loop_idx if x[0] <= depth]

    def calls(self, st, line):
        k = 0
        while k < len(st):
            kind, v, ln = st[k]
            if kind == "id" and k + 1 < len(st) and st[k + 1][1] == "(":
                end = _match(st, k + 1)
                args = _split_args(st[k + 2:end])
                self.call(v, args, ln, st[k:end + 1])
                for a in args:
                    self.calls(a, ln)
                k = end + 1
                continue
            k += 1

    def call(self, name, args, line, whole):
        if name in SOURCE_CALLS or name in ALIAS_CALLS or name in NEUTRAL:
            return
        taints = {i: self.taint_of(a) for i, a in enumerate(args)}
        tainted = {i: t for i, t in taints.items() if t}
        if PRINTF.search(name):
            fmt_i = next((i for i, a in enumerate(args) if a and a[0][0] == "str"), None)
            if fmt_i is None:
                if tainted:
                    self.add(line, UNKNOWN, f"{name}: non-literal format", whole)
                return
            fmt = "".join(t[1][1:-1] for t in args[fmt_i] if t[0] == "str")
            ai = fmt_i + 1
            for m in CONV.finditer(fmt):
                _, width, prec, _, conv = m.groups()
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
                        self.add(line, WARN, f"{name}: %s without precision", whole)
                    elif prec == "*" and self.bounds(tainted[ai], prec_arg):
                        self.add(line, BOUNDED, f"{name}: %.*s precision is the origin's length", whole)
                    else:
                        self.add(line, UNKNOWN, f"{name}: %.{prec}s precision not tied to the origin's length", whole)
                ai += 1
            return
        if not tainted:
            return
        if name in NUL_SINKS:
            self.add(line, WARN, f"{name}: NUL-scanning function", whole)
        elif name in SELF_BOUNDED:
            self.add(line, BOUNDED, f"{name}: bound derived from the ASN1 object argument", whole)
        elif name in LEN_TAKING:
            n = LEN_TAKING[name]
            ptrs = [t for i, t in tainted.items() if i != n]
            if n < len(args) and ptrs and all(self.bounds(t, args[n]) for t in ptrs):
                self.add(line, BOUNDED, f"{name}: size is the origin's length", whole)
            else:
                self.add(line, UNKNOWN, f"{name}: size not tied to the origin's length", whole)
        else:
            self.add(line, UNKNOWN, f"{name}: tainted pointer passed to unmodelled callee", whole)

    def derefs(self, st, line):
        idx_ok = {(v, o) for (_, v, o) in self.loop_idx} | set(self.stmt_idx)
        for k, (kind, v, ln) in enumerate(st):
            ptr, index = None, None
            if kind == "id" and v in self.taint:
                nxt = st[k + 1][1] if k + 1 < len(st) else ""
                prev = st[k - 1][1] if k else ""
                before = st[k - 2] if k >= 2 else ("", "", 0)
                unary = prev == "*" and (k < 2 or before[1] in ("(", "!", "&&", "||", "=", ",", "==", "!=", "return")
                                         or before[0] == "op" and before[1] not in (")", "]"))
                cast = prev == "*" and before[1] in _TYPEWORDS
                if nxt == "[":
                    ptr, index = self.taint[v], st[k + 2:_match(st, k + 1, "[", "]")]
                elif unary and not cast:
                    ptr, index = self.taint[v], [("num", "0", ln)]
            elif v == "data" and k >= 2 and st[k - 1][1] in ("->", ".") and k + 1 < len(st) and st[k + 1][1] == "[":
                base = []
                j = k - 2
                while j >= 0 and (st[j][0] == "id" or st[j][1] in ("->", ".")):
                    base.insert(0, st[j])
                    j -= 1
                ptr, index = Taint(_text(base), False), st[k + 2:_match(st, k + 1, "[", "]")]
            if ptr is None:
                continue
            ctx = st[max(0, k - 3):k + 4]
            if len(index) == 1 and index[0][0] == "id" and (index[0][1], ptr.origin) in idx_ok and not ptr.derived:
                self.add(ln, BOUNDED, "index bounded by an enclosing `for (i < origin length)`", ctx)
            elif len(index) == 1 and index[0][1] == "0" and not ptr.derived and self._guard_before(st, k, ptr.origin):
                self.add(ln, BOUNDED, "first byte read after `origin->length > 0 &&`", ctx)
            else:
                self.add(ln, UNKNOWN, "dereference not tied to a bound", ctx)

    def _guard_before(self, st, k, origin):
        """A `origin->length > 0 &&` (or != 0, >= 1) chain item to the left of st[k] at the same depth."""
        depth_at = [0] * len(st)
        d = 0
        for i, t in enumerate(st):
            if t[1] == "(":
                d += 1
            depth_at[i] = d
            if t[1] == ")":
                d -= 1
        target = depth_at[k]
        seg_start = 0
        for i in range(k - 1, -1, -1):
            if depth_at[i] < target:
                seg_start = i + 1
                break
            if st[i][1] == "||" and depth_at[i] == target:
                return False
        seg = st[seg_start:k]
        txt = _text(seg)
        pats = [f"{origin} -> length > 0 &&", f"{origin} -> length != 0 &&", f"{origin} -> length >= 1 &&",
                f"{origin} . length > 0 &&"]
        return any(p in txt for p in pats)


def _depth0(toks, j):
    d = 0
    for t in toks[:j]:
        if t[1] in "([":
            d += 1
        elif t[1] in ")]":
            d -= 1
    return d == 0


def scan(src: str) -> Report:
    s = _Scan()
    stmt, pdepth, bdepth = [], 0, 0
    for t in tokens(src):
        if t[1] == "(":
            pdepth += 1
        elif t[1] == ")":
            pdepth -= 1
        if pdepth == 0 and t[1] in (";", "{", "}"):
            if stmt:
                s.statement(stmt, bdepth, t[1] == "{")
            stmt = []
            if t[1] == "{":
                bdepth += 1
            elif t[1] == "}":
                bdepth -= 1
                s.close_block(bdepth)
            continue
        stmt.append(t)
    if stmt:
        s.statement(stmt, bdepth, False)
    kinds = {f.kind for f in s.findings}
    verdict = WARN if WARN in kinds else UNKNOWN if UNKNOWN in kinds else BOUNDED if BOUNDED in kinds else NONE
    return Report(verdict, s.findings)
