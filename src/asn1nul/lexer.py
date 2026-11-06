"""Minimal C lexer: drops comments and preprocessor lines, keeps string literals as tokens."""
import re

_TOKEN = re.compile(r'''
    (?P<str>"(?:\\.|[^"\\])*")
  | (?P<chr>'(?:\\.|[^'\\])*')
  | (?P<id>[A-Za-z_][A-Za-z_0-9]*)
  | (?P<num>\d[\w.]*)
  | (?P<op>->|\+\+|--|&&|\|\||==|!=|<=|>=|<<|>>|[-+*/%&|^!~<>=?:;,.(){}\[\]#])
  | (?P<ws>\s+)
''', re.X)


def strip_comments(src: str) -> str:
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c == '"' or c == "'":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1])
            i = j + 1
        elif src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append("\n" * src.count("\n", i, j))
            i = j
        elif src.startswith("//", i):
            j = src.find("\n", i)
            i = n if j < 0 else j
        else:
            out.append(c)
            i += 1
    return "".join(out)


def drop_preprocessor(src: str) -> str:
    lines, cont = [], False
    for line in src.split("\n"):
        if cont or line.lstrip().startswith("#"):
            cont = line.rstrip().endswith("\\")
            lines.append("")
        else:
            lines.append(line)
    return "\n".join(lines)


def tokens(src: str):
    src = drop_preprocessor(strip_comments(src))
    out, line = [], 1
    for m in _TOKEN.finditer(src):
        kind = m.lastgroup
        if kind == "ws":
            line += m.group().count("\n")
            continue
        out.append((kind, m.group(), line))
    return out
