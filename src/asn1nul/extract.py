"""Extract one function definition (by name) from a C file."""
from .lexer import strip_comments


def function_source(src: str, name: str) -> str:
    text = strip_comments(src)
    lines = text.split("\n")
    for i, line in enumerate(lines):
        if not line or line[0].isspace() or line.startswith("#"):
            continue
        if f"{name}(" not in line.replace(" (", "("):
            continue
        j, buf = i, ""
        while j < len(lines):
            buf += lines[j] + "\n"
            if ";" in lines[j] and "{" not in buf:
                break
            if "{" in lines[j]:
                break
            j += 1
        if "{" not in buf:
            continue
        depth, k, body = 0, i, []
        while k < len(lines):
            body.append(lines[k])
            depth += lines[k].count("{") - lines[k].count("}")
            if depth == 0 and "{" in "".join(body):
                return "\n".join(body) + "\n"
            k += 1
    raise KeyError(name)
