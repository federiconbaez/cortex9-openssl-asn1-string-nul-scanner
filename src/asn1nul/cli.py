"""CLI:
  python -m asn1nul scan FILE.c [--function NAME]   lexical scan of local C text (nothing is compiled or run)
  python -m asn1nul corpus                          upstream + synthetic summary
"""
import argparse
import json
import pathlib

from .corpus import outcome, synthetic_rows, upstream_rows
from .extract import function_source
from .scanner import scan


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="asn1nul")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("file")
    s.add_argument("--function")
    sub.add_parser("corpus")
    a = ap.parse_args(argv)
    if a.cmd == "scan":
        src = pathlib.Path(a.file).read_text(errors="replace")
        if a.function:
            src = function_source(src, a.function)
        r = scan(src)
        print(json.dumps({"verdict": r.verdict, "findings": [f.__dict__ for f in r.findings]}, indent=2))
        return 0
    out = {"upstream": [{k: r[k] for k in ("function", "side", "truth", "scanner")} | {"outcome": outcome(r["truth"], r["scanner"])}
                        for r in upstream_rows()],
           "synthetic_mismatches": [r["file"] for r in synthetic_rows() if r["scanner"] != r["expect"]]}
    print(json.dumps(out, indent=2))
    return 0
