"""Regenerate results/ (deterministic). Usage: gen_results.py [outdir]"""
import collections
import csv
import hashlib
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from asn1nul.corpus import outcome, synthetic_rows, upstream_rows  # noqa: E402

out = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "results"
out.mkdir(parents=True, exist_ok=True)
up = list(upstream_rows())
with open(out / "upstream.csv", "w", newline="") as f:
    w = csv.writer(f, lineterminator="\n")
    w.writerow(["function", "side", "file", "truth", "scanner", "outcome", "unsafe", "unknown", "safe"])
    for r in up:
        k = collections.Counter(x.kind for x in r["findings"])
        w.writerow([r["function"], r["side"], r["file"], r["truth"], r["scanner"],
                    outcome(r["truth"], r["scanner"]), k["UNSAFE"], k["UNKNOWN"], k["SAFE"]])
with open(out / "upstream_findings.csv", "w", newline="") as f:
    w = csv.writer(f, lineterminator="\n")
    w.writerow(["function", "side", "rel_line", "kind", "rule", "text"])
    for r in up:
        for x in r["findings"]:
            w.writerow([r["function"], r["side"], x.line, x.kind, x.rule, x.text])
with open(out / "summary.csv", "w", newline="") as f:
    w = csv.writer(f, lineterminator="\n")
    w.writerow(["corpus", "side", "outcome", "count"])
    c = collections.Counter((r["side"], outcome(r["truth"], r["scanner"])) for r in up)
    for (side, o), n in sorted(c.items()):
        w.writerow(["upstream", side, o, n])
    syn = list(synthetic_rows())
    c2 = collections.Counter(outcome(r["truth"], r["scanner"]) for r in syn)
    for o, n in sorted(c2.items()):
        w.writerow(["synthetic", "-", o, n])
    w.writerow(["synthetic", "-", "rule_mismatches", sum(r["scanner"] != r["expect"] for r in syn)])
with open(out / "synthetic.csv", "w", newline="") as f:
    w = csv.writer(f, lineterminator="\n")
    w.writerow(["file", "expect", "scanner", "truth", "outcome", "limitation"])
    for r in syn:
        w.writerow([r["file"], r["expect"], r["scanner"], r["truth"], outcome(r["truth"], r["scanner"]), r["limitation"]])
FILES = ("upstream.csv", "upstream_findings.csv", "summary.csv", "synthetic.csv")
(out / "SHA256SUMS").write_text("".join(
    f"{hashlib.sha256((out / n).read_bytes()).hexdigest()}  {n}\n" for n in FILES))
