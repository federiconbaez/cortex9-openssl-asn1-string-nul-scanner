"""Run the scanner over the upstream (OpenSSL 1.1.1l fix series) and synthetic corpora."""
import json
import pathlib

from .extract import function_source
from .scanner import scan

FIX = pathlib.Path(__file__).resolve().parents[2] / "fixtures"


def upstream_rows(root=FIX):
    cases = json.loads((root / "upstream/corpus.json").read_text())["cases"]
    for c in cases:
        for side in ("pre", "post"):
            src = (root / "upstream" / c[side]).read_text()
            r = scan(function_source(src, c["id"]))
            yield {"function": c["id"], "side": side, "file": c[side], "truth": c["truth_" + side],
                   "scanner": r.verdict, "findings": r.findings}


def synthetic_rows(root=FIX):
    for c in json.loads((root / "synthetic.json").read_text())["cases"]:
        r = scan((root / "synthetic" / c["file"]).read_text())
        yield {"file": c["file"], "expect": c["expect"], "truth": c["truth"], "scanner": r.verdict,
               "limitation": c.get("limitation", ""), "findings": r.findings}


def outcome(truth, verdict):
    """How a scanner verdict relates to the hand label."""
    if truth == "OUT_OF_SCOPE":
        return "out_of_scope"
    if truth == "UNSAFE":
        return {"UNSAFE": "detected", "UNKNOWN": "flagged_unknown"}.get(verdict, "missed")
    if truth == "SAFE":
        return {"UNSAFE": "false_positive", "UNKNOWN": "unknown_on_safe"}.get(verdict, "correct_safe")
    if truth == "UNKNOWN":
        return {"UNKNOWN": "agrees_unknown", "UNSAFE": "overclaims_unsafe"}.get(verdict, "underclaims_safe")
    raise ValueError(truth)
