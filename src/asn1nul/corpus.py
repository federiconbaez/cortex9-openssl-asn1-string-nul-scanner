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
    """How a scanner label relates to the hand label (truth is UNSAFE / SAFE / UNKNOWN / OUT_OF_SCOPE)."""
    if truth == "OUT_OF_SCOPE":
        return "out_of_scope"
    if truth == "UNSAFE":
        return {"NUL_SINK_WARNING": "warned", "UNKNOWN": "unknown_on_unsafe"}.get(verdict, "not_warned_on_unsafe")
    if truth == "SAFE":
        return {"NUL_SINK_WARNING": "warning_on_safe", "UNKNOWN": "unknown_on_safe"}.get(verdict, "no_warning_on_safe")
    if truth == "UNKNOWN":
        return {"UNKNOWN": "unknown_on_unknown", "NUL_SINK_WARNING": "warning_on_unknown"}.get(verdict, "bounded_on_unknown")
    raise ValueError(truth)
