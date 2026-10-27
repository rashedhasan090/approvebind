from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .core import SEVERITIES, SEV_RANK, DEFAULT_SENSITIVE, analyze, parse_trace, summarize


def render_text(rep: dict, name: str) -> str:
    lines = [f"approvebind: {name}",
             f"  {rep['calls']} calls, {rep['approvals']} approvals, {rep['bound']} calls bound to an approval"]
    if not rep["findings"]:
        lines.append("  OK: every executed call matches what was approved")
    for f in rep["findings"]:
        ap = f" approval={f['approval']}" if f["approval"] else ""
        lines.append(f"  [{f['severity'].upper()}] {f['code']} event#{f['call_index']} {f['tool']}{ap}")
        lines.append(f"      {f['message']}")
        if "approved" in f["detail"] and "executed" in f["detail"]:
            lines.append(f"      approved: {f['detail']['approved']}")
            lines.append(f"      executed: {f['detail']['executed']}")
    c = rep["counts"]
    lines.append("  " + ", ".join(f"{c[s]} {s}" for s in reversed(SEVERITIES)))
    return "\n".join(lines)


def render_md(rep: dict, name: str) -> str:
    out = [f"## approvebind: `{name}`", "",
           f"{rep['calls']} calls, {rep['approvals']} approvals, {rep['bound']} bound.", ""]
    if not rep["findings"]:
        return "\n".join(out + ["No findings."])
    out += ["| Severity | Code | Event | Tool | Approval | Message |", "|---|---|---|---|---|---|"]
    for f in rep["findings"]:
        out.append(f"| {f['severity']} | {f['code']} | {f['call_index']} | `{f['tool']}` | "
                   f"{f['approval'] or ''} | {f['message'].replace('|', '/')} |")
    return "\n".join(out)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="approvebind",
                                description="Check that what an agent executed is exactly what was approved.")
    p.add_argument("traces", nargs="+", help="JSONL or JSON trace files ('-' for stdin)")
    p.add_argument("--format", choices=["text", "json", "md"], default="text")
    p.add_argument("--max-age", type=float, default=300.0,
                   help="seconds an approval stays valid (default 300, 0 disables)")
    p.add_argument("--sensitive", default=DEFAULT_SENSITIVE,
                   help="regex of tool names that need an approval")
    p.add_argument("--fail-on", choices=SEVERITIES + ["none"], default="high",
                   help="exit 1 if any finding is at or above this severity (default high)")
    p.add_argument("--version", action="version", version=__version__)
    a = p.parse_args(argv)
    worst = -1
    reports = []
    for path in a.traces:
        text = sys.stdin.read() if path == "-" else open(path, encoding="utf-8").read()
        approvals, calls = parse_trace(text)
        f = analyze(approvals, calls, max_age=a.max_age or None, sensitive=a.sensitive)
        rep = summarize(f, calls, approvals)
        rep["trace"] = path
        reports.append(rep)
        for x in f:
            worst = max(worst, SEV_RANK[x["severity"]] if isinstance(x, dict) else SEV_RANK[x.severity])
    if a.format == "json":
        print(json.dumps(reports if len(reports) > 1 else reports[0], indent=2))
    else:
        r = render_md if a.format == "md" else render_text
        print("\n\n".join(r(rep, rep["trace"]) for rep in reports))
    if a.fail_on != "none" and worst >= SEV_RANK[a.fail_on]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
