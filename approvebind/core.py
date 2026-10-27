"""Bind approvals to executed tool calls and report where they diverge."""
from __future__ import annotations

import json
import posixpath
import re
import shlex
from dataclasses import dataclass, field, asdict
from typing import Any

SEVERITIES = ["low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

DEFAULT_SENSITIVE = r"(shell|bash|exec|run_command|terminal|write|edit|delete|remove|rm|move|rename|send|email|post|deploy|push|transfer|pay|http_request)"
PATH_KEYS = {"path", "file", "filepath", "file_path", "target", "dest", "destination",
             "src", "source", "dir", "directory", "cwd", "filename", "to", "url"}
COMMAND_KEYS = {"command", "cmd", "script"}
ESCALATING_FLAGS = {"-r", "-R", "-f", "-rf", "-fr", "--force", "--recursive", "--no-verify",
                    "--hard", "-y", "--yes", "--all", "--prune", "--delete", "-D", "--force-with-lease",
                    "--no-preserve-root", "sudo"}
REBIND_TOOLS = re.compile(r"\b(ln|mv|cp|rename|symlink|mount|chmod|chown)\b")


@dataclass
class Finding:
    code: str
    severity: str
    call_index: int
    tool: str
    approval: str | None
    message: str
    detail: dict = field(default_factory=dict)


@dataclass
class Approval:
    id: str
    tool: str
    args: dict
    index: int
    ts: float | None
    cwd: str | None
    single_use: bool = True
    uses: list = field(default_factory=list)


@dataclass
class Call:
    index: int
    tool: str
    args: dict
    approval: str | None
    ts: float | None
    cwd: str | None
    bound: str | None = None
    inferred: bool = False


def _load_args(a: Any) -> dict:
    if isinstance(a, dict):
        return a
    if isinstance(a, str):
        try:
            v = json.loads(a)
            return v if isinstance(v, dict) else {"value": v}
        except ValueError:
            return {"command": a}
    if a is None:
        return {}
    return {"value": a}


def _ts(e: dict) -> float | None:
    v = e.get("ts", e.get("timestamp", e.get("time")))
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        from datetime import datetime
        try:
            return datetime.fromisoformat(v.replace("Z", "+00:00")).timestamp()
        except ValueError:
            return None
    return None


def parse_trace(text: str) -> tuple[list[Approval], list[Call]]:
    """Parse a JSONL (or JSON array) trace of approval and tool_call events."""
    text = text.strip()
    if not text:
        return [], []
    if text.startswith("["):
        events = json.loads(text)
    else:
        events = [json.loads(l) for l in text.splitlines() if l.strip() and not l.lstrip().startswith("//")]
    approvals: list[Approval] = []
    calls: list[Call] = []
    cwd: str | None = None
    for i, e in enumerate(events):
        kind = (e.get("type") or e.get("event") or "").lower()
        if kind in ("cwd", "chdir"):
            cwd = e.get("path") or e.get("cwd")
            continue
        if e.get("cwd") and kind not in ("approval", "approve"):
            cwd = e["cwd"]
        if kind in ("approval", "approve", "approved", "confirm", "guard_allow"):
            c = e.get("call") or {}
            tool = c.get("tool") or c.get("name") or e.get("tool") or ""
            args = _load_args(c.get("args", c.get("arguments", e.get("args"))))
            approvals.append(Approval(
                id=str(e.get("id") or f"approval@{i}"), tool=tool, args=args, index=i,
                ts=_ts(e), cwd=e.get("cwd") or cwd,
                single_use=e.get("scope", "once") in ("once", "single", None)))
        elif kind in ("tool_call", "call", "function_call", "tool_use", "exec"):
            fn = e.get("function") or {}
            tool = e.get("tool") or e.get("name") or fn.get("name") or ""
            args = _load_args(e.get("args", e.get("arguments", e.get("input", fn.get("arguments")))))
            calls.append(Call(index=i, tool=tool, args=args,
                              approval=e.get("approval") or e.get("approval_id"),
                              ts=_ts(e), cwd=cwd))
    return approvals, calls


def _resolve(p: str, cwd: str | None) -> str:
    if p.startswith(("http://", "https://")):
        return p
    if not p.startswith("/") and cwd:
        p = posixpath.join(cwd, p)
    return posixpath.normpath(p)


def _is_unpinned(v: str) -> str | None:
    if re.search(r"\$\{?\w+", v):
        return "environment variable"
    if v.startswith("~"):
        return "home directory expansion"
    if re.search(r"[*?\[]", v):
        return "glob pattern"
    if re.search(r"`|\$\(", v):
        return "command substitution"
    return None


def _cmd_tokens(s: str) -> list[str]:
    try:
        return shlex.split(s)
    except ValueError:
        return s.split()


def _cmd_paths(tokens: list[str]) -> list[str]:
    return [t for t in tokens[1:] if not t.startswith("-") and ("/" in t or "." in t)]


def _paths_of(args: dict) -> dict[str, str]:
    out = {}
    for k, v in args.items():
        if isinstance(v, str) and k.lower() in PATH_KEYS:
            out[k] = v
    for k in COMMAND_KEYS:
        if isinstance(args.get(k), str):
            for j, t in enumerate(_cmd_paths(_cmd_tokens(args[k]))):
                out[f"{k}[{j}]"] = t
    return out


def _flatten(d: Any, prefix: str = "") -> dict[str, Any]:
    if isinstance(d, dict):
        out = {}
        for k, v in d.items():
            out.update(_flatten(v, f"{prefix}.{k}" if prefix else str(k)))
        return out
    if isinstance(d, list):
        out = {}
        for i, v in enumerate(d):
            out.update(_flatten(v, f"{prefix}[{i}]"))
        return out
    return {prefix: d}


def bind(approvals: list[Approval], calls: list[Call]) -> None:
    by_id = {a.id: a for a in approvals}
    for c in calls:
        if c.approval and c.approval in by_id:
            c.bound = c.approval
            by_id[c.approval].uses.append(c.index)
            continue
        # infer: most recent prior approval for same tool that is unused (or reusable)
        best = None
        for a in approvals:
            if a.index < c.index and a.tool == c.tool and (not a.uses or not a.single_use):
                best = a
        if best is not None:
            c.bound, c.inferred = best.id, True
            best.uses.append(c.index)


def analyze(approvals: list[Approval], calls: list[Call], *, max_age: float | None = 300.0,
            sensitive: str = DEFAULT_SENSITIVE) -> list[Finding]:
    bind(approvals, calls)
    by_id = {a.id: a for a in approvals}
    sens = re.compile(sensitive, re.I)
    findings: list[Finding] = []

    def add(code, sev, c, a, msg, **detail):
        findings.append(Finding(code, sev, c.index, c.tool, a.id if a else None, msg, detail))

    for c in calls:
        a = by_id.get(c.bound) if c.bound else None
        if c.approval and c.approval not in by_id:
            add("DANGLING_APPROVAL", "high", c, None,
                f"call cites approval '{c.approval}' that never appears in the trace")
        if a is None:
            if sens.search(c.tool) and approvals:
                add("UNBOUND_CALL", "medium", c, None,
                    "sensitive call ran with no approval bound to it while other calls were approved")
            continue
        if a.tool != c.tool:
            add("TOOL_SWAP", "critical", c, a,
                f"approved tool '{a.tool}' but executed '{c.tool}'", approved=a.tool, executed=c.tool)
            continue
        # argument drift
        fa, fc = _flatten(a.args), _flatten(c.args)
        changed = {k: {"approved": fa.get(k), "executed": fc.get(k)}
                   for k in sorted(set(fa) | set(fc)) if fa.get(k) != fc.get(k)}
        cmd_key = next((k for k in COMMAND_KEYS if isinstance(a.args.get(k), str)
                        and isinstance(c.args.get(k), str)), None)
        if cmd_key and a.args[cmd_key] != c.args[cmd_key]:
            ta, tc = _cmd_tokens(a.args[cmd_key]), _cmd_tokens(c.args[cmd_key])
            added = [t for t in tc if t not in ta]
            esc = [t for t in added if t in ESCALATING_FLAGS or re.fullmatch(r"-[a-zA-Z]*[rf][a-zA-Z]*", t)]
            chained = [t for t in added if t in ("&&", "||", ";", "|") or t.endswith(";")]
            if esc or chained:
                add("SCOPE_ESCALATION", "critical", c, a,
                    "executed command adds " + ", ".join(
                        ([f"escalating flags {esc}"] if esc else []) +
                        ([f"chained commands {chained}"] if chained else [])) +
                    " that were not in the approved command",
                    approved=a.args[cmd_key], executed=c.args[cmd_key])
            else:
                add("ARG_DRIFT", "high", c, a, "executed command differs from approved command",
                    approved=a.args[cmd_key], executed=c.args[cmd_key])
        elif changed:
            add("ARG_DRIFT", "high", c, a,
                f"{len(changed)} argument(s) differ from what was approved: " + ", ".join(changed),
                changes=changed)
        # target rebinding through cwd change
        pa, pc = _paths_of(a.args), _paths_of(c.args)
        for k, v in pa.items():
            if k in pc and pc[k] == v and not v.startswith(("/", "http")):
                ra, rc = _resolve(v, a.cwd), _resolve(v, c.cwd)
                if ra != rc:
                    add("TARGET_REBIND", "high", c, a,
                        f"relative path '{v}' was approved in {a.cwd or '?'} but executed in {c.cwd or '?'}",
                        approved_target=ra, executed_target=rc)
            why = _is_unpinned(v)
            if why:
                add("UNPINNED_TARGET", "medium", c, a,
                    f"approved target '{v}' uses {why}, so the approver could not see what it resolves to",
                    arg=k)
        # intervening calls that touch the approved target
        targets = {_resolve(v, a.cwd) for v in pa.values()}
        for o in calls:
            if a.index < o.index < c.index and o is not c:
                text = json.dumps(o.args)
                opaths = {_resolve(v, o.cwd) for v in _paths_of(o.args).values()}
                hit = targets & opaths
                if hit and (REBIND_TOOLS.search(text) or re.search(r"write|move|rename|link", o.tool, re.I)):
                    add("TOCTOU_WRITE", "high", c, a,
                        f"event #{o.index} ({o.tool}) modified approved target {sorted(hit)} between approval and execution",
                        intervening=o.index)
        # reuse
        if a.single_use and len(a.uses) > 1 and a.uses[0] != c.index:
            add("APPROVAL_REUSE", "high", c, a,
                f"single-use approval already consumed by event #{a.uses[0]}", uses=a.uses)
        # staleness
        if max_age is not None and a.ts is not None and c.ts is not None and c.ts - a.ts > max_age:
            add("STALE_APPROVAL", "medium", c, a,
                f"executed {int(c.ts - a.ts)}s after approval (limit {int(max_age)}s)")
        if c.inferred and findings and findings[-1].call_index == c.index:
            findings[-1].detail["binding"] = "inferred"
    return findings


def summarize(findings: list[Finding], calls: list[Call], approvals: list[Approval]) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        counts[f.severity] += 1
    return {"calls": len(calls), "approvals": len(approvals),
            "bound": sum(1 for c in calls if c.bound), "counts": counts,
            "findings": [asdict(f) for f in findings]}
