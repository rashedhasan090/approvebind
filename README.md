# approvebind

**Check that what an AI agent executed is exactly what a human or guard approved.**

Agent frameworks ask for approval before risky tool calls. The person (or guard model) approves a
specific call, and then the agent runs *something*. Those two things are usually logged separately
and nobody checks that they are the same. `approvebind` binds every executed tool call in a trace to
the approval it relied on and reports every way the execution drifted from the approval.

It is offline, has no dependencies (Python stdlib only), and works on plain JSONL traces.

## What's novel

Most agent safety tooling asks *was this call approved?* `approvebind` asks *was the approved call
the one that actually ran, against the same target, once, and soon after?* It treats approval as a
binding between a decision and an action, and checks for the classic ways that binding breaks:

| Code | Severity | What it means |
|---|---|---|
| `TOOL_SWAP` | critical | The approval was for one tool and a different tool ran under it. |
| `SCOPE_ESCALATION` | critical | The executed shell command added escalating flags (`-rf`, `--force`, `--hard`, `sudo`, ...) or chained commands (`&&`, `;`, `|`) that the approver never saw. |
| `ARG_DRIFT` | high | Arguments differ from the approved ones (nested keys are compared individually). |
| `TARGET_REBIND` | high | The same relative path was approved in one working directory and executed in another, so it hits a different file. |
| `TOCTOU_WRITE` | high | Between approval and execution, another call linked, moved, or rewrote the approved target (time-of-check to time-of-use). |
| `APPROVAL_REUSE` | high | A single-use approval was consumed by more than one call. |
| `DANGLING_APPROVAL` | high | A call cites an approval id that never appears in the trace. |
| `STALE_APPROVAL` | medium | The call ran longer after the approval than `--max-age` allows. |
| `UNPINNED_TARGET` | medium | The approved target used `$VARS`, `~`, globs, or command substitution, so the approver could not see what it would resolve to. |
| `UNBOUND_CALL` | medium | A sensitive tool ran with no approval at all while other calls in the same trace were gated. |

When a call doesn't cite an approval id, `approvebind` infers the binding to the most recent unused
approval for the same tool and marks the finding `binding: inferred`.

## Install

```bash
pip install git+https://github.com/rashedhasan090/approvebind
# or, from a clone
pip install .
```

You can also run it without installing: `python -m approvebind trace.jsonl`.

## Run

```bash
approvebind examples/trace.jsonl                 # text report, exit 1 on high or worse
approvebind --format md examples/trace.jsonl     # markdown table for PR comments
approvebind --format json --fail-on none t.jsonl # machine-readable
approvebind --max-age 60 --fail-on medium t.jsonl
```

Options: `--format text|json|md`, `--max-age SECONDS` (default 300, `0` disables),
`--sensitive REGEX` (tool names that need approval), `--fail-on low|medium|high|critical|none`.

## Trace format

One JSON object per line (a JSON array also works). Event types:

```jsonl
{"type":"cwd","path":"/home/dev/project"}
{"type":"approval","id":"a1","by":"user","ts":1000,"scope":"once","call":{"tool":"shell","args":{"command":"rm build/tmp.log"}}}
{"type":"tool_call","tool":"shell","approval":"a1","ts":1004,"args":{"command":"rm -rf build"}}
```

* `approval` events carry the approved `call` (`tool` or `name`, plus `args` or `arguments`), an
  optional `id`, `ts` (epoch seconds or ISO 8601), `cwd`, and `scope` (`once` by default; anything
  else such as `session` allows reuse).
* `tool_call` (also `call`, `function_call`, `tool_use`, `exec`) carries `tool`/`name` or an
  OpenAI-style `function`, `args`/`arguments`/`input` (object or JSON string), optional `approval`
  id, `ts`, and `cwd`.
* `cwd`/`chdir` events update the working directory used to resolve relative paths.

Event numbers in reports are 0-based line positions in the trace.

## Demo

```text
$ approvebind examples/trace.jsonl
approvebind: examples/trace.jsonl
  8 calls, 5 approvals, 6 calls bound to an approval
  [CRITICAL] SCOPE_ESCALATION event#2 shell approval=a1
      executed command adds escalating flags ['-rf'] that were not in the approved command
      approved: rm build/tmp.log
      executed: rm -rf build
  [MEDIUM] UNBOUND_CALL event#4 shell
      sensitive call ran with no approval bound to it while other calls were approved
  [HIGH] TOCTOU_WRITE event#5 write_file approval=a2
      event #4 (shell) modified approved target ['/home/dev/project/config.yaml'] between approval and execution
  [HIGH] ARG_DRIFT event#8 send_email approval=a3
      1 argument(s) differ from what was approved: to
  [HIGH] APPROVAL_REUSE event#8 send_email approval=a3
      single-use approval already consumed by event #7
  [MEDIUM] STALE_APPROVAL event#8 send_email approval=a3
      executed 480s after approval (limit 300s)
  [HIGH] TARGET_REBIND event#11 delete_file approval=a4
      relative path 'cache/old.db' was approved in /home/dev/project but executed in /home/dev
  [CRITICAL] TOOL_SWAP event#13 http_request approval=a5
      approved tool 'read_file' but executed 'http_request'
      approved: read_file
      executed: http_request
  [MEDIUM] UNBOUND_CALL event#14 deploy
      sensitive call ran with no approval bound to it while other calls were approved
  2 critical, 4 high, 3 medium, 0 low
```

`examples/clean.jsonl` shows a trace that passes.

## Tests

```bash
python -m unittest -v
```

## Limits

This is a static check on logs, not a runtime enforcer. Path extraction from shell commands is
heuristic, and it cannot see symlinks that were created outside the trace. Use it in CI over recorded
agent sessions, or as a post-hoc audit after an incident.

## License

MIT
