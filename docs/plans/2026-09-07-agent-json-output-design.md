# Agent-friendly `net`: JSON output and `net ai`

**Date**: 2026-09-07
**Status**: Approved

## Goal

Let shell-capable AI agents (Claude Code, Codex, Aider, ...) drive `net`
reliably: predictable machine-readable output, a documented exit-code
contract, no interactive prompts, and one place to learn the tool.

Out of scope for now: an MCP server. It can be layered on the same
structured output later without changing this design.

## Decisions

| Decision | Choice | Rationale |
|---|---|---|
| Consumer | Shell-capable agents first | They already run commands; no new dependency needed |
| Scope | Every command, read and write | Agents diagnose *and* act; writes report what changed |
| Discovery | `net ai` subcommand + `docs/AI.md` | Works on a machine with only the binary; doc generated from the same source |
| Envelope | Uniform `{ok, command, data|error}` | One parser for every command; errors are structured |
| Privilege | `--json` implies non-interactive (`sudo -n`) | A password prompt hangs an agent; exit 3 with a `privilege` error instead |
| Text output | Byte-identical when `--json` is absent | Proven by test |

## JSON contract

Persistent flag `--json` on the root command. When set, stdout carries
exactly one JSON document. Progress lines, banners and summaries are
suppressed. Logs stay on stderr, so `--json --debug` still works.

```json
{"ok": true,  "command": "status",  "data": { ... }}
{"ok": false, "command": "connect", "error": {"code": "not_found", "message": "..."}}
```

`data` is built from the `pkg/types` result structs (`Connection`,
`VPNStatus`, `HotspotStatus`, `WiFiNetwork`, `NetworkConfig`), which gain
`json` tags. Secrets in config output are masked exactly as in text mode.

Mutating commands return what changed (interface, new values) plus the
same connection block `status` returns, so an agent can verify without a
second call.

### Exit codes

| Code | Meaning | `error.code` values |
|---|---|---|
| 0 | ok | |
| 1 | operation failed | `failed`, `not_found`, `timeout`, `portal`, `tool_missing` |
| 2 | usage error | `usage` |
| 3 | needs privileges | `privilege` |
| 130 | interrupted | |

## `net ai`

Prints a plain-text guide; needs neither root nor a config file.
Generated from the cobra command tree plus a hand-written block per
command so it cannot drift from real flags. Contents:

1. Five-line rules: use `--json`, parse the envelope, check `ok`, exit
   codes, privilege requirement.
2. Suggested workflow: `status` first, `scan` before `connect`, `status`
   after any change, `stop` to undo.
3. Per command: synopsis, what it changes on the system, one example
   `--json` response.
4. Safety notes: `connect` can drop the current link, `dns` rewrites
   `/etc/resolv.conf`, `mac` cycles the interface, hotspot/dhcp need
   extra tools.

`docs/AI.md` is written by `go generate`; a test asserts it matches.

## Implementation shape

- `cmd/net/output.go`: envelope type, `emit`/`emitError`, `JSON bool` on
  `App`. Existing `printf`/`progress`/`println` helpers become no-ops in
  JSON mode so the ~35 print sites need no edits.
- Each `Run*` in `app.go` builds a result struct, then prints text or
  emits JSON.
- `main.go`: register `--json`, use `sudo -n` when set, map error codes
  to exit codes in one place.
- Tests: golden-file table tests per command with mocked managers; a
  no-op test asserting text output is byte-identical with the flag off;
  an integration test through the real cobra entry point.

## Stages

1. Envelope, exit codes, `--json` on read commands (`status`, `list`,
   `scan`, `show`, `vpn` status). Byte-identical text test.
2. `--json` on mutating commands (`connect`, `stop`, `vpn`, `dns`, `mac`,
   `hotspot`, `dhcp`).
3. `net ai` and generated `docs/AI.md`.
4. Non-interactive privilege handling under `--json`.
