# Sagitarrius Privacy Station — broker architecture (PROPOSAL, not implemented)

Status: **proposed, awaiting human approval** (see "Decision required" at
the end). No code in this document exists yet. Nothing here changes the
current CLI, vault format, or the no-network invariant of `sagitarrius`.

## Problem (one sentence)

An AI agent that needs to *use* a credential today must *receive* the
credential (env var, prompt, tool result) — after which no technical
control can stop it from leaking it (OWASP LLM06:2025, excessive agency).

## MVP workflow (the only flow v1 supports)

```bash
sagitarrius add TEST_WEATHER_KEY            # existing CLI, unchanged
cat > policy.toml <<'EOF'                   # operator-written, default-deny
[[grant]]
credential = "TEST_WEATHER_KEY"
methods    = ["GET"]
hosts      = ["127.0.0.1:18080"]
paths      = ["/v1/echo"]
max_response_bytes = 65536
allow_response_fields = ["status", "echo"]
EOF
printf '%s' "$MASTER_PW" | sagitarrius-broker call \
  --policy policy.toml --request req.json   # req names credential+op only
# -> {"status":"ok","echo":"..."}  (redacted, schema-checked)
# audit event appended to audit.jsonl (no bodies, no secrets)
```

The agent prepares `req.json` and reads the redacted result. It never
holds the password, the credential, or the VMK.

## Network-boundary decision (Options A/B/C)

**Recommended: Option A — separate `sagitarrius-broker` binary.**

| Criterion | A: separate broker binary (recommended) | B: local IPC + separate net executor | C: network inside `sagitarrius` |
|---|---|---|---|
| Security boundary | OS process boundary; main CLI stays provably network-free (auditable: no net deps in its tree) | Stronger isolation, but 2 new trust hops (IPC auth + executor auth) | Weakest: one compromised/flag-confused path exposes vault+network together |
| Master-key handling | Broker reuses `vault`/`envelope` modules in-process; password via `--password-stdin`-style pipe, zeroized; no key crosses IPC | VMK/KEK must cross IPC or be re-derived per side — strictly worse | Same as A, but shares fate with every CLI flag parser bug |
| IPC auth | None needed (single process; caller auth = master password) | Needs a local auth protocol (token/socket perms) — new attack surface | N/A |
| Secret exposure | Credential lives only in broker heap during the call | Credential crosses IPC (needs sealed channel) | Same as A |
| Network perms | Only broker binary ever opens sockets; firewall/packaging can scope it | Finest scoping, at 2× the code | Whole CLI gains sockets |
| Testing | Deterministic: mock TCP server, assert redaction | 3 components to harness | Same as A |
| Distribution | Second `[[bin]]`, same crate tree, same release archives | Extra service install/supervision per OS | No new artifact |
| Cross-platform cost | One blocking HTTP client everywhere | Per-OS IPC + service management | One client, but invariant lost |
| CLI compat | 100% — main binary untouched | 100% | Risks flag/env confusion |

Rejected: B (isolation gain does not pay for two new auth boundaries in an
MVP), C (breaks the documented no-network invariant for convenience —
explicitly against AGENTS.md).

Consequences of A that need approval: a new `[[bin]]`, new deps for the
broker only (`ureq` + `url`, both pure-Rust, rustls TLS), and new
(non-vault) file formats (policy TOML, request/response JSON, audit JSONL).
**No vault-format change. No new dep in the main binary's tree.**

## Request authentication (no model promises involved)

- The caller proves local-operator status per call with the **master
  password via stdin pipe** (same mechanism as `--password-stdin`).
  No password → no unlock → deny. There is no standing broker token in v1
  (fewer secrets to manage; documented limitation: every call needs the
  operator's password, i.e. human-approved or harness-held execution).
- Policy file is operator-written TOML outside the vault. A request names
  `(credential, method, url)`; the broker matches it **literally** against
  grants. Anything from the agent is untrusted data, never policy.
- Agent identity is NOT established in v1 (single local operator assumed);
  multi-tenant/agent identity is explicitly out of scope.

## Destination validation

- Grant lists exact `host:port` + path prefixes. After DNS resolution,
  **every** resolved A/AAAA must either be allowlisted-loopback (grant sets
  `loopback = true`, test-only, warned) or pass the SSRF filter, else deny.
- Always denied: 169.254.169.254/32 + 169.254.0.0/16 (cloud metadata),
  10/8, 172.16/12, 192.168/16, 224/4+, ::/128, ::1/128 and fe80::/10
  (unless loopback-allowed), 0.0.0.0/8, unresolvable names.
- No redirects in v1 (any 3xx → deny; documented, tested).
- `HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY` are stripped for broker requests.
- Timeouts: connect 10 s, total 30 s. TLS verification mandatory, no
  opt-out flag. Response cap: grant `max_response_bytes` (default 64 KiB).

## Response minimization

Per-grant `allow_response_fields`: JSON responses are filtered to exactly
those top-level fields; anything else (wrong shape, oversize, non-JSON
when JSON expected) → deny + redacted error. Errors never include request
or response bodies. Tests assert the raw credential appears in **no**
agent-visible output (stdout result, audit log, error strings).

## Failure behavior (all default-deny)

Auth fail, policy miss/ambiguity, vault locked/missing, unresolvable or
forbidden destination, timeout, malformed/oversized response, audit-write
failure → deny, non-zero exit, redacted error. Audit failure never
disables authorization (deny first, log best-effort).

## Replay/timeout/partial failure

- Requests carry `timestamp`; outside ±5 min → deny. No cross-call replay
  cache in v1 (single-shot process): replay inside the window re-executes,
  which is safe only for the idempotent test integration — documented.
- Timeouts kill the request; no partial results are returned.
- Crashes leave no plaintext artifacts: credential lives in zeroized
  buffers only; audit entries contain no bodies (tested by scanning the
  audit file for the credential after every test).

## Memory/process safety

Same rules as the main binary (zeroize key material and secrets,
`--password-stdin` over env, strip password env from any child, no secret
in errors/logs), plus: the broker never `exec`s children in v1.

## Audit

Append-only JSONL next to the vault dir: timestamp, grant id, credential
*name*, method, host, path, outcome, response byte count, redacted error.
Never: credential values, request/response bodies, passwords, VMK.

## Module sketch (fits current `src/`)

- `src/broker/main.rs` — new `[[bin]]`, stdio JSON in/out, exit codes.
- `src/broker/policy.rs` — TOML grants, default-deny matcher (pure, unit-tested).
- `src/broker/request.rs` — strict request schema validation.
- `src/broker/http.rs` — allowlisted HTTPS client wrapper (timeouts, no-redirect, caps).
- `src/broker/respond.rs` — schema filter + redaction.
- `src/broker/audit.rs` — redacted JSONL writer.
- Reuse untouched: `vault`, `vault_v3`, `envelope`, `crypto`, `input`, `state`, `storage`, `error`.

## What MVP explicitly does NOT do

VPN/browser/email/cloud-sync/UI/teams/MCP-server/OAuth flows/multi-agent/
general classifier (per scope §8). MCP note: the MCP spec (2026-07-28)
recommends OAuth 2.1 for HTTP transports and env-retrieval for STDIO —
our local stdio-JSON + vault-held policy is the compatible local
equivalent; a future MCP *server* adapter would sit in front of the broker
and reuse its authorization, not bypass it.

## Decision required (single escalation, recommended defaults)

1. Approve Option A + this MVP scope? (Recommended: yes.)
2. Approve new deps `ureq` + `url` for the broker binary only (main CLI
   tree unchanged)? (Recommended: yes — minimal blocking client + URL
   parser; alternatives `hyper`/`reqwest` rejected as heavier async stacks.)
3. Approve new surfaces: `sagitarrius-broker` binary, `--policy` TOML,
   request/response JSON, audit JSONL? (Recommended: yes as specified.)
4. Confirm: no vault-format change, no main-CLI flag changes, no rename —
   nothing further needed from you on those.
