# Product Vision — Sagitarrius Privacy Station

## Problem

AI agents and automation need to call APIs that require credentials
(GitHub tokens, cloud API keys, database passwords). Today, operators
either:

1. Hand the raw credential to the agent — the agent can now exfiltrate it.
2. Build a custom proxy per API — high maintenance, inconsistent security.

## Vision

Sagitarrius Privacy Station is a **credential broker** between agents and
APIs. The agent asks the broker to make a call; the broker checks policy,
attaches the credential, executes the call, and returns only an allowlisted
response. The agent never sees the credential.

## Principles

1. **Credentials never leave the broker** — not to agents, not to logs,
   not to audit events.
2. **Default deny** — every destination, method, and field must be
   explicitly allowed.
3. **Minimal disclosure** — responses are filtered to an allowlist before
   reaching the agent.
4. **Auditable** — every call leaves a redacted trail.
5. **Operator-controlled** — policies are human-written files, not
   agent-influenced state.

## Target users

- Developers running AI coding assistants (Claude Code, Cursor, Copilot)
  that need API access.
- DevOps teams automating CI/CD with secrets in a local vault.
- Security teams that want a single chokepoint for agent egress.

## Non-goals (v1)

- OAuth token exchange or refresh
- Credential rotation
- Multi-tenant vaults
- Windows service / daemon mode
