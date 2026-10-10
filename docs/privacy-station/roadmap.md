# Roadmap — Sagitarrius Privacy Station

## PS-01: MVP broker (current)

- [x] Separate `sagitarrius-broker` binary
- [x] Default-deny policy engine
- [x] Vault integration (unlock, credential resolution)
- [x] SSRF-filtered HTTP layer
- [x] Allowlist response filter
- [x] Redacted audit events
- [x] 17 security scenarios tested
- [ ] End-to-end tests with local HTTPS server
- [ ] Commit and merge to main

## PS-02: Operator experience

- `sagitarrius broker init` — generate a starter policy file
- `sagitarrius broker audit` — pretty-print audit log
- `sagitarrius broker test --policy p.json` — dry-run policy validation

## PS-03: Policy ergonomics

- YAML policy support (via `serde_yaml`)
- Policy inheritance / includes
- Environment-specific policies (dev/staging/prod)

## PS-04: Protocol hardening

- Request signing (HMAC over policy hash + request hash)
- Replay cache (nonce-based, cross-call)
- Mutual TLS for broker-to-upstream

## PS-05: Agent integration

- MCP (Model Context Protocol) server mode
- JSON-RPC over stdio
- Agent-friendly error codes

## PS-06: Distribution

- cargo-dist packages for Linux/macOS/Windows
- Homebrew/scoop/winget formulas
- Signed releases with checksums
