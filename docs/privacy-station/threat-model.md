# Threat Model — sagitarrius-broker

## Assets

- Vault master password (operator-only, never stored)
- Credential values (secrets in the vault)
- Agent-visible output (must not contain secrets)
- Audit log (must not contain secrets)

## Threats

### T1: Agent exfiltrates credential
**Mitigation**: Credential value never leaves the broker process. The
broker attaches it as an HTTP header internally; it is zeroized after use.

### T2: Agent requests unauthorized destination
**Mitigation**: Default-deny policy. Every request must match a grant on
credential, method, host, and path. Unknown fields rejected.

### T3: SSRF — agent targets internal services
**Mitigation**: DNS resolution + IP filter before connect. Private,
link-local, loopback (without opt-in), and metadata addresses denied.

### T4: DNS rebinding
**Mitigation**: Resolve-then-check before connecting. Race window
documented as not guaranteed.

### T5: Redirect to internal service
**Mitigation**: `max_redirects(0)`. Redirects are denied.

### T6: Proxy exfiltration
**Mitigation**: `proxy(None)` explicitly. Proxy env vars ignored.

### T7: Response contains secrets
**Mitigation**: Allowlist filter. Only explicitly allowed top-level fields
are returned. Unknown fields dropped.

### T8: Audit log contains secrets
**Mitigation**: Redacted JSONL. No bodies, headers, passwords, or
credential values. Credential NAME only.

### T9: Agent floods audit log
**Mitigation**: Audit events are append-only with a size cap. Denied
requests are audited too (they are the interesting ones).

### T10: Timestamp replay
**Mitigation**: ±500 second window. Stale requests rejected.

### T11: Credential in error messages
**Mitigation**: Static error strings only. Upstream errors are redacted
through a static mapping.

## Out of scope

- Physical access to the operator machine
- Compromised vault file at rest (mitigated by existing encryption)
- Side-channel timing attacks on credential comparison
