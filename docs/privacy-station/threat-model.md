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
**Mitigation**: Every DNS answer is validated, including IPv4-mapped IPv6
and transition addresses. Private, link-local, special-use, multicast,
unspecified, and metadata addresses are denied. Loopback requires an
explicit grant opt-in, and mixed loopback/public answers are rejected.

### T4: DNS rebinding
**Mitigation**: Validation returns the accepted socket addresses and the
request uses a pinned resolver containing only those addresses. The HTTP
client does not perform a second DNS lookup for the approved hostname.
Hostname-based TLS verification and SNI still use the original hostname.
A hostname answer with too many addresses fails closed.

### T5: Redirect to internal service
**Mitigation**: `max_redirects(0)`. A 3xx response is classified as
`redirect denied`; it is never followed and its body is never returned.

### T6: Proxy exfiltration
**Mitigation**: `proxy(None)` explicitly. Proxy env vars ignored.

### T7: Response contains secrets
**Mitigation**: Constrained response schema. Only explicitly allowed leaf
paths with explicitly allowed scalar types and bounds are returned. Nested
objects are rebuilt leaf-by-leaf and are never copied wholesale. Unknown
fields are dropped. An allowed string field can still disclose whatever the
upstream server puts there; the schema does not claim to detect arbitrary
secrets by string comparison.

### T8: Audit log contains secrets
**Mitigation**: Redacted JSONL. No bodies, headers, passwords, or
credential values. Credential NAME only. Metadata fields and total log size
are bounded.

### T9: Agent floods audit log
**Mitigation**: Audit events and the total audit file are append-only with
size caps. Authorization denials are audited where a bounded event can be
written.

### T10: Timestamp replay
**Mitigation**: ±500 second window. Stale requests rejected.

### T11: Credential in error messages
**Mitigation**: Static error strings only. Upstream errors are redacted
through a static mapping.

### T12: Untrusted agent substitutes its own policy
**Status**: Not mitigated inside the broker binary. `--policy` is trusted
operator/launcher input. Direct invocation by an untrusted agent is
unsupported because the broker cannot distinguish same-user operator and
agent processes. See `policy-trust-boundary.md`.

## Out of scope

- Physical access to the operator machine
- Compromised vault file at rest (mitigated by existing encryption)
- Side-channel timing attacks on credential comparison
- Buffers owned by the HTTP/TLS libraries, which are not guaranteed to be
  zeroized
- In-window replay of an authorized request (only timestamp freshness is
  enforced)
