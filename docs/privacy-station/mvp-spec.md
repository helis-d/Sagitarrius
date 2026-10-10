# MVP Spec — sagitarrius-broker

## Overview

`sagitarrius-broker` is a credential broker binary. It lets AI agents and
automation perform authorized API operations using credentials stored in a
Sagitarrius vault without ever receiving those credentials.

## Binary separation

- `sagitarrius` (main CLI): network-free by construction. No `ureq`, `url`,
  `hyper`, or `reqwest` in its dependency tree.
- `sagitarrius-broker`: the only binary that opens sockets. Built with
  `--features broker-http`.

## Usage

```sh
printf '%s' "$MASTER_PW" | sagitarrius-broker call \
  --policy policy.json --request req.json
```

- **stdin**: master password (one line)
- **stdout**: one JSON envelope (`{"ok":true,"result":{...}}` or `{"ok":false,"error":"..."}`)
- **stderr**: diagnostics
- **exit 0**: call executed
- **exit 2**: denied or failed

## Policy format (JSON)

The implementation uses JSON. An earlier decision record mentioned TOML;
that format was not implemented. See `DECISIONS.md` for the unresolved
format-conformance question.

```json
{
  "version": 1,
  "grants": [
    {
      "id": "g1",
      "credential": "MY_API_KEY",
      "credential_use": "bearer",
      "methods": ["GET"],
      "hosts": ["api.example.com:443"],
      "paths": ["/v1/"],
      "headers": {"X-Api-Version": "2024-01-01"},
      "allow_body": false,
      "max_body_bytes": 0,
      "max_response_bytes": 65536,
      "timeout_secs": 10,
      "allow_response_fields": [
        {"path": "status", "kind": "string", "max_len": 64},
        {"path": "data.id", "kind": "integer"}
      ],
      "loopback": false
    }
  ]
}
```

- `methods` supports only `GET` and `POST`.
- `hosts` are exact lowercase `host:port` values.
- `paths` are segment scopes: `/v1` covers `/v1` and `/v1/status`, but not
  `/v10/status`.
- Policy headers must be visible ASCII and must not override broker- or
  HTTP-controlled fields such as `Authorization`, `Host`, `Content-Length`,
  `Transfer-Encoding`, `Connection`, proxy headers, or upgrade headers.
- Request bodies are disabled: `allow_body` must be `false` and
  `max_body_bytes` must be `0`.
- Response disclosure is a constrained schema, not a list of top-level
  names. Objects cannot be selected wholesale; every nested value needs an
  explicit leaf path, type, and applicable string/array bound.
- Unknown fields are rejected at load.

## Request format (JSON)

```json
{
  "grant": "g1",
  "credential": "MY_API_KEY",
  "method": "GET",
  "url": "https://api.example.com/v1/status",
  "timestamp": 1735689600,
  "nonce": "01J0000000000000000000000"
}
```

- `timestamp` must be within ±300 seconds of current time. There is no
  cross-call replay cache.
- `url` must use lowercase `http` or `https`.
- URLs must not contain query strings, fragments, embedded credentials,
  backslashes, percent-encoded bytes, or dot segments.
- No `headers` or `body` field is allowed. `body` is an unknown field and
  is rejected.

## Security properties

| Property | Mechanism |
|----------|-----------|
| Default deny | Every field must match; no wildcards |
| SSRF prevention | DNS answer is fully validated, then pinned for the connection |
| No redirects | `max_redirects(0)`; 3xx responses are denied, not followed |
| No proxy | `proxy(None)` explicitly |
| Response minimization | Constrained response schema; nested objects are never copied wholesale |
| Audit trail | Intent before network, completion afterward; redacted JSONL |
| Credential isolation | Value never leaves broker process |
| Fail-closed | Missing intent audit prevents the request; completion-audit failure reports a possible side effect |

## Policy trust boundary

`--policy` is trusted-operator input, not agent input. The broker process
cannot distinguish an operator shell from an agent process running as the
same user. Therefore, direct invocation by an untrusted agent is
unsupported: a trusted operator or launcher must select the policy file and
supply the master password. Permitting an untrusted agent to choose
`--policy` would let it substitute a permissive policy. The supported
deployment options are recorded in
`docs/privacy-station/policy-trust-boundary.md`.

## Audit format

```json
{"ts":1735689600,"grant":"g1","credential":"MY_API_KEY","method":"GET","host":"api.example.com:443","path":"/v1/status","outcome":"ok","response_bytes":42}
```

Stored at `broker-audit.jsonl` in the vault directory.
