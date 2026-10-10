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
      "allow_response_fields": ["status", "data"],
      "loopback": false
    }
  ]
}
```

All fields except `headers`, `allow_body`, `max_body_bytes`,
`max_response_bytes`, `timeout_secs`, and `loopback` are required.
Unknown fields are rejected at load.

## Request format (JSON)

```json
{
  "grant": "g1",
  "credential": "MY_API_KEY",
  "method": "GET",
  "url": "https://api.example.com/v1/status",
  "ts": 1735689600
}
```

- `ts` must be within ±500 seconds of current time
- `url` must be `https://` (or `http://` for loopback grants only)
- No `headers` field allowed (headers come from policy)
- `body` only allowed for POST when `allow_body: true`

## Security properties

| Property | Mechanism |
|----------|-----------|
| Default deny | Every field must match; no wildcards |
| SSRF prevention | DNS resolution + IP filter before connect |
| No redirects | `max_redirects(0)` |
| No proxy | `proxy(None)` explicitly |
| Response minimization | Allowlist filter; unknown fields dropped |
| Audit trail | Redacted JSONL; no bodies, secrets, or headers |
| Credential isolation | Value never leaves broker process |
| Fail-closed | Audit-write failure denies operation |

## Audit format

```json
{"ts":1735689600,"grant":"g1","credential":"MY_API_KEY","method":"GET","host":"api.example.com:443","path":"/v1/status","outcome":"ok","response_bytes":42}
```

Stored at `broker-audit.jsonl` in the vault directory.
