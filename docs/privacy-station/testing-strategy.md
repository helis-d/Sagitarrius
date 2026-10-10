# Testing Strategy — sagitarrius-broker

## Test layers

### 1. Unit tests (in-module)

Each broker module carries `#[cfg(test)]` tests for pure logic:

- `policy.rs`: grant matching, deny reasons, validation
- `request.rs`: schema parsing, timestamp window, URL validation
- `http.rs`: target validation, IP filtering, agent config
- `respond.rs`: allowlist filter, envelope shape
- `audit.rs`: event shape, redaction

### 2. Integration tests (`tests/broker.rs`)

23 tests covering 17 security scenarios:

| # | Scenario | Test |
|---|----------|------|
| 1 | Valid grant authorizes | `s01_valid_grant_authorizes` |
| 2 | Credential mismatch denied | `s02_credential_mismatch_denied` |
| 3 | Method not in grant denied | `s03_method_not_in_grant_denied` |
| 4 | Host not in grant denied | `s04_host_not_in_grant_denied` |
| 5 | Path not in grant denied | `s05_path_not_in_grant_denied` |
| 6 | Fake headers rejected | `s06_request_with_headers_rejected` |
| 7 | Body rules enforced | `s07_body_in_get_rejected`, `s07_body_in_post_denied_when_grant_disallows` |
| 8 | Corrupt policy fails closed | `s08_corrupt_policy_fails_closed` |
| 9 | Malformed request rejected | `s09_malformed_request_rejected` |
| 10 | Loopback requires opt-in | `s10_loopback_requires_opt_in` |
| 11 | Private addresses denied | `s11_private_addresses_denied` |
| 12 | DNS rebinding denied | `s12_dns_rebinding_filtered_ip_denied` |
| 13 | Redirect denied | `s13_redirect_denied` |
| 14 | Proxy env ignored | `s14_proxy_env_ignored` |
| 15 | Sensitive fields filtered | `s15_sensitive_fields_filtered` |
| 16 | Oversized/malformed response | `s16_oversized_response_enforced`, `s16_malformed_json_response_rejected` |
| 17 | Credential never in outputs | `s17_credential_never_in_outputs` |

### 3. Property tests (future)

- Policy matching: for any (grant, request) pair, authorize returns
  Ok iff all fields match.
- Response filter: for any JSON object and allowlist, output contains
  only allowed keys.

### 4. End-to-end tests (future)

- Spin up a local HTTPS server with a self-signed cert.
- Create a real vault with a test credential.
- Run `sagitarrius-broker call` and verify the server received the
  correct Authorization header and the agent received only allowlisted
  fields.

## Running tests

```sh
# All tests (including broker)
cargo test --locked

# Broker tests only
cargo test --features broker-http --test broker

# With clippy
cargo clippy --locked --all-targets --all-features -- -D warnings
```

## Coverage goals

- 100% of deny paths in `policy::authorize`
- 100% of `TargetDeny` variants in `http::validate_target`
- All `respond::filter_response` branches
- All `audit::append` error paths
