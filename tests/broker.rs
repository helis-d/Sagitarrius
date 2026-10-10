//! Integration tests for the broker: 17 security scenarios.
//!
//! Tests are organized by scenario number from the PS-01 spec.
//! Pure functions are tested directly; HTTP behavior is tested against a
//! local TCP server (loopback grants allow HTTP in tests).

#![cfg(feature = "broker-http")]

use assert_cmd::Command;
use sagitarrius::broker::{audit, http, policy, request, respond};
use serde_json::json;
use std::fs;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
#[cfg(unix)]
use std::process::Stdio;
#[cfg(unix)]
use std::sync::mpsc;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Mutex,
};
use std::thread::{self, JoinHandle};

const TEST_CREDENTIAL: &str = "TESTKEY";

fn example_policy_json() -> String {
    serde_json::json!({
        "version": 1,
        "grants": [{
            "id": "g1",
            "credential": "TESTKEY",
            "credential_use": "bearer",
            "hosts": ["api.example.com:443", "127.0.0.1:9443"],
            "paths": ["/v1/"],
            "methods": ["GET"],
            "allow_body": false,
            "max_body_bytes": 0,
            "max_response_bytes": 65536,
            "timeout_secs": 10,
            "allow_response_fields": [
                {"path": "status", "kind": "string", "max_len": 64},
                {"path": "data.id", "kind": "integer"}
            ],
            "headers": {"X-Api-Version": "2024-01-01"},
            "loopback": true
        }]
    })
    .to_string()
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn valid_request(port: u16, method: &str, path: &str, nonce: &str) -> String {
    json!({
        "grant": "g1",
        "credential": TEST_CREDENTIAL,
        "method": method,
        "url": format!("http://127.0.0.1:{port}{path}"),
        "timestamp": now_secs(),
        "nonce": nonce
    })
    .to_string()
}

const BROKER_TEST_PASSWORD: &str = "broker-test-operator-password-123";
const BROKER_TEST_CREDENTIAL_VALUE: &str = "broker-test-bearer-value-456";

fn broker_test_vault() -> tempfile::TempDir {
    let dir = tempfile::TempDir::new().unwrap();
    Command::cargo_bin("sagitarrius")
        .unwrap()
        .env("SAGITARRIUS_VAULT_DIR", dir.path())
        .env("SAGITARRIUS_PASSWORD", BROKER_TEST_PASSWORD)
        .arg("init")
        .assert()
        .success();
    Command::cargo_bin("sagitarrius")
        .unwrap()
        .env("SAGITARRIUS_VAULT_DIR", dir.path())
        .env("SAGITARRIUS_PASSWORD", BROKER_TEST_PASSWORD)
        .args(["add", TEST_CREDENTIAL])
        .write_stdin(format!(
            "{BROKER_TEST_CREDENTIAL_VALUE}\n{BROKER_TEST_CREDENTIAL_VALUE}\n"
        ))
        .assert()
        .success();
    dir
}

fn broker_policy(port: u16, max_response_bytes: usize) -> serde_json::Value {
    json!({
        "version": 1,
        "grants": [{
            "id": "g1",
            "credential": TEST_CREDENTIAL,
            "credential_use": "bearer",
            "methods": ["GET"],
            "hosts": [format!("127.0.0.1:{port}")],
            "paths": ["/v1/"],
            "headers": {"X-Test": "broker"},
            "allow_body": false,
            "max_body_bytes": 0,
            "max_response_bytes": max_response_bytes,
            "timeout_secs": 5,
            "allow_response_fields": [
                {"path": "status", "kind": "string", "max_len": 64},
                {"path": "data.id", "kind": "integer"}
            ],
            "loopback": true
        }]
    })
}

fn broker_request(port: u16, path: &str) -> serde_json::Value {
    json!({
        "grant": "g1",
        "credential": TEST_CREDENTIAL,
        "method": "GET",
        "url": format!("http://127.0.0.1:{port}{path}"),
        "timestamp": now_secs(),
        "nonce": format!("broker-{path}")
    })
}

fn run_broker(
    vault_dir: &tempfile::TempDir,
    policy: &serde_json::Value,
    request: &serde_json::Value,
    extra_env: &[(&str, &str)],
) -> std::process::Output {
    let work = tempfile::TempDir::new().unwrap();
    let policy_path = work.path().join("policy.json");
    let request_path = work.path().join("request.json");
    fs::write(&policy_path, serde_json::to_string(policy).unwrap()).unwrap();
    fs::write(&request_path, serde_json::to_string(request).unwrap()).unwrap();
    let mut command = Command::cargo_bin("sagitarrius-broker").unwrap();
    command
        .env("SAGITARRIUS_VAULT_DIR", vault_dir.path())
        .env_remove("SAGITARRIUS_PASSWORD")
        .args([
            "call",
            "--policy",
            policy_path.to_str().unwrap(),
            "--request",
            request_path.to_str().unwrap(),
        ])
        .write_stdin(format!("{BROKER_TEST_PASSWORD}\n"));
    for (name, value) in extra_env {
        command.env(name, value);
    }
    command.output().unwrap()
}

fn stdout_json(output: &std::process::Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

fn audit_events(vault_dir: &tempfile::TempDir) -> Vec<serde_json::Value> {
    let raw = fs::read(vault_dir.path().join("broker-audit.jsonl")).unwrap();
    String::from_utf8(raw)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

// --- Scenario 1: Policy checks — valid grant matches ---

#[test]
fn s01_valid_grant_authorizes() {
    assert!(policy::load_policy(example_policy_json().as_bytes()).is_ok());
    let p: policy::Policy = serde_json::from_str(&example_policy_json()).unwrap();
    let g = policy::authorize(
        &p,
        "g1",
        TEST_CREDENTIAL,
        "GET",
        "api.example.com:443",
        "/v1/status",
    );
    assert!(g.is_ok());
    let g = g.unwrap();
    assert_eq!(g.id, "g1");
    assert!(g.hosts.contains(&"api.example.com:443".to_string()));
}

// --- Scenario 2: Credential mismatch denied ---

#[test]
fn s02_credential_mismatch_denied() {
    let p: policy::Policy = serde_json::from_str(&example_policy_json()).unwrap();
    let result = policy::authorize(
        &p,
        "g1",
        "OTHERKEY",
        "GET",
        "api.example.com:443",
        "/v1/status",
    );
    assert!(result.is_err());
}

#[test]
fn s02_unknown_grant_denied() {
    let p: policy::Policy = serde_json::from_str(&example_policy_json()).unwrap();
    let result = policy::authorize(
        &p,
        "nonexistent",
        TEST_CREDENTIAL,
        "GET",
        "api.example.com:443",
        "/v1/status",
    );
    assert!(result.is_err());
}

// --- Scenario 3: Method not in grant denied ---

#[test]
fn s03_method_not_in_grant_denied() {
    let p: policy::Policy = serde_json::from_str(&example_policy_json()).unwrap();
    let result = policy::authorize(
        &p,
        "g1",
        TEST_CREDENTIAL,
        "POST",
        "api.example.com:443",
        "/v1/status",
    );
    assert!(result.is_err());
}

// --- Scenario 4: Host not in grant denied ---

#[test]
fn s04_host_not_in_grant_denied() {
    let p: policy::Policy = serde_json::from_str(&example_policy_json()).unwrap();
    let result = policy::authorize(
        &p,
        "g1",
        TEST_CREDENTIAL,
        "GET",
        "evil.com:443",
        "/v1/status",
    );
    assert!(result.is_err());
}

// --- Scenario 5: Path not in grant denied ---

#[test]
fn s05_path_not_in_grant_denied() {
    let p: policy::Policy = serde_json::from_str(&example_policy_json()).unwrap();
    let result = policy::authorize(
        &p,
        "g1",
        TEST_CREDENTIAL,
        "GET",
        "api.example.com:443",
        "/admin/delete",
    );
    assert!(result.is_err());

    // A `/v1/` grant is a segment scope, not a string prefix: `/v10` is out
    // of scope while `/v1` itself and `/v1/status` are in scope.
    let denied = policy::authorize(
        &p,
        "g1",
        TEST_CREDENTIAL,
        "GET",
        "api.example.com:443",
        "/v10/status",
    );
    assert!(denied.is_err());
    for allowed in ["/v1", "/v1/status"] {
        let result = policy::authorize(
            &p,
            "g1",
            TEST_CREDENTIAL,
            "GET",
            "api.example.com:443",
            allowed,
        );
        assert!(result.is_ok(), "{allowed} should be in scope");
    }
}

// --- Scenario 6: Fake headers in request rejected ---

#[test]
fn s06_request_with_headers_rejected() {
    let mut req_json: serde_json::Value =
        serde_json::from_str(&valid_request(9443, "GET", "/v1/status", "s06")).unwrap();
    req_json["headers"] = serde_json::json!({"X-Evil": "injected"});
    let result = request::parse_request(req_json.to_string().as_bytes(), now_secs());
    assert!(result.is_err());
}

// --- Scenario 7: Body in GET rejected; body in POST allowed if grant allows ---

#[test]
fn s07_body_in_get_rejected() {
    let mut req_json: serde_json::Value =
        serde_json::from_str(&valid_request(9443, "GET", "/v1/status", "s07-get")).unwrap();
    req_json["body"] = serde_json::json!("should-not-be-here");
    let result = request::parse_request(req_json.to_string().as_bytes(), now_secs());
    assert!(result.is_err());
}

#[test]
fn s07_body_in_post_denied_when_grant_disallows() {
    let mut req_json: serde_json::Value =
        serde_json::from_str(&valid_request(9443, "POST", "/v1/status", "s07-post")).unwrap();
    req_json["body"] = serde_json::json!("{\"key\":\"value\"}");
    let result = request::parse_request(req_json.to_string().as_bytes(), now_secs());
    assert!(result.is_err());
}

// --- Scenario 8: Corrupt policy file fails closed ---

#[test]
fn s08_corrupt_policy_fails_closed() {
    let result = policy::load_policy(b"this is not json");
    assert!(result.is_err());

    let result = policy::load_policy(b"{\"version\":1,\"grants\":[{\"id\":\"g1\"");
    assert!(result.is_err());

    // Valid JSON but missing required fields
    let result = policy::load_policy(b"{\"version\":1,\"grants\":[{}]}");
    assert!(result.is_err());
}

// --- Scenario 9: Malformed request rejected before network ---

#[test]
fn s09_malformed_request_rejected() {
    // Not JSON
    let result = request::parse_request(b"not json", now_secs());
    assert!(result.is_err());

    // Missing required field
    let mut req_json: serde_json::Value =
        serde_json::from_str(&valid_request(9443, "GET", "/v1/status", "s09-missing")).unwrap();
    req_json.as_object_mut().unwrap().remove("nonce");
    let result = request::parse_request(req_json.to_string().as_bytes(), now_secs());
    assert!(result.is_err());

    // Invalid URL, embedded credentials, query, fragment, and unsupported
    // scheme. Every other field in these requests is valid.
    for url in [
        "not-a-url",
        "https://user:pass@127.0.0.1:9443/v1/status",
        "https://127.0.0.1:9443/v1/status?debug=1",
        "https://127.0.0.1:9443/v1/status#section",
        "gopher://127.0.0.1:9443/v1/status",
    ] {
        let mut req_json: serde_json::Value =
            serde_json::from_str(&valid_request(9443, "GET", "/v1/status", "s09")).unwrap();
        req_json["url"] = serde_json::Value::String(url.to_string());
        let result = request::parse_request(req_json.to_string().as_bytes(), now_secs());
        assert!(result.is_err(), "{url} must be rejected");
    }
}

#[test]
fn s09_plain_http_needs_loopback_opt_in() {
    let p: policy::Policy = serde_json::from_str(&example_policy_json()).unwrap();
    let mut no_loopback = p;
    no_loopback.grants[0].loopback = false;
    no_loopback.grants[0].hosts = vec!["127.0.0.1:18080".to_string()];
    assert_eq!(
        http::validate_target(
            "http://127.0.0.1:18080/v1/status",
            &no_loopback.grants[0].hosts,
            &no_loopback.grants[0].paths,
            false
        ),
        Err(http::TargetDeny::LoopbackNotAllowed)
    );
}

// --- Scenario 10: Loopback requires explicit opt-in ---

#[test]
fn s10_loopback_requires_opt_in() {
    // Policy without loopback: true
    let mut p: policy::Policy = serde_json::from_str(&example_policy_json()).unwrap();
    p.grants[0].loopback = false;

    let result = http::validate_target(
        "http://127.0.0.1:8080/test",
        &p.grants[0].hosts,
        &p.grants[0].paths,
        p.grants[0].loopback,
    );
    assert!(result.is_err());

    // With loopback: true, same URL passes structural checks
    let mut p2: policy::Policy = serde_json::from_str(&example_policy_json()).unwrap();
    p2.grants[0].loopback = true;
    p2.grants[0].hosts = vec!["127.0.0.1:8080".to_string()];
    p2.grants[0].paths = vec!["/".to_string()];
    let result2 = http::validate_target(
        "http://127.0.0.1:8080/test",
        &p2.grants[0].hosts,
        &p2.grants[0].paths,
        p2.grants[0].loopback,
    );
    assert!(result2.is_ok());
}

// --- Scenario 11: Private/link-local/metadata addresses denied ---

#[test]
fn s11_private_addresses_denied() {
    let hosts = vec!["api.example.com:443".to_string()];
    let paths = vec!["/v1/".to_string()];

    for url in [
        "http://10.0.0.1/test",
        "http://172.16.0.1/test",
        "http://192.168.1.1/test",
        "http://169.254.169.254/latest/meta-data",
        "http://[::1]/test",
        "http://[fe80::1]/test",
    ] {
        let result = http::validate_target(url, &hosts, &paths, false);
        assert!(result.is_err(), "expected {url} to be denied");
    }
}

struct CellDns {
    addrs: Mutex<Vec<SocketAddr>>,
}

impl http::Dns for CellDns {
    fn lookup(&self, _host: &str, _port: u16) -> Result<Vec<SocketAddr>, http::TargetDeny> {
        Ok(self.addrs.lock().unwrap().clone())
    }
}

struct MockHttp {
    addr: SocketAddr,
    hits: std::sync::Arc<AtomicUsize>,
    handle: Option<JoinHandle<()>>,
}

impl MockHttp {
    fn start(body: &str) -> Self {
        Self::start_with(
            "200 OK",
            &[("Content-Type", "application/json")],
            body.to_string(),
        )
    }

    fn start_with(status: &str, headers: &[(&str, &str)], body: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let hits = std::sync::Arc::new(AtomicUsize::new(0));
        let worker_hits = hits.clone();
        let status = status.to_string();
        let headers = headers
            .iter()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect::<Vec<_>>();
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0u8; 8192];
                let _ = stream.read(&mut request);
                worker_hits.fetch_add(1, Ordering::SeqCst);
                let mut response = format!("HTTP/1.1 {status}\r\n");
                for (name, value) in &headers {
                    response.push_str(&format!("{name}: {value}\r\n"));
                }
                response.push_str(&format!(
                    "Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                ));
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Self {
            addr,
            hits,
            handle: Some(handle),
        }
    }

    fn join(mut self) {
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }
}

#[cfg(unix)]
struct DelayedHttp {
    addr: SocketAddr,
    handle: Option<JoinHandle<()>>,
    request_received: mpsc::Receiver<()>,
    send_response: mpsc::Sender<()>,
}

#[cfg(unix)]
impl DelayedHttp {
    fn start(body: String) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let (request_tx, request_received) = mpsc::channel();
        let (send_response, response_rx) = mpsc::channel();
        let handle = thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                let mut request = [0u8; 8192];
                let _ = stream.read(&mut request);
                let _ = request_tx.send(());
                // Wait until the test has changed audit writability. This
                // proves the completion record, not the intent record, is
                // the one that fails.
                let _ = response_rx.recv();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
            }
        });
        Self {
            addr,
            handle: Some(handle),
            request_received,
            send_response,
        }
    }

    fn join(mut self) {
        if let Some(handle) = self.handle.take() {
            handle.join().unwrap();
        }
    }
}

// --- Scenario 12: DNS rebinding — filtered IP denied ---

#[test]
fn s12_dns_rebinding_filtered_ip_denied() {
    // Use a hostname that resolves to a filtered range (simulated by
    // testing the IP check directly with a mock hostname).
    // In practice we test the IP validation logic.
    let hosts = vec!["localhost:1".to_string()];
    let paths = vec!["/".to_string()];

    // localhost resolves to 127.0.0.1 which is loopback — denied without opt-in
    let result = http::validate_target("http://localhost:1/", &hosts, &paths, false);
    assert!(result.is_err());
}

#[test]
fn s12_pinned_connection_ignores_later_dns_rebinding() {
    const BODY: &str = r#"{"status":"ok"}"#;
    let approved = MockHttp::start(BODY);
    let decoy = TcpListener::bind("127.0.0.1:0").unwrap();
    decoy.set_nonblocking(true).unwrap();
    let decoy_addr = decoy.local_addr().unwrap();

    let approved_addr = approved.addr;
    let approved_hits = approved.hits.clone();
    let dns = CellDns {
        addrs: Mutex::new(vec![approved_addr]),
    };
    let hosts = vec![format!("pinned.invalid:{}", approved_addr.port())];
    let paths = vec!["/v1/".to_string()];
    let url = format!("http://pinned.invalid:{}/v1/echo", approved_addr.port());
    let target = http::validate_target_with(&url, &hosts, &paths, true, &dns).unwrap();
    assert_eq!(target.validated_addrs, vec![approved_addr]);

    // Simulate DNS rebinding after validation: the hostname now answers with
    // an unapproved loopback address. The pinned agent must not follow it.
    *dns.addrs.lock().unwrap() = vec![decoy_addr];
    let agent = http::agent_for_target(&target, 5);
    let response = agent.get(&target.url).call().unwrap();
    assert_eq!(response.into_body().read_to_string().unwrap(), BODY);
    assert_eq!(approved_hits.load(Ordering::SeqCst), 1);
    match decoy.accept() {
        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
        Ok(_) => panic!("rebound DNS address must not receive the request"),
        Err(e) => panic!("unexpected decoy listener error: {e}"),
    }
    assert_ne!(approved_addr, decoy_addr);
    approved.join();
}

// --- Scenario 13: Redirect denied (max_redirects=0) ---

#[test]
fn s13_redirect_denied() {
    let vault_dir = broker_test_vault();
    let server = MockHttp::start_with(
        "302 Found",
        &[("Location", "/v1/ok")],
        r#"{"status":"redirected"}"#.to_string(),
    );
    let port = server.addr.port();
    let output = run_broker(
        &vault_dir,
        &broker_policy(port, 65536),
        &broker_request(port, "/v1/echo"),
        &[],
    );
    assert_eq!(output.status.code(), Some(2));
    let envelope = stdout_json(&output);
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["error"], "redirect denied");
    assert_eq!(server.hits.load(Ordering::SeqCst), 1);
    let events = audit_events(&vault_dir);
    assert!(events
        .iter()
        .any(|event| event["outcome"] == "error:redirect-denied"));
    server.join();
}

// --- Scenario 14: Proxy env vars ignored ---

#[test]
fn s14_proxy_env_ignored() {
    let vault_dir = broker_test_vault();
    let server = MockHttp::start(r#"{"status":"ok","data":{"id":1}}"#);
    let port = server.addr.port();
    // Only the broker child sees these poisoned proxy settings. If the
    // broker consulted them, the request would go to a dead proxy.
    let output = run_broker(
        &vault_dir,
        &broker_policy(port, 65536),
        &broker_request(port, "/v1/echo"),
        &[
            ("http_proxy", "http://127.0.0.1:9"),
            ("https_proxy", "http://127.0.0.1:9"),
            ("HTTP_PROXY", "http://127.0.0.1:9"),
            ("HTTPS_PROXY", "http://127.0.0.1:9"),
        ],
    );
    assert_eq!(output.status.code(), Some(0));
    let envelope = stdout_json(&output);
    assert_eq!(envelope["ok"], true);
    assert_eq!(envelope["result"]["status"], "ok");
    assert_eq!(server.hits.load(Ordering::SeqCst), 1);
    server.join();
}

// --- Scenario 15: Sensitive response fields filtered ---

#[test]
fn s15_sensitive_fields_filtered() {
    let body = serde_json::json!({
        "status": "ok",
        "data": {"id": 42, "token": "should-be-removed"},
        "password": "should-be-removed",
        "secret": "should-be-removed",
        "token": "should-be-removed"
    })
    .to_string()
    .into_bytes();

    let allow = vec![
        policy::ResponseFieldRule {
            path: "status".to_string(),
            kind: policy::ResponseKind::Text,
            max_len: Some(64),
            max_items: None,
            element_kind: None,
        },
        policy::ResponseFieldRule {
            path: "data.id".to_string(),
            kind: policy::ResponseKind::Integer,
            max_len: None,
            max_items: None,
            element_kind: None,
        },
    ];
    let filtered = respond::filter_response(&body, &allow).unwrap();
    let v = filtered;

    assert!(v.get("status").is_some());
    assert_eq!(v["data"]["id"], 42);
    assert!(v["data"].get("token").is_none());
    assert!(v.get("password").is_none());
    assert!(v.get("secret").is_none());
    assert!(v.get("token").is_none());
}

// --- Scenario 16: Oversized response, timeout, malformed response ---

#[test]
fn s16_oversized_response_enforced() {
    let vault_dir = broker_test_vault();
    let body = format!("{{\"status\":\"{}\"}}", "x".repeat(128));
    let server = MockHttp::start(&body);
    let port = server.addr.port();
    let output = run_broker(
        &vault_dir,
        &broker_policy(port, 16),
        &broker_request(port, "/v1/echo"),
        &[],
    );
    assert_eq!(output.status.code(), Some(2));
    let envelope = stdout_json(&output);
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["error"], "upstream response too large");
    assert_eq!(server.hits.load(Ordering::SeqCst), 1);
    let events = audit_events(&vault_dir);
    assert!(events
        .iter()
        .any(|event| event["outcome"] == "error:response-too-large"));
    server.join();
}

#[test]
fn s16_malformed_json_response_rejected() {
    let body = b"not json at all".to_vec();
    let allow = vec![policy::ResponseFieldRule {
        path: "status".to_string(),
        kind: policy::ResponseKind::Text,
        max_len: Some(64),
        max_items: None,
        element_kind: None,
    }];
    let result = respond::filter_response(&body, &allow);
    assert!(result.is_err());
}

// --- Scenario 17: Credential absence in all outputs ---

#[test]
fn s17_credential_never_in_outputs() {
    // Test that error envelopes never contain credential values
    let err = respond::err_envelope("denied by policy");
    assert!(!err.contains("supersecret"));

    let ok = respond::ok_envelope(serde_json::json!({"result": "ok"}));
    assert!(!ok.contains("supersecret"));

    // Test that audit events never contain credential values
    let dir = tempfile::tempdir().unwrap();
    let ctx = audit::CallContext {
        grant: "g1",
        credential: "SECRET_NAME",
        method: "GET",
        host: "api.example.com:443",
        path: "/v1/test",
    };
    audit::append(dir.path(), &ctx, "ok", 10).unwrap();
    let raw = std::fs::read(audit::audit_path(dir.path())).unwrap();
    let raw_str = String::from_utf8(raw.clone()).unwrap();
    // The credential NAME is allowed, but no value
    assert!(raw_str.contains("SECRET_NAME"));
    // No "value" field
    let v: serde_json::Value = serde_json::from_slice(&raw).unwrap();
    assert!(v.get("value").is_none());
    assert!(v.get("body").is_none());
    assert!(v.get("password").is_none());
}

#[test]
fn audit_intent_failure_prevents_network_side_effects() {
    let vault_dir = broker_test_vault();
    let server = MockHttp::start(r#"{"status":"ok","data":{"id":1}}"#);
    let port = server.addr.port();
    fs::create_dir(vault_dir.path().join("broker-audit.jsonl")).unwrap();
    let output = run_broker(
        &vault_dir,
        &broker_policy(port, 65536),
        &broker_request(port, "/v1/echo"),
        &[],
    );
    assert_eq!(output.status.code(), Some(2));
    let envelope = stdout_json(&output);
    assert_eq!(envelope["ok"], false);
    assert_eq!(envelope["error"], "audit unavailable");
    assert_eq!(
        server.hits.load(Ordering::SeqCst),
        0,
        "an unaudited request must never be sent"
    );
    // Do not join: the server correctly received no connection, so its
    // accept thread remains blocked until the test process exits.
}

#[cfg(unix)]
#[test]
fn audit_completion_failure_reports_possible_side_effect() {
    use std::os::unix::fs::PermissionsExt;
    use std::time::Duration;

    let vault_dir = broker_test_vault();
    let server = DelayedHttp::start(r#"{"status":"ok","data":{"id":1}}"#.to_string());
    let port = server.addr.port();
    let work = tempfile::TempDir::new().unwrap();
    let policy_path = work.path().join("policy.json");
    let request_path = work.path().join("request.json");
    fs::write(
        &policy_path,
        serde_json::to_string(&broker_policy(port, 65536)).unwrap(),
    )
    .unwrap();
    fs::write(
        &request_path,
        serde_json::to_string(&broker_request(port, "/v1/echo")).unwrap(),
    )
    .unwrap();
    let broker_path = Command::cargo_bin("sagitarrius-broker")
        .unwrap()
        .get_program()
        .to_owned();
    let mut child = std::process::Command::new(broker_path)
        .env("SAGITARRIUS_VAULT_DIR", vault_dir.path())
        .env_remove("SAGITARRIUS_PASSWORD")
        .arg("call")
        .arg("--policy")
        .arg(&policy_path)
        .arg("--request")
        .arg(&request_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(format!("{BROKER_TEST_PASSWORD}\n").as_bytes())
            .unwrap();
    }
    server
        .request_received
        .recv_timeout(Duration::from_secs(10))
        .unwrap();

    // The intent record has already been written. Make the completion record
    // fail after the remote side effect below.
    let mut permissions = fs::metadata(vault_dir.path()).unwrap().permissions();
    permissions.set_mode(0o555);
    fs::set_permissions(vault_dir.path(), permissions).unwrap();
    server.send_response.send(()).unwrap();
    let output = child.wait_with_output().unwrap();

    let mut permissions = fs::metadata(vault_dir.path()).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(vault_dir.path(), permissions).unwrap();

    assert_eq!(output.status.code(), Some(2));
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(
        stdout.contains("upstream call may have completed; completion audit unavailable"),
        "withholding the response must not imply the call was undone: {stdout}"
    );
    assert!(
        !stdout.contains("\"result\""),
        "no filtered response may follow a failed completion audit"
    );
    server.join();
}

#[test]
fn s17_credential_absent_from_broker_output() {
    let vault_dir = broker_test_vault();
    let upstream = format!(
        "{{\"status\":\"ok\",\"data\":{{\"id\":42,\"token\":\"{BROKER_TEST_CREDENTIAL_VALUE}\"}},\"secret\":\"{BROKER_TEST_CREDENTIAL_VALUE}\"}}"
    );
    let server = MockHttp::start(&upstream);
    let port = server.addr.port();
    let output = run_broker(
        &vault_dir,
        &broker_policy(port, 65536),
        &broker_request(port, "/v1/echo"),
        &[],
    );
    assert_eq!(output.status.code(), Some(0));
    let stdout = String::from_utf8(output.stdout.clone()).unwrap();
    let envelope: serde_json::Value = serde_json::from_str(&stdout).unwrap();
    assert_eq!(
        envelope,
        json!({"ok": true, "result": {"status": "ok", "data": {"id": 42}}})
    );
    assert!(
        !stdout.contains(BROKER_TEST_CREDENTIAL_VALUE),
        "filtered broker output must not contain the credential value"
    );
    let stderr = String::from_utf8(output.stderr.clone()).unwrap();
    assert!(
        !stderr.contains(BROKER_TEST_CREDENTIAL_VALUE),
        "broker diagnostics must not contain the credential value"
    );
    let audit_raw = fs::read(vault_dir.path().join("broker-audit.jsonl")).unwrap();
    let audit_text = String::from_utf8(audit_raw).unwrap();
    assert!(
        !audit_text.contains(BROKER_TEST_CREDENTIAL_VALUE),
        "audit events must name the credential, never repeat its value"
    );
    assert!(
        audit_text.contains("\"outcome\":\"attempt:authorized\""),
        "the durable intent record must precede the response"
    );
    assert!(
        audit_text.contains("\"outcome\":\"ok\""),
        "the completion record must follow the response"
    );
    assert_eq!(server.hits.load(Ordering::SeqCst), 1);
    server.join();
}

// --- Additional: Timestamp freshness ---

#[test]
fn timestamp_stale_request_rejected() {
    let stale_ts = now_secs() - 1000; // 1000 seconds ago
    let mut req_json: serde_json::Value =
        serde_json::from_str(&valid_request(9443, "GET", "/v1/status", "stale")).unwrap();
    req_json["timestamp"] = serde_json::json!(stale_ts);
    let result = request::parse_request(req_json.to_string().as_bytes(), now_secs());
    assert!(result.is_err());
}

// --- Additional: Policy validation edge cases ---

#[test]
fn policy_empty_grants_denies_all() {
    let p = policy::Policy {
        version: 1,
        grants: vec![],
    };
    let result = policy::authorize(
        &p,
        "g1",
        TEST_CREDENTIAL,
        "GET",
        "api.example.com:443",
        "/v1/status",
    );
    assert!(result.is_err());
}

#[test]
fn policy_empty_hosts_denies_all() {
    let mut p: policy::Policy = serde_json::from_str(&example_policy_json()).unwrap();
    p.grants[0].hosts.clear();
    let result = policy::authorize(
        &p,
        "g1",
        TEST_CREDENTIAL,
        "GET",
        "api.example.com:443",
        "/v1/status",
    );
    assert!(result.is_err());
}
