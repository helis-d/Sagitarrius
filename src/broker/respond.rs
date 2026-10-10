//! Response minimization: rebuild agent-visible output from an allowlist.
//!
//! The primary defense is construction, not scrubbing: the result object is
//! built ONLY from explicitly allowed top-level fields. Unknown fields are
//! dropped, never passed through. A response that is not a JSON object, or
//! that lacks every allowed field, is denied. (Scrubbing known secret
//! strings out of free text is unreliable and is NOT the mechanism.)

use serde_json::Value;

/// Filter `body` down to exactly `allowed` top-level keys.
/// Returns the filtered JSON value, or a static reason string.
pub fn filter_response(body: &[u8], allowed: &[String]) -> Result<Value, &'static str> {
    let v: Value = serde_json::from_slice(body).map_err(|_| "upstream response is not JSON")?;
    let obj = v
        .as_object()
        .ok_or("upstream response is not a JSON object")?;
    let mut out = serde_json::Map::new();
    for key in allowed {
        if let Some(val) = obj.get(key) {
            out.insert(key.clone(), val.clone());
        }
    }
    if out.is_empty() {
        return Err("upstream response holds none of the allowed fields");
    }
    Ok(Value::Object(out))
}

/// The final agent-visible envelope. `result` is the filtered object;
/// `error` is always a static redacted string, never upstream text.
pub fn ok_envelope(result: Value) -> String {
    serde_json::json!({"ok": true, "result": result}).to_string()
}

pub fn err_envelope(reason: &str) -> String {
    serde_json::json!({"ok": false, "error": reason}).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn allowed() -> Vec<String> {
        vec!["status".to_string(), "echo".to_string()]
    }

    #[test]
    fn keeps_only_allowed_fields() {
        let v = filter_response(
            br#"{"status":"ok","echo":"hi","secret":"LEAK","nested":{"secret":1}}"#,
            &allowed(),
        )
        .unwrap();
        assert_eq!(v, serde_json::json!({"status": "ok", "echo": "hi"}));
    }

    #[test]
    fn rejects_non_objects_and_empty_matches() {
        assert!(filter_response(b"[1,2]", &allowed()).is_err());
        assert!(filter_response(b"\"str\"", &allowed()).is_err());
        assert!(filter_response(br#"{"other":1}"#, &allowed()).is_err());
        assert!(filter_response(b"{invalid", &allowed()).is_err());
    }

    #[test]
    fn envelopes_carry_no_free_text() {
        let e: Value = serde_json::from_str(&err_envelope("denied: unknown grant")).unwrap();
        assert_eq!(e["ok"], false);
        assert_eq!(e["error"], "denied: unknown grant");
        let o: Value =
            serde_json::from_str(&ok_envelope(serde_json::json!({"status": "ok"}))).unwrap();
        assert_eq!(o["ok"], true);
        assert_eq!(o["result"]["status"], "ok");
    }
}
