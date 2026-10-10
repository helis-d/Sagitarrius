//! Response minimization: rebuild agent-visible output from a constrained
//! schema.
//!
//! The primary defense is construction, not scrubbing: the result object is
//! built ONLY from explicitly allowed leaf paths with explicitly allowed
//! scalar types and bounds. Unknown fields are dropped, nested objects are
//! never copied wholesale, and arrays are accepted only with an explicit
//! scalar element kind and item limit. A response that is not a JSON object,
//! or that lacks every allowed leaf, is denied. (Scrubbing known secret
//! strings out of free text is unreliable and is NOT the mechanism.)

use crate::broker::policy::{ResponseElementKind, ResponseFieldRule, ResponseKind};
use serde_json::Value;

/// Filter `body` down to exactly the leaves selected by `allowed`.
/// Returns the rebuilt JSON value, or a static reason string.
pub fn filter_response(body: &[u8], allowed: &[ResponseFieldRule]) -> Result<Value, &'static str> {
    let v: Value = serde_json::from_slice(body).map_err(|_| "upstream response is not JSON")?;
    let obj = v
        .as_object()
        .ok_or("upstream response is not a JSON object")?;
    let mut out = serde_json::Map::new();
    let mut matched = 0;
    for rule in allowed {
        let segments: Vec<&str> = rule.path.split('.').collect();
        let Some(value) = get_path(obj, &segments)? else {
            continue;
        };
        let checked = check_value(value, rule)?;
        insert_path(&mut out, &segments, checked)?;
        matched += 1;
    }
    if matched == 0 {
        return Err("upstream response holds none of the allowed fields");
    }
    Ok(Value::Object(out))
}

fn get_path<'a>(
    obj: &'a serde_json::Map<String, Value>,
    segments: &[&str],
) -> Result<Option<&'a Value>, &'static str> {
    let mut current = obj;
    for (i, segment) in segments.iter().enumerate() {
        let Some(next) = current.get(*segment) else {
            return Ok(None);
        };
        if i + 1 == segments.len() {
            return Ok(Some(next));
        }
        current = next
            .as_object()
            .ok_or("upstream response structure is not allowed")?;
    }
    Err("upstream response structure is not allowed")
}

fn check_value(value: &Value, rule: &ResponseFieldRule) -> Result<Value, &'static str> {
    match rule.kind {
        ResponseKind::Text => {
            let text = value
                .as_str()
                .ok_or("upstream response field has the wrong type")?;
            let max_len = rule.max_len.ok_or("response rule is missing max_len")?;
            if text.chars().count() > max_len {
                return Err("upstream response string is too long");
            }
            Ok(Value::String(text.to_string()))
        }
        ResponseKind::Integer => {
            if value.is_i64() || value.is_u64() {
                Ok(value.clone())
            } else {
                Err("upstream response field has the wrong type")
            }
        }
        ResponseKind::Number => {
            if value.is_number() {
                Ok(value.clone())
            } else {
                Err("upstream response field has the wrong type")
            }
        }
        ResponseKind::Boolean => {
            if value.is_boolean() {
                Ok(value.clone())
            } else {
                Err("upstream response field has the wrong type")
            }
        }
        ResponseKind::Null => {
            if value.is_null() {
                Ok(Value::Null)
            } else {
                Err("upstream response field has the wrong type")
            }
        }
        ResponseKind::Array => {
            let items = value
                .as_array()
                .ok_or("upstream response field has the wrong type")?;
            let max_items = rule.max_items.ok_or("response rule is missing max_items")?;
            let element_kind = rule
                .element_kind
                .ok_or("response rule is missing element_kind")?;
            if items.len() > max_items {
                return Err("upstream response array is too long");
            }
            let mut checked = Vec::with_capacity(items.len());
            for item in items {
                checked.push(check_scalar(item, element_kind, rule.max_len)?);
            }
            Ok(Value::Array(checked))
        }
    }
}

fn check_scalar(
    value: &Value,
    kind: ResponseElementKind,
    max_len: Option<usize>,
) -> Result<Value, &'static str> {
    match kind {
        ResponseElementKind::Text => {
            let text = value
                .as_str()
                .ok_or("upstream response field has the wrong type")?;
            let max_len = max_len.ok_or("response rule is missing max_len")?;
            if text.chars().count() > max_len {
                return Err("upstream response string is too long");
            }
            Ok(Value::String(text.to_string()))
        }
        ResponseElementKind::Integer => {
            if value.is_i64() || value.is_u64() {
                Ok(value.clone())
            } else {
                Err("upstream response field has the wrong type")
            }
        }
        ResponseElementKind::Number => {
            if value.is_number() {
                Ok(value.clone())
            } else {
                Err("upstream response field has the wrong type")
            }
        }
        ResponseElementKind::Boolean => {
            if value.is_boolean() {
                Ok(value.clone())
            } else {
                Err("upstream response field has the wrong type")
            }
        }
        ResponseElementKind::Null => {
            if value.is_null() {
                Ok(Value::Null)
            } else {
                Err("upstream response field has the wrong type")
            }
        }
    }
}

fn insert_path(
    root: &mut serde_json::Map<String, Value>,
    segments: &[&str],
    value: Value,
) -> Result<(), &'static str> {
    let mut current = root;
    for (i, segment) in segments.iter().enumerate() {
        if i + 1 == segments.len() {
            if current.contains_key(*segment) {
                return Err("response rules select the same path");
            }
            current.insert((*segment).to_string(), value);
            return Ok(());
        }
        let entry = current
            .entry((*segment).to_string())
            .or_insert_with(|| Value::Object(serde_json::Map::new()));
        current = entry
            .as_object_mut()
            .ok_or("response rules select overlapping paths")?;
    }
    Err("response rules select the same path")
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
    use crate::broker::policy::{ResponseElementKind, ResponseKind};

    fn text_rule(path: &str) -> ResponseFieldRule {
        ResponseFieldRule {
            path: path.to_string(),
            kind: ResponseKind::Text,
            max_len: Some(64),
            max_items: None,
            element_kind: None,
        }
    }

    fn allowed() -> Vec<ResponseFieldRule> {
        vec![text_rule("status"), text_rule("echo")]
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
    fn nested_objects_are_selected_leaf_by_leaf() {
        let rules = vec![
            ResponseFieldRule {
                path: "data.id".to_string(),
                kind: ResponseKind::Integer,
                max_len: None,
                max_items: None,
                element_kind: None,
            },
            text_rule("status"),
        ];
        let v = filter_response(
            br#"{"status":"ok","data":{"id":42,"token":"LEAK","nested":{"password":"LEAK"}}}"#,
            &rules,
        )
        .unwrap();
        assert_eq!(v, serde_json::json!({"status": "ok", "data": {"id": 42}}));
    }

    #[test]
    fn arrays_and_types_are_bounded() {
        let rules = vec![ResponseFieldRule {
            path: "items".to_string(),
            kind: ResponseKind::Array,
            max_len: Some(8),
            max_items: Some(2),
            element_kind: Some(ResponseElementKind::Text),
        }];
        let v = filter_response(br#"{"items":["a","b"]}"#, &rules).unwrap();
        assert_eq!(v, serde_json::json!({"items": ["a", "b"]}));
        assert!(filter_response(br#"{"items":["a","b","c"]}"#, &rules).is_err());
        assert!(filter_response(br#"{"items":["0123456789"]}"#, &rules).is_err());
        assert!(filter_response(br#"{"items":[1]}"#, &rules).is_err());
        assert!(filter_response(br#"{"items":[["a"]]}"#, &rules).is_err());

        let integer = vec![ResponseFieldRule {
            path: "count".to_string(),
            kind: ResponseKind::Integer,
            max_len: None,
            max_items: None,
            element_kind: None,
        }];
        assert!(filter_response(br#"{"count":1.5}"#, &integer).is_err());
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
