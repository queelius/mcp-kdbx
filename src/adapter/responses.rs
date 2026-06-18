//! The tool-result envelope.
//!
//! Every tool returns a JSON object as a single text-content block (spec section
//! 1). Success is `{ "ok": true, "data": ... }`; failure is `{ "ok": false,
//! "error": { "code", "message", "details? } }`. This shape is parseable from
//! prompt text without the agent needing to know MCP-protocol-level error
//! semantics, and it gives the audit trail one shape to log.
//!
//! The MCP transport (rmcp) carries this string as the tool's text content. We
//! do not use rmcp's protocol-level error path for tool-domain failures: a
//! locked vault or a missing entry is a normal, expected outcome the agent
//! should see and reason about, not a transport error.

use crate::kdbx_core::error::{CoreError, ErrorCode};
use crate::kdbx_core::vault::LockInfo;
use serde::Serialize;
use serde_json::json;

/// Build the `VAULT_LOCKED` error for a tool that found the vault locked.
///
/// The first tool call after a lock should say what staged work the lock
/// discarded, so the agent can recover (re-unlock, re-stage). The caller passes
/// the result of [`crate::kdbx_core::vault::Vault::take_last_lock`]: when it is
/// `Some`, the error carries `details { lock_reason, pending_discarded_count,
/// pending_discarded_summary }`; when it is `None` (no prior lock to report, or
/// the details were already taken by an earlier call), the error is a bare
/// `VAULT_LOCKED` with no details.
///
/// `take_last_lock` clears the stash, so only the first locked-tool call after a
/// lock gets the details; subsequent calls get the bare error. This is the
/// single place that shape is built, so every tool reports it the same way.
pub fn locked_error(last_lock: Option<LockInfo>) -> CoreError {
    let base = CoreError::new(ErrorCode::VaultLocked);
    match last_lock {
        Some(info) => base.with_details(json!({
            "lock_reason": info.reason,
            "pending_discarded_count": info.pending_discarded_count,
            "pending_discarded_summary": info.summary,
        })),
        None => base,
    }
}

/// Serialize a successful tool payload into the `{ ok: true, data }` envelope
/// string.
pub fn ok<T: Serialize>(data: T) -> String {
    let value = match serde_json::to_value(&data) {
        Ok(data) => json!({ "ok": true, "data": data }),
        // Serializing a tool's own output should never fail. If it somehow does,
        // report it as an error envelope rather than panicking the handler.
        Err(e) => error_value(
            "INTERNAL",
            &format!("failed to serialize tool output: {e}"),
            None,
        ),
    };
    to_string(&value)
}

/// Serialize a [`CoreError`] into the `{ ok: false, error }` envelope string.
pub fn err(error: &CoreError) -> String {
    let value = error_value(error.code(), error.message(), error.details().cloned());
    to_string(&value)
}

/// Collapse a `CoreResult`-shaped outcome into the envelope string.
pub fn from_result<T: Serialize>(result: Result<T, CoreError>) -> String {
    match result {
        Ok(data) => ok(data),
        Err(e) => err(&e),
    }
}

/// Build the `{ ok: false, error: { code, message, details? } }` value.
fn error_value(code: &str, message: &str, details: Option<serde_json::Value>) -> serde_json::Value {
    let mut error = json!({ "code": code, "message": message });
    if let Some(details) = details {
        error["details"] = details;
    }
    json!({ "ok": false, "error": error })
}

/// Serialize a JSON value to a string, falling back to a fixed error envelope if
/// even that fails (it should not for a plain object).
fn to_string(value: &serde_json::Value) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| {
        r#"{"ok":false,"error":{"code":"INTERNAL","message":"envelope serialization failed"}}"#
            .to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdbx_core::error::ErrorCode;
    use serde_json::Value;

    #[test]
    fn ok_wraps_data() {
        let s = ok(json!({ "vault_name": "personal", "locked": false }));
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["ok"], json!(true));
        assert_eq!(v["data"]["vault_name"], json!("personal"));
        assert!(v.get("error").is_none());
    }

    #[test]
    fn err_carries_code_message_and_details() {
        let e = CoreError::new(ErrorCode::GroupNotFound)
            .with_message("no group at /Web/Nope")
            .with_details(json!({ "path": "/Web/Nope" }));
        let s = err(&e);
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["ok"], json!(false));
        assert_eq!(v["error"]["code"], json!("GROUP_NOT_FOUND"));
        assert_eq!(v["error"]["message"], json!("no group at /Web/Nope"));
        assert_eq!(v["error"]["details"]["path"], json!("/Web/Nope"));
    }

    #[test]
    fn err_without_details_omits_the_key() {
        let s = err(&CoreError::new(ErrorCode::VaultLocked));
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["error"]["code"], json!("VAULT_LOCKED"));
        assert!(v["error"].get("details").is_none());
    }

    #[test]
    fn locked_error_with_info_carries_discard_details() {
        let info = LockInfo {
            reason: "idle_timeout".to_string(),
            pending_discarded_count: 2,
            summary: vec!["/Web/GitHub".to_string(), "/Web/GitLab".to_string()],
        };
        let s = err(&locked_error(Some(info)));
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["error"]["code"], json!("VAULT_LOCKED"));
        assert_eq!(v["error"]["details"]["lock_reason"], json!("idle_timeout"));
        assert_eq!(v["error"]["details"]["pending_discarded_count"], json!(2));
        assert_eq!(
            v["error"]["details"]["pending_discarded_summary"],
            json!(["/Web/GitHub", "/Web/GitLab"])
        );
    }

    #[test]
    fn locked_error_without_info_is_bare() {
        let s = err(&locked_error(None));
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["error"]["code"], json!("VAULT_LOCKED"));
        assert!(v["error"].get("details").is_none());
    }

    #[test]
    fn from_result_maps_both_arms() {
        let good: Result<_, CoreError> = Ok(json!({ "n": 1 }));
        let bad: Result<Value, CoreError> = Err(CoreError::new(ErrorCode::AuthFailed));
        assert_eq!(
            serde_json::from_str::<Value>(&from_result(good)).unwrap()["ok"],
            json!(true)
        );
        assert_eq!(
            serde_json::from_str::<Value>(&from_result(bad)).unwrap()["ok"],
            json!(false)
        );
    }
}
