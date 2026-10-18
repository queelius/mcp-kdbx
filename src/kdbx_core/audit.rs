//! JSONL audit-log events and sha256 reveal hashing.
//!
//! This module implements spec section 6 ("Audit trail"). Every audited action
//! is an [`AuditEvent`] variant. A variant knows two things on its own: its
//! stable wire name ([`AuditEvent::event`]) and its severity level
//! ([`AuditEvent::level`]). The level is a property of the variant, not a
//! separate lookup table, so there is one place to change when an event's
//! severity changes.
//!
//! An event renders to the spec envelope:
//!
//! ```json
//! { "timestamp": "...", "level": "info", "event": "vault_unlocked",
//!   "pid": 12345, "details": { /* event-specific */ } }
//! ```
//!
//! The envelope builder ([`AuditEvent::envelope`]) takes the timestamp and pid
//! as arguments so tests are deterministic. The runtime path stamps
//! `chrono::Utc::now()` and `std::process::id()` via [`AuditLog::write`].
//!
//! Privacy invariants (non-negotiable, spec section 6):
//!
//! - Plaintext values never appear in any event. Reveal events carry a sha256
//!   hash via [`hash_revealed`], never the value.
//! - The master password and unlock-command output never appear anywhere.
//!
//! Deferred beyond v0.1: debug/trace JSON-RPC payload capture (the spec's
//! `tool_call` and `mcp_message` events). Those events were never wired into a
//! call site. The actual leak risk (rmcp Debug-logging raw JSON-RPC payloads
//! that contain secrets) is prevented in `main.rs` by capping rmcp's tracing
//! verbosity, not by emitting redacted copies of those payloads here. If the
//! capture is added later, it must restore a redaction layer before logging.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Write;
use std::sync::Mutex;

/// Severity level for an audit event, mapped from the spec's per-event level
/// column. The wire form is lowercase (see [`Level::as_str`]) to match the
/// envelope shape in spec section 6.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Error,
    Warn,
    Info,
    Debug,
    Trace,
}

impl Level {
    /// The lowercase wire string for this level.
    pub fn as_str(&self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Info => "info",
            Level::Debug => "debug",
            Level::Trace => "trace",
        }
    }
}

/// One audited action. Each variant carries the event-specific detail fields
/// named in the spec's "Logged events" table (section 6).
///
/// `target_path` is the canonical vault path of the record acted on, or `None`
/// (JSON `null`) when the record has no addressable path and was named by UUID.
///
/// Field names on the variants match the snake_case keys that appear in the
/// rendered `details` object, so the mapping in [`AuditEvent::details_json`]
/// stays a direct transcription with no renaming surprises.
#[derive(Debug, Clone)]
pub enum AuditEvent {
    /// Server process started. Captures vault path and policy, never secrets.
    ServerStarted {
        server_version: String,
        vault_path: String,
        writes_allowed: bool,
        idle_timeout_seconds: u64,
    },
    /// A vault was unlocked. `unlock_source` is one of "input", "env", "cmd".
    VaultUnlocked {
        unlock_source: String,
        file_mtime: String,
    },
    /// A vault was locked (idle, explicit, or shutdown).
    VaultLocked {
        reason: String,
        pending_discarded_count: u64,
    },
    /// Authentication failed. `source` matches the unlock source that failed.
    AuthFailed { source: String, error_code: String },
    /// A write was staged into the working database (not yet on disk).
    WriteStaged {
        tool: String,
        target_path: Option<String>,
        target_uuid: String,
        /// Present only for field-level writes; null otherwise.
        field_name: Option<String>,
    },
    /// The pending stage was discarded. `summary` carries paths only, no values.
    StageDiscarded {
        reason: String,
        num_dropped: u64,
        summary: Vec<String>,
    },
    /// The working database was written to disk.
    SaveCommitted {
        num_changes: u64,
        before_mtime: String,
        after_mtime: String,
    },
    /// Save was refused because the file changed on disk since unlock.
    SaveRefused {
        before_mtime: String,
        conflict_mtime: String,
        pending_changes: u64,
    },
    /// Save failed mid-flight. `failure_step` names where it stopped.
    SaveFailed {
        failure_step: String,
        error_message: String,
        pending_changes: u64,
    },
    /// A password field was revealed. `sha256` is [`hash_revealed`] of the value.
    RevealPassword {
        target_path: Option<String>,
        target_uuid: String,
        sha256: String,
    },
    /// A non-password protected field was revealed.
    RevealProtected {
        target_path: Option<String>,
        target_uuid: String,
        field_name: String,
        sha256: String,
    },
    /// An attachment was downloaded. `sha256` is a plain SHA-256 content
    /// fingerprint of the bytes (lowercase hex), the same digest the
    /// `kdbx_list_attachments` view reports, not the domain-separated
    /// [`hash_revealed`] (which is for string secrets). It identifies which
    /// attachment was taken without storing its content.
    DownloadAttachment {
        target_path: Option<String>,
        attachment_name: String,
        size_bytes: u64,
        sha256: String,
    },
    /// A TOTP code was computed. The code itself is never logged.
    GetOtp {
        target_path: Option<String>,
        target_uuid: String,
    },
}

impl AuditEvent {
    /// The stable wire name for this event (the `event` envelope field).
    pub fn event(&self) -> &'static str {
        match self {
            AuditEvent::ServerStarted { .. } => "server_started",
            AuditEvent::VaultUnlocked { .. } => "vault_unlocked",
            AuditEvent::VaultLocked { .. } => "vault_locked",
            AuditEvent::AuthFailed { .. } => "auth_failed",
            AuditEvent::WriteStaged { .. } => "write_staged",
            AuditEvent::StageDiscarded { .. } => "stage_discarded",
            AuditEvent::SaveCommitted { .. } => "save_committed",
            AuditEvent::SaveRefused { .. } => "save_refused",
            AuditEvent::SaveFailed { .. } => "save_failed",
            AuditEvent::RevealPassword { .. } => "reveal_password",
            AuditEvent::RevealProtected { .. } => "reveal_protected",
            AuditEvent::DownloadAttachment { .. } => "download_attachment",
            AuditEvent::GetOtp { .. } => "get_otp",
        }
    }

    /// The severity level for this event, taken from the spec's level column.
    /// The level is a property of the variant; there is no second table.
    pub fn level(&self) -> Level {
        match self {
            AuditEvent::ServerStarted { .. } => Level::Info,
            AuditEvent::VaultUnlocked { .. } => Level::Info,
            AuditEvent::VaultLocked { .. } => Level::Info,
            AuditEvent::AuthFailed { .. } => Level::Error,
            AuditEvent::WriteStaged { .. } => Level::Info,
            AuditEvent::StageDiscarded { .. } => Level::Info,
            AuditEvent::SaveCommitted { .. } => Level::Info,
            AuditEvent::SaveRefused { .. } => Level::Warn,
            AuditEvent::SaveFailed { .. } => Level::Error,
            AuditEvent::RevealPassword { .. } => Level::Info,
            AuditEvent::RevealProtected { .. } => Level::Info,
            AuditEvent::DownloadAttachment { .. } => Level::Info,
            AuditEvent::GetOtp { .. } => Level::Info,
        }
    }

    /// The event-specific `details` payload as a JSON object. Pure and
    /// testable: it never reads the clock, the pid, or the environment.
    pub fn details_json(&self) -> Value {
        match self {
            AuditEvent::ServerStarted {
                server_version,
                vault_path,
                writes_allowed,
                idle_timeout_seconds,
            } => json!({
                "server_version": server_version,
                "vault_path": vault_path,
                "writes_allowed": writes_allowed,
                "idle_timeout_seconds": idle_timeout_seconds,
            }),
            AuditEvent::VaultUnlocked {
                unlock_source,
                file_mtime,
            } => json!({
                "unlock_source": unlock_source,
                "file_mtime": file_mtime,
            }),
            AuditEvent::VaultLocked {
                reason,
                pending_discarded_count,
            } => json!({
                "reason": reason,
                "pending_discarded_count": pending_discarded_count,
            }),
            AuditEvent::AuthFailed { source, error_code } => json!({
                "source": source,
                "error_code": error_code,
            }),
            AuditEvent::WriteStaged {
                tool,
                target_path,
                target_uuid,
                field_name,
            } => json!({
                "tool": tool,
                "target_path": target_path,
                "target_uuid": target_uuid,
                "field_name": field_name,
            }),
            AuditEvent::StageDiscarded {
                reason,
                num_dropped,
                summary,
            } => json!({
                "reason": reason,
                "num_dropped": num_dropped,
                "summary": summary,
            }),
            AuditEvent::SaveCommitted {
                num_changes,
                before_mtime,
                after_mtime,
            } => json!({
                "num_changes": num_changes,
                "before_mtime": before_mtime,
                "after_mtime": after_mtime,
            }),
            AuditEvent::SaveRefused {
                before_mtime,
                conflict_mtime,
                pending_changes,
            } => json!({
                "before_mtime": before_mtime,
                "conflict_mtime": conflict_mtime,
                "pending_changes": pending_changes,
            }),
            AuditEvent::SaveFailed {
                failure_step,
                error_message,
                pending_changes,
            } => json!({
                "failure_step": failure_step,
                "error_message": error_message,
                "pending_changes": pending_changes,
            }),
            AuditEvent::RevealPassword {
                target_path,
                target_uuid,
                sha256,
            } => json!({
                "target_path": target_path,
                "target_uuid": target_uuid,
                "sha256": sha256,
            }),
            AuditEvent::RevealProtected {
                target_path,
                target_uuid,
                field_name,
                sha256,
            } => json!({
                "target_path": target_path,
                "target_uuid": target_uuid,
                "field_name": field_name,
                "sha256": sha256,
            }),
            AuditEvent::DownloadAttachment {
                target_path,
                attachment_name,
                size_bytes,
                sha256,
            } => json!({
                "target_path": target_path,
                "attachment_name": attachment_name,
                "size_bytes": size_bytes,
                "sha256": sha256,
            }),
            AuditEvent::GetOtp {
                target_path,
                target_uuid,
            } => json!({
                "target_path": target_path,
                "target_uuid": target_uuid,
            }),
        }
    }

    /// Build the full envelope with an injected `timestamp` (RFC3339 string)
    /// and `pid`. Keeping these as arguments makes the rendering deterministic
    /// in tests; the runtime path supplies the real clock and pid.
    pub fn envelope(&self, timestamp: &str, pid: u32) -> Value {
        json!({
            "timestamp": timestamp,
            "level": self.level().as_str(),
            "event": self.event(),
            "pid": pid,
            "details": self.details_json(),
        })
    }
}

/// The reveal-hash domain prefix. The single trailing NUL byte is part of the
/// contract: `sha256("kdbx-reveal-v1\0" || value)`. Changing these bytes breaks
/// every previously logged hash, so they are pinned here and asserted in tests.
const REVEAL_DOMAIN_PREFIX: &[u8] = b"kdbx-reveal-v1\0";

/// Domain-separated sha256 of a revealed value, as lowercase hex.
///
/// The hash is over `REVEAL_DOMAIN_PREFIX` followed by the value bytes. The
/// domain prefix separates these hashes from any other sha256 use and blunts
/// generic rainbow-table lookups. This is the privacy invariant for reveal
/// events: the log stores this hash, never the value.
pub fn hash_revealed(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(REVEAL_DOMAIN_PREFIX);
    hasher.update(value.as_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        // Two lowercase hex chars per byte, no separators.
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Writes audit events as JSONL to stderr and, if configured, to a file.
///
/// One JSON object per line. The optional file handle is opened append-only
/// from `KDBX_LOG_FILE` by the caller and handed in via [`AuditLog::new`]. The
/// write path is synchronous and best-effort: a failed file write does not
/// abort the action being audited (the event still reaches stderr).
pub struct AuditLog {
    file: Option<Mutex<File>>,
}

impl AuditLog {
    /// Build a logger that writes to stderr only.
    pub fn stderr_only() -> Self {
        Self { file: None }
    }

    /// Build a logger that writes to stderr and the given append file handle.
    pub fn new(file: Option<File>) -> Self {
        Self {
            file: file.map(Mutex::new),
        }
    }

    /// Render `event` to a single JSONL line and emit it.
    ///
    /// The timestamp is stamped here as `chrono::Utc::now()` in RFC3339 form
    /// and the pid as `std::process::id()`. Tests that need determinism call
    /// [`AuditEvent::envelope`] directly with injected values instead.
    pub fn write(&self, event: &AuditEvent) {
        let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let pid = std::process::id();
        let envelope = event.envelope(&timestamp, pid);
        let line = envelope.to_string();
        self.emit_line(&line);
    }

    /// Write one already-rendered line (plus newline) to stderr and the file.
    fn emit_line(&self, line: &str) {
        // stderr first so the record is visible even if the file write fails.
        let mut stderr = std::io::stderr();
        let _ = writeln!(stderr, "{line}");
        if let Some(file) = &self.file {
            if let Ok(mut handle) = file.lock() {
                let _ = writeln!(handle, "{line}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Construct one of every variant. Used to check the event name and level
    /// mapping is exhaustive and matches the spec table.
    fn all_events() -> Vec<(AuditEvent, &'static str, Level)> {
        vec![
            (
                AuditEvent::ServerStarted {
                    server_version: "0.1.0".to_string(),
                    vault_path: "/vault.kdbx".to_string(),
                    writes_allowed: false,
                    idle_timeout_seconds: 900,
                },
                "server_started",
                Level::Info,
            ),
            (
                AuditEvent::VaultUnlocked {
                    unlock_source: "env".to_string(),
                    file_mtime: "2026-05-08T10:00:00Z".to_string(),
                },
                "vault_unlocked",
                Level::Info,
            ),
            (
                AuditEvent::VaultLocked {
                    reason: "idle".to_string(),
                    pending_discarded_count: 0,
                },
                "vault_locked",
                Level::Info,
            ),
            (
                AuditEvent::AuthFailed {
                    source: "cmd".to_string(),
                    error_code: "AUTH_FAILED".to_string(),
                },
                "auth_failed",
                Level::Error,
            ),
            (
                AuditEvent::WriteStaged {
                    tool: "kdbx_update_field".to_string(),
                    target_path: Some("/Web/GitHub".to_string()),
                    target_uuid: "abcd".to_string(),
                    field_name: Some("Password".to_string()),
                },
                "write_staged",
                Level::Info,
            ),
            (
                AuditEvent::StageDiscarded {
                    reason: "idle_lock".to_string(),
                    num_dropped: 2,
                    summary: vec!["/Web/GitHub".to_string(), "/Web/GitLab".to_string()],
                },
                "stage_discarded",
                Level::Info,
            ),
            (
                AuditEvent::SaveCommitted {
                    num_changes: 1,
                    before_mtime: "2026-05-08T10:00:00Z".to_string(),
                    after_mtime: "2026-05-08T10:01:00Z".to_string(),
                },
                "save_committed",
                Level::Info,
            ),
            (
                AuditEvent::SaveRefused {
                    before_mtime: "2026-05-08T10:00:00Z".to_string(),
                    conflict_mtime: "2026-05-08T10:00:30Z".to_string(),
                    pending_changes: 1,
                },
                "save_refused",
                Level::Warn,
            ),
            (
                AuditEvent::SaveFailed {
                    failure_step: "rename".to_string(),
                    error_message: "disk full".to_string(),
                    pending_changes: 1,
                },
                "save_failed",
                Level::Error,
            ),
            (
                AuditEvent::RevealPassword {
                    target_path: Some("/Web/GitHub".to_string()),
                    target_uuid: "abcd".to_string(),
                    sha256: "deadbeef".to_string(),
                },
                "reveal_password",
                Level::Info,
            ),
            (
                AuditEvent::RevealProtected {
                    target_path: Some("/Web/GitHub".to_string()),
                    target_uuid: "abcd".to_string(),
                    field_name: "RecoveryKey".to_string(),
                    sha256: "deadbeef".to_string(),
                },
                "reveal_protected",
                Level::Info,
            ),
            (
                AuditEvent::DownloadAttachment {
                    target_path: Some("/Web/GitHub".to_string()),
                    attachment_name: "key.pem".to_string(),
                    size_bytes: 2048,
                    sha256: "deadbeef".to_string(),
                },
                "download_attachment",
                Level::Info,
            ),
            (
                AuditEvent::GetOtp {
                    target_path: Some("/Web/GitHub".to_string()),
                    target_uuid: "abcd".to_string(),
                },
                "get_otp",
                Level::Info,
            ),
        ]
    }

    #[test]
    fn level_wire_strings() {
        assert_eq!(Level::Error.as_str(), "error");
        assert_eq!(Level::Warn.as_str(), "warn");
        assert_eq!(Level::Info.as_str(), "info");
        assert_eq!(Level::Debug.as_str(), "debug");
        assert_eq!(Level::Trace.as_str(), "trace");
    }

    #[test]
    fn each_event_maps_to_its_spec_name_and_level() {
        for (event, name, level) in all_events() {
            assert_eq!(event.event(), name, "event name mismatch for {name}");
            assert_eq!(event.level(), level, "level mismatch for {name}");
        }
    }

    #[test]
    fn envelope_has_all_five_top_level_fields() {
        let (event, name, level) = all_events().into_iter().next().unwrap();
        let env = event.envelope("2026-05-08T10:00:00Z", 12345);
        let obj = env.as_object().unwrap();
        // Exactly the five envelope fields from spec section 6, no more.
        assert_eq!(obj.len(), 5);
        assert_eq!(obj["timestamp"], json!("2026-05-08T10:00:00Z"));
        assert_eq!(obj["level"], json!(level.as_str()));
        assert_eq!(obj["event"], json!(name));
        assert_eq!(obj["pid"], json!(12345));
        assert!(obj["details"].is_object());
    }

    #[test]
    fn every_variant_renders_the_envelope_shape() {
        for (event, name, level) in all_events() {
            let env = event.envelope("2026-05-08T10:00:00Z", 999);
            assert_eq!(env["timestamp"], json!("2026-05-08T10:00:00Z"));
            assert_eq!(env["level"], json!(level.as_str()));
            assert_eq!(env["event"], json!(name));
            assert_eq!(env["pid"], json!(999));
            assert!(
                env["details"].is_object(),
                "details must be an object for {name}"
            );
        }
    }

    #[test]
    fn details_carry_the_spec_fields() {
        // Spot-check a few variants against the spec's details column.
        let staged = AuditEvent::WriteStaged {
            tool: "kdbx_add_entry".to_string(),
            target_path: Some("/Web/New".to_string()),
            target_uuid: "uuid-1".to_string(),
            field_name: None,
        };
        let d = staged.details_json();
        assert_eq!(d["tool"], json!("kdbx_add_entry"));
        assert_eq!(d["target_path"], json!("/Web/New"));
        assert_eq!(d["target_uuid"], json!("uuid-1"));
        assert_eq!(d["field_name"], Value::Null);

        let reveal = AuditEvent::RevealProtected {
            target_path: Some("/Web/X".to_string()),
            target_uuid: "uuid-2".to_string(),
            field_name: "Secret".to_string(),
            sha256: "abc123".to_string(),
        };
        let d = reveal.details_json();
        assert_eq!(d["field_name"], json!("Secret"));
        assert_eq!(d["sha256"], json!("abc123"));

        let otp = AuditEvent::GetOtp {
            target_path: Some("/Web/X".to_string()),
            target_uuid: "uuid-3".to_string(),
        };
        let d = otp.details_json();
        // No code field: the OTP value is never logged.
        assert!(d.get("code").is_none());
        assert_eq!(d.as_object().unwrap().len(), 2);
    }

    #[test]
    fn hash_revealed_matches_handcomputed_sha256() {
        // Compute the expected digest directly over the domain prefix bytes
        // plus the value, so the test does not depend on the function under
        // test for its own expectation.
        let value = "hunter2";
        let mut hasher = Sha256::new();
        hasher.update(b"kdbx-reveal-v1\0");
        hasher.update(value.as_bytes());
        let expected: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        assert_eq!(hash_revealed(value), expected);
        // sha256 hex is 64 lowercase chars.
        assert_eq!(hash_revealed(value).len(), 64);
        assert!(
            hash_revealed(value)
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
        );
    }

    #[test]
    fn hash_revealed_pinned_vector_for_empty_string() {
        // Pinned vector: sha256 of exactly the 15 prefix bytes "kdbx-reveal-v1\0"
        // with an empty value. Guards the prefix byte-for-byte, including the
        // single trailing NUL.
        let mut hasher = Sha256::new();
        hasher.update(b"kdbx-reveal-v1\0");
        let expected: String = hasher
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_eq!(hash_revealed(""), expected);
    }

    #[test]
    fn hash_domain_prefix_includes_single_nul() {
        // The constant is exactly the ascii text plus one NUL byte: 15 bytes.
        assert_eq!(REVEAL_DOMAIN_PREFIX, b"kdbx-reveal-v1\0");
        assert_eq!(REVEAL_DOMAIN_PREFIX.len(), 15);
        assert_eq!(REVEAL_DOMAIN_PREFIX[14], 0u8);
    }

    #[test]
    fn hash_differs_from_undomained_sha256() {
        // A plain sha256 of the value (no domain prefix) must not match, which
        // confirms the prefix is actually mixed in.
        let value = "hunter2";
        let mut plain = Sha256::new();
        plain.update(value.as_bytes());
        let plain_hex: String = plain
            .finalize()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        assert_ne!(hash_revealed(value), plain_hex);
    }

    #[test]
    fn audit_log_constructors_do_not_panic() {
        // Smoke test: stderr-only and file-less constructors build cleanly.
        let _stderr = AuditLog::stderr_only();
        let _none = AuditLog::new(None);
    }
}
