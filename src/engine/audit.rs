//! JSONL audit-log events with keyed fingerprints of revealed values.
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
//! - Plaintext values never appear in any event. Reveal events carry a keyed
//!   fingerprint ([`KeyedFingerprint`]: HMAC-SHA256 under the stable audit
//!   key, derived at unlock), never the value. An unkeyed hash of a
//!   low-entropy secret would be a lookup oracle (a 4-digit PIN falls in
//!   under 10,000 tries); the keyed one can be checked only by someone who
//!   holds the vault's key material, with `diff-kdbx fingerprint`.
//! - Everything derived from the stable audit key (the fingerprints, and the
//!   derivation parameters and salt `vault_unlocked` records) is written to
//!   the audit file only, never to stderr ([`Sink`]). With those and one
//!   revealed plaintext, an offline master-password search costs exactly
//!   what an attack on the vault file costs, so the audit file is as
//!   sensitive as the vault; stderr, which MCP hosts often surface, carries
//!   no such material. Without an audit file the key is not derived at all.
//! - The master password and unlock-command output never appear anywhere.
//!
//! Deferred beyond v0.1: debug/trace JSON-RPC payload capture (the spec's
//! `tool_call` and `mcp_message` events). Those events were never wired into a
//! call site. The actual leak risk (rmcp Debug-logging raw JSON-RPC payloads
//! that contain secrets) is prevented in `main.rs` by capping rmcp's tracing
//! verbosity, not by emitting redacted copies of those payloads here. If the
//! capture is added later, it must restore a redaction layer before logging.

use crate::engine::error::ErrorCode;
use crate::engine::unlock::UnlockSource;
use crate::engine::vault::{LockReason, UnreadableReason};
use crate::engine::vault_file::{LockUnavailable, SaveStep};
use kdbx_core::fingerprint::{
    DeriveParams, Domain, Fingerprint, FingerprintKey, KdfError, KeyMaterial,
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::fs::File;
use std::io::Write;
use std::sync::Mutex;

/// Severity level, shared by audit events and the `KDBX_LOG_LEVEL` setting.
///
/// The variants are declared least verbose first, so the derived `Ord` is the
/// verbosity order: an event is emitted when `event.level() <= configured`.
/// The wire and config spelling is the lowercase variant name, via serde (the
/// envelope's `level` field, and [`Level::from_str`] for the env var), so
/// there is no string table to keep in step.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Default,
    serde::Serialize,
    serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    Error,
    Warn,
    /// The default level. Captures lifecycle and reveal events.
    #[default]
    Info,
    Debug,
    Trace,
}

impl std::str::FromStr for Level {
    type Err = serde::de::value::Error;

    /// Parse the lowercase level name (case-sensitive). Anything else is an
    /// error, so a misspelled `KDBX_LOG_LEVEL` does not silently default.
    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        use serde::de::IntoDeserializer;
        Level::deserialize(raw.into_deserializer())
    }
}

/// Which write tool staged a change (the `write_staged` event's `tool`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WriteTool {
    KdbxAddEntry,
    KdbxUpdateField,
}

/// Why the stage was discarded (the `stage_discarded` event's `reason`). A
/// lock also drops the stage, but that is reported as `vault_locked` with a
/// [`LockReason`]; this event covers the explicit tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StageDiscardReason {
    /// `kdbx_discard_pending`.
    Manual,
}

/// The stable audit fingerprint key, with what it was derived with.
///
/// The only way to build one is [`AuditKey::derive`], which runs Argon2id
/// over the vault's key material, and the only way to build a
/// [`KeyedFingerprint`] (what an audit event carries) is
/// [`AuditKey::fingerprint`]. So an audit event cannot carry a fingerprint
/// computed under the random session key, and a session-keyed
/// [`Fingerprint`] (what tool responses carry) cannot be passed where an
/// audit fingerprint is expected. Opaque: the key never leaves this value,
/// and it is zeroized on drop.
pub struct AuditKey {
    key: FingerprintKey,
    derivation: AuditKeyDerivation,
}

impl AuditKey {
    /// Derive the key with `FingerprintKey::derive` (Argon2id) from
    /// `material`, salted with `salt`, at `params`. Runs the KDF.
    pub fn derive(
        material: &KeyMaterial<'_>,
        salt: uuid::Uuid,
        params: DeriveParams,
    ) -> Result<AuditKey, KdfError> {
        Ok(AuditKey {
            key: FingerprintKey::derive(material, salt, &params)?,
            derivation: AuditKeyDerivation { params, salt },
        })
    }

    /// What the key was derived with (for `vault_unlocked`'s file copy).
    pub fn derivation(&self) -> AuditKeyDerivation {
        self.derivation
    }

    /// The audit fingerprint of `bytes` in `domain`.
    pub fn fingerprint(&self, domain: Domain, bytes: &[u8]) -> KeyedFingerprint {
        KeyedFingerprint {
            domain,
            fingerprint: self.key.fingerprint(domain, bytes),
        }
    }
}

/// A fingerprint under the stable audit key, together with the kdbx-core
/// domain it was computed in.
///
/// Built only by [`AuditKey::fingerprint`] (the fields are private), so the
/// key is always the audit key and the recorded domain is the one actually
/// used. An event renders it, in the audit file only, as `fingerprint` (64
/// lowercase hex) and `fingerprint_domain` (the domain's versioned label,
/// `kdbx-core/field/v1` or `kdbx-core/attachment/v1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyedFingerprint {
    domain: Domain,
    fingerprint: Fingerprint,
}

impl KeyedFingerprint {
    /// The domain the fingerprint separates (field value, attachment bytes).
    pub fn domain(&self) -> Domain {
        self.domain
    }

    /// The fingerprint itself.
    pub fn fingerprint(&self) -> Fingerprint {
        self.fingerprint
    }

    /// The 64-character lowercase hex form, as logged.
    pub fn to_hex(&self) -> String {
        self.fingerprint.to_hex()
    }
}

/// What the stable audit key was derived with: the inputs, besides the vault's
/// key material, a verifier needs to rebuild it (`vault_unlocked` records
/// them in the audit file).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditKeyDerivation {
    /// The Argon2id parameters (rendered `argon2id$v=19$m=..,t=..,p=..`).
    pub params: DeriveParams,
    /// The salt: the vault's root group UUID.
    pub salt: uuid::Uuid,
}

/// Where a rendered event goes. Fields derived from the stable audit key are
/// rendered for [`Sink::File`] only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sink {
    /// stderr: diagnostics an MCP host may show or collect.
    Stderr,
    /// The `KDBX_LOG_FILE` audit log, protected like the vault.
    File,
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
    /// A vault was unlocked. When the stable audit key was derived (an audit
    /// file is configured), the file copy also records `fingerprint_params`
    /// and `fingerprint_salt` from `audit_key`, what a verifier needs to
    /// rebuild the key from the vault's key material.
    VaultUnlocked {
        unlock_source: UnlockSource,
        file_mtime: String,
        audit_key: Option<AuditKeyDerivation>,
    },
    /// A vault was locked (idle, explicit, or shutdown).
    VaultLocked {
        reason: LockReason,
        pending_discarded_count: u64,
    },
    /// An unlock failed with `VAULT_UNREADABLE`: the vault file is not a
    /// readable KDBX database (found before any key was checked), or, with
    /// `reason` `kdf_parameters_unsupported`, the key was right but the
    /// vault's KDF parameters cannot derive the audit key. Distinct from
    /// `auth_failed`, which is a wrong key. `reason` is null only if the
    /// error carried none, which the vault never does.
    UnlockFailed {
        unlock_source: UnlockSource,
        reason: Option<UnreadableReason>,
    },
    /// Authentication failed. `source` matches the unlock source that failed.
    AuthFailed {
        source: UnlockSource,
        error_code: ErrorCode,
    },
    /// A write was staged into the working database (not yet on disk).
    WriteStaged {
        tool: WriteTool,
        target_path: Option<String>,
        target_uuid: String,
        /// Present only for field-level writes; null otherwise.
        field_name: Option<String>,
    },
    /// The pending stage was discarded. `summary` carries paths only, no values.
    StageDiscarded {
        reason: StageDiscardReason,
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
    /// Save failed mid-flight. `failure_step` names where it stopped (null
    /// only if the error carried no step, which the save path never does).
    SaveFailed {
        failure_step: Option<SaveStep>,
        error_message: String,
        pending_changes: u64,
    },
    /// A password field was revealed. `fingerprint` is the audit-keyed
    /// fingerprint of the value (domain `kdbx-core/field/v1`), present when
    /// the audit key exists and rendered to the audit file only.
    RevealPassword {
        target_path: Option<String>,
        target_uuid: String,
        fingerprint: Option<KeyedFingerprint>,
    },
    /// A non-password secret field was revealed.
    RevealProtected {
        target_path: Option<String>,
        target_uuid: String,
        field_name: String,
        fingerprint: Option<KeyedFingerprint>,
    },
    /// An attachment was downloaded. `fingerprint` is the audit-keyed
    /// fingerprint of its bytes (domain `kdbx-core/attachment/v1`). It
    /// identifies which attachment was taken without storing its content.
    /// (Tool responses carry a different, session-keyed fingerprint.)
    DownloadAttachment {
        target_path: Option<String>,
        target_uuid: String,
        attachment_name: String,
        size_bytes: u64,
        fingerprint: Option<KeyedFingerprint>,
    },
    /// A save proceeded without the inter-instance writer lock because the
    /// filesystem cannot lock (the content check still ran).
    WriterLockUnavailable { reason: LockUnavailable },
    /// A TOTP code was computed. The code itself is never logged.
    GetOtp {
        target_path: Option<String>,
        target_uuid: String,
        /// The `time_unix` the caller asked for, or `None` for "now".
        requested_time_unix: Option<u64>,
        /// The time the code was computed at, after clamping the request to
        /// now plus or minus one period.
        time_unix: u64,
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
            AuditEvent::UnlockFailed { .. } => "unlock_failed",
            AuditEvent::WriteStaged { .. } => "write_staged",
            AuditEvent::StageDiscarded { .. } => "stage_discarded",
            AuditEvent::SaveCommitted { .. } => "save_committed",
            AuditEvent::SaveRefused { .. } => "save_refused",
            AuditEvent::SaveFailed { .. } => "save_failed",
            AuditEvent::RevealPassword { .. } => "reveal_password",
            AuditEvent::RevealProtected { .. } => "reveal_protected",
            AuditEvent::DownloadAttachment { .. } => "download_attachment",
            AuditEvent::GetOtp { .. } => "get_otp",
            AuditEvent::WriterLockUnavailable { .. } => "writer_lock_unavailable",
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
            AuditEvent::UnlockFailed { .. } => Level::Warn,
            AuditEvent::WriteStaged { .. } => Level::Info,
            AuditEvent::StageDiscarded { .. } => Level::Info,
            AuditEvent::SaveCommitted { .. } => Level::Info,
            AuditEvent::SaveRefused { .. } => Level::Warn,
            AuditEvent::SaveFailed { .. } => Level::Error,
            AuditEvent::RevealPassword { .. } => Level::Info,
            AuditEvent::RevealProtected { .. } => Level::Info,
            AuditEvent::DownloadAttachment { .. } => Level::Info,
            AuditEvent::GetOtp { .. } => Level::Info,
            AuditEvent::WriterLockUnavailable { .. } => Level::Warn,
        }
    }

    /// The event-specific `details` payload for `sink`, as a JSON object.
    /// Pure and testable: it never reads the clock, the pid, or the
    /// environment. Audit-key fields are added for [`Sink::File`] only.
    pub fn details_json(&self, sink: Sink) -> Value {
        let mut details = self.public_details();
        if sink == Sink::File
            && let (Value::Object(map), Value::Object(keyed)) =
                (&mut details, self.audit_key_details())
        {
            map.extend(keyed);
        }
        details
    }

    /// The fields derived from the stable audit key: the fingerprint of a
    /// revealed value with its domain, or the key's derivation inputs. An
    /// empty object when the event has none or the key was not derived.
    fn audit_key_details(&self) -> Value {
        let fingerprint = |fp: &Option<KeyedFingerprint>| match fp {
            Some(fp) => json!({
                "fingerprint": fp.to_hex(),
                "fingerprint_domain": fp.domain.label(),
            }),
            None => json!({}),
        };
        match self {
            AuditEvent::VaultUnlocked {
                audit_key: Some(derivation),
                ..
            } => json!({
                "fingerprint_params": derivation.params.to_string(),
                "fingerprint_salt": derivation.salt.to_string(),
            }),
            AuditEvent::RevealPassword {
                fingerprint: fp, ..
            }
            | AuditEvent::RevealProtected {
                fingerprint: fp, ..
            }
            | AuditEvent::DownloadAttachment {
                fingerprint: fp, ..
            } => fingerprint(fp),
            _ => json!({}),
        }
    }

    /// The fields every sink gets.
    fn public_details(&self) -> Value {
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
                ..
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
                ..
            } => json!({
                "target_path": target_path,
                "target_uuid": target_uuid,
            }),
            AuditEvent::RevealProtected {
                target_path,
                target_uuid,
                field_name,
                ..
            } => json!({
                "target_path": target_path,
                "target_uuid": target_uuid,
                "field_name": field_name,
            }),
            AuditEvent::DownloadAttachment {
                target_path,
                target_uuid,
                attachment_name,
                size_bytes,
                ..
            } => json!({
                "target_path": target_path,
                "target_uuid": target_uuid,
                "attachment_name": attachment_name,
                "size_bytes": size_bytes,
            }),
            AuditEvent::WriterLockUnavailable { reason } => json!({ "reason": reason }),
            AuditEvent::UnlockFailed {
                unlock_source,
                reason,
            } => json!({
                "unlock_source": unlock_source,
                "reason": reason,
            }),
            AuditEvent::GetOtp {
                target_path,
                target_uuid,
                requested_time_unix,
                time_unix,
            } => json!({
                "target_path": target_path,
                "target_uuid": target_uuid,
                "requested_time_unix": requested_time_unix,
                "time_unix": time_unix,
            }),
        }
    }

    /// Build the full envelope with an injected `timestamp` (RFC3339 string)
    /// and `pid`. Keeping these as arguments makes the rendering deterministic
    /// in tests; the runtime path supplies the real clock and pid.
    pub fn envelope(&self, timestamp: &str, pid: u32, sink: Sink) -> Value {
        json!({
            "timestamp": timestamp,
            "level": self.level(),
            "event": self.event(),
            "pid": pid,
            "details": self.details_json(sink),
        })
    }
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

    /// Whether an audit file is configured: only then is the stable audit
    /// key worth deriving, since its fingerprints are written nowhere else.
    pub fn has_file(&self) -> bool {
        self.file.is_some()
    }

    /// Render `event` once per sink and emit it: the stderr rendering to
    /// stderr, the file rendering (with the audit-key fields) to the file.
    ///
    /// The timestamp is stamped here as `chrono::Utc::now()` in RFC3339 form
    /// and the pid as `std::process::id()`. Tests that need determinism call
    /// [`AuditEvent::envelope`] directly with injected values instead.
    pub fn write(&self, event: &AuditEvent) {
        let timestamp = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let pid = std::process::id();
        // stderr first so the record is visible even if the file write fails.
        let mut stderr = std::io::stderr();
        let _ = writeln!(stderr, "{}", event.envelope(&timestamp, pid, Sink::Stderr));
        if let Some(file) = &self.file
            && let Ok(mut handle) = file.lock()
        {
            let _ = writeln!(handle, "{}", event.envelope(&timestamp, pid, Sink::File));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fixed fingerprint for the pinned envelopes: all bytes 0xab.
    fn fixed(domain: Domain) -> KeyedFingerprint {
        KeyedFingerprint {
            domain,
            fingerprint: Fingerprint::from_bytes([0xab; 32]),
        }
    }

    const FIXED_HEX: &str = "abababababababababababababababababababababababababababababababab";

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
                    unlock_source: UnlockSource::Env,
                    file_mtime: "2026-05-08T10:00:00Z".to_string(),
                    audit_key: Some(AuditKeyDerivation {
                        params: DeriveParams::FLOOR,
                        salt: uuid::Uuid::from_u128(0x0123_4567_89ab_cdef_0123_4567_89ab_cdef),
                    }),
                },
                "vault_unlocked",
                Level::Info,
            ),
            (
                AuditEvent::VaultLocked {
                    reason: LockReason::IdleTimeout,
                    pending_discarded_count: 0,
                },
                "vault_locked",
                Level::Info,
            ),
            (
                AuditEvent::AuthFailed {
                    source: UnlockSource::Cmd,
                    error_code: ErrorCode::AuthFailed,
                },
                "auth_failed",
                Level::Error,
            ),
            (
                AuditEvent::WriteStaged {
                    tool: WriteTool::KdbxUpdateField,
                    target_path: Some("/Web/GitHub".to_string()),
                    target_uuid: "abcd".to_string(),
                    field_name: Some("Password".to_string()),
                },
                "write_staged",
                Level::Info,
            ),
            (
                AuditEvent::StageDiscarded {
                    reason: StageDiscardReason::Manual,
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
                    failure_step: Some(SaveStep::Rename),
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
                    fingerprint: Some(fixed(Domain::Field)),
                },
                "reveal_password",
                Level::Info,
            ),
            (
                AuditEvent::RevealProtected {
                    target_path: Some("/Web/GitHub".to_string()),
                    target_uuid: "abcd".to_string(),
                    field_name: "RecoveryKey".to_string(),
                    fingerprint: Some(fixed(Domain::Field)),
                },
                "reveal_protected",
                Level::Info,
            ),
            (
                AuditEvent::DownloadAttachment {
                    target_path: Some("/Web/GitHub".to_string()),
                    target_uuid: "abcd".to_string(),
                    attachment_name: "key.pem".to_string(),
                    size_bytes: 2048,
                    fingerprint: Some(fixed(Domain::Attachment)),
                },
                "download_attachment",
                Level::Info,
            ),
            (
                AuditEvent::GetOtp {
                    target_path: Some("/Web/GitHub".to_string()),
                    target_uuid: "abcd".to_string(),
                    requested_time_unix: None,
                    time_unix: 1_700_000_000,
                },
                "get_otp",
                Level::Info,
            ),
            (
                AuditEvent::UnlockFailed {
                    unlock_source: UnlockSource::Input,
                    reason: Some(UnreadableReason::NotKdbx),
                },
                "unlock_failed",
                Level::Warn,
            ),
            (
                AuditEvent::WriterLockUnavailable {
                    reason: LockUnavailable::NoLocks,
                },
                "writer_lock_unavailable",
                Level::Warn,
            ),
        ]
    }

    /// The exact JSONL line each event renders to, pinned. The audit log is a
    /// durable on-disk format that operators grep and parse; any change to a
    /// key, a value spelling, or a type here is a format break and must be
    /// deliberate.
    const PINNED_ENVELOPES: &[&str] = &[
        r#"{"details":{"idle_timeout_seconds":900,"server_version":"0.1.0","vault_path":"/vault.kdbx","writes_allowed":false},"event":"server_started","level":"info","pid":42,"timestamp":"2026-01-01T00:00:00Z"}"#,
        r#"{"details":{"file_mtime":"2026-05-08T10:00:00Z","fingerprint_params":"argon2id$v=19$m=65536,t=3,p=1","fingerprint_salt":"01234567-89ab-cdef-0123-456789abcdef","unlock_source":"env"},"event":"vault_unlocked","level":"info","pid":42,"timestamp":"2026-01-01T00:00:00Z"}"#,
        r#"{"details":{"pending_discarded_count":0,"reason":"idle_timeout"},"event":"vault_locked","level":"info","pid":42,"timestamp":"2026-01-01T00:00:00Z"}"#,
        r#"{"details":{"error_code":"AUTH_FAILED","source":"cmd"},"event":"auth_failed","level":"error","pid":42,"timestamp":"2026-01-01T00:00:00Z"}"#,
        r#"{"details":{"field_name":"Password","target_path":"/Web/GitHub","target_uuid":"abcd","tool":"kdbx_update_field"},"event":"write_staged","level":"info","pid":42,"timestamp":"2026-01-01T00:00:00Z"}"#,
        r#"{"details":{"num_dropped":2,"reason":"manual","summary":["/Web/GitHub","/Web/GitLab"]},"event":"stage_discarded","level":"info","pid":42,"timestamp":"2026-01-01T00:00:00Z"}"#,
        r#"{"details":{"after_mtime":"2026-05-08T10:01:00Z","before_mtime":"2026-05-08T10:00:00Z","num_changes":1},"event":"save_committed","level":"info","pid":42,"timestamp":"2026-01-01T00:00:00Z"}"#,
        r#"{"details":{"before_mtime":"2026-05-08T10:00:00Z","conflict_mtime":"2026-05-08T10:00:30Z","pending_changes":1},"event":"save_refused","level":"warn","pid":42,"timestamp":"2026-01-01T00:00:00Z"}"#,
        r#"{"details":{"error_message":"disk full","failure_step":"rename","pending_changes":1},"event":"save_failed","level":"error","pid":42,"timestamp":"2026-01-01T00:00:00Z"}"#,
        r#"{"details":{"fingerprint":"abababababababababababababababababababababababababababababababab","fingerprint_domain":"kdbx-core/field/v1","target_path":"/Web/GitHub","target_uuid":"abcd"},"event":"reveal_password","level":"info","pid":42,"timestamp":"2026-01-01T00:00:00Z"}"#,
        r#"{"details":{"field_name":"RecoveryKey","fingerprint":"abababababababababababababababababababababababababababababababab","fingerprint_domain":"kdbx-core/field/v1","target_path":"/Web/GitHub","target_uuid":"abcd"},"event":"reveal_protected","level":"info","pid":42,"timestamp":"2026-01-01T00:00:00Z"}"#,
        r#"{"details":{"attachment_name":"key.pem","fingerprint":"abababababababababababababababababababababababababababababababab","fingerprint_domain":"kdbx-core/attachment/v1","size_bytes":2048,"target_path":"/Web/GitHub","target_uuid":"abcd"},"event":"download_attachment","level":"info","pid":42,"timestamp":"2026-01-01T00:00:00Z"}"#,
        r#"{"details":{"requested_time_unix":null,"target_path":"/Web/GitHub","target_uuid":"abcd","time_unix":1700000000},"event":"get_otp","level":"info","pid":42,"timestamp":"2026-01-01T00:00:00Z"}"#,
        r#"{"details":{"reason":"not_kdbx","unlock_source":"input"},"event":"unlock_failed","level":"warn","pid":42,"timestamp":"2026-01-01T00:00:00Z"}"#,
        r#"{"details":{"reason":"no_locks"},"event":"writer_lock_unavailable","level":"warn","pid":42,"timestamp":"2026-01-01T00:00:00Z"}"#,
    ];

    #[test]
    fn envelopes_render_to_the_pinned_jsonl() {
        let events = all_events();
        assert_eq!(events.len(), PINNED_ENVELOPES.len());
        for ((event, name, _), pinned) in events.iter().zip(PINNED_ENVELOPES) {
            assert_eq!(
                event
                    .envelope("2026-01-01T00:00:00Z", 42, Sink::File)
                    .to_string(),
                *pinned,
                "{name} drifted from the pinned audit format"
            );
        }
    }

    /// The stderr renderings of the events that carry audit-key fields: the
    /// same envelopes minus every such field, pinned like the file ones.
    const PINNED_STDERR: &[(&str, &str)] = &[
        (
            "vault_unlocked",
            r#"{"details":{"file_mtime":"2026-05-08T10:00:00Z","unlock_source":"env"},"event":"vault_unlocked","level":"info","pid":42,"timestamp":"2026-01-01T00:00:00Z"}"#,
        ),
        (
            "reveal_password",
            r#"{"details":{"target_path":"/Web/GitHub","target_uuid":"abcd"},"event":"reveal_password","level":"info","pid":42,"timestamp":"2026-01-01T00:00:00Z"}"#,
        ),
        (
            "reveal_protected",
            r#"{"details":{"field_name":"RecoveryKey","target_path":"/Web/GitHub","target_uuid":"abcd"},"event":"reveal_protected","level":"info","pid":42,"timestamp":"2026-01-01T00:00:00Z"}"#,
        ),
        (
            "download_attachment",
            r#"{"details":{"attachment_name":"key.pem","size_bytes":2048,"target_path":"/Web/GitHub","target_uuid":"abcd"},"event":"download_attachment","level":"info","pid":42,"timestamp":"2026-01-01T00:00:00Z"}"#,
        ),
    ];

    #[test]
    fn stderr_never_carries_audit_key_material() {
        for (event, name, _) in all_events() {
            let stderr = event
                .envelope("2026-01-01T00:00:00Z", 42, Sink::Stderr)
                .to_string();
            assert!(!stderr.contains("fingerprint"), "{name}: {stderr}");
            assert!(!stderr.contains("argon2id"), "{name}: {stderr}");
            assert!(!stderr.contains("01234567-89ab"), "{name}: {stderr}");
            match PINNED_STDERR.iter().find(|(n, _)| *n == name) {
                Some((_, pinned)) => assert_eq!(stderr, *pinned, "{name} stderr drifted"),
                // Every other event renders the same for both sinks.
                None => assert_eq!(
                    stderr,
                    event
                        .envelope("2026-01-01T00:00:00Z", 42, Sink::File)
                        .to_string(),
                    "{name}"
                ),
            }
        }
    }

    #[test]
    fn without_an_audit_key_the_file_gets_no_fingerprint_fields() {
        let reveal = AuditEvent::RevealPassword {
            target_path: None,
            target_uuid: "u".to_string(),
            fingerprint: None,
        };
        let unlocked = AuditEvent::VaultUnlocked {
            unlock_source: UnlockSource::Env,
            file_mtime: String::new(),
            audit_key: None,
        };
        for event in [reveal, unlocked] {
            let file = event.details_json(Sink::File);
            assert_eq!(file, event.details_json(Sink::Stderr));
            assert!(!file.to_string().contains("fingerprint"));
        }
    }

    #[test]
    fn level_wire_strings_parse_and_order() {
        let all = [
            (Level::Error, "error"),
            (Level::Warn, "warn"),
            (Level::Info, "info"),
            (Level::Debug, "debug"),
            (Level::Trace, "trace"),
        ];
        for (level, name) in all {
            assert_eq!(serde_json::to_value(level).unwrap(), json!(name));
            assert_eq!(name.parse::<Level>().unwrap(), level);
        }
        assert!("INFO".parse::<Level>().is_err());
        assert!("verbose".parse::<Level>().is_err());
        // Declaration order is verbosity order.
        assert!(Level::Error < Level::Warn && Level::Warn < Level::Info);
        assert!(Level::Info < Level::Debug && Level::Debug < Level::Trace);
        assert_eq!(Level::default(), Level::Info);
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
        let env = event.envelope("2026-05-08T10:00:00Z", 12345, Sink::File);
        let obj = env.as_object().unwrap();
        // Exactly the five envelope fields from spec section 6, no more.
        assert_eq!(obj.len(), 5);
        assert_eq!(obj["timestamp"], json!("2026-05-08T10:00:00Z"));
        assert_eq!(obj["level"], json!(level));
        assert_eq!(obj["event"], json!(name));
        assert_eq!(obj["pid"], json!(12345));
        assert!(obj["details"].is_object());
    }

    #[test]
    fn every_variant_renders_the_envelope_shape() {
        for (event, name, level) in all_events() {
            let env = event.envelope("2026-05-08T10:00:00Z", 999, Sink::Stderr);
            assert_eq!(env["timestamp"], json!("2026-05-08T10:00:00Z"));
            assert_eq!(env["level"], json!(level));
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
            tool: WriteTool::KdbxAddEntry,
            target_path: Some("/Web/New".to_string()),
            target_uuid: "uuid-1".to_string(),
            field_name: None,
        };
        let d = staged.details_json(Sink::File);
        assert_eq!(d["tool"], json!("kdbx_add_entry"));
        assert_eq!(d["target_path"], json!("/Web/New"));
        assert_eq!(d["target_uuid"], json!("uuid-1"));
        assert_eq!(d["field_name"], Value::Null);

        let reveal = AuditEvent::RevealProtected {
            target_path: Some("/Web/X".to_string()),
            target_uuid: "uuid-2".to_string(),
            field_name: "Secret".to_string(),
            fingerprint: Some(fixed(Domain::Field)),
        };
        let d = reveal.details_json(Sink::File);
        assert_eq!(d["field_name"], json!("Secret"));
        assert_eq!(d["fingerprint"], json!(FIXED_HEX));
        assert_eq!(d["fingerprint_domain"], json!(Domain::Field.label()));
        assert!(d.get("sha256").is_none(), "the unkeyed sha256 is gone");

        let otp = AuditEvent::GetOtp {
            target_path: Some("/Web/X".to_string()),
            target_uuid: "uuid-3".to_string(),
            requested_time_unix: Some(0),
            time_unix: 1_699_999_970,
        };
        let d = otp.details_json(Sink::File);
        // No code field: the OTP value is never logged. The requested and the
        // effective (clamped) evaluation times are.
        assert!(d.get("code").is_none());
        assert_eq!(d["requested_time_unix"], json!(0));
        assert_eq!(d["time_unix"], json!(1_699_999_970));
        assert_eq!(d.as_object().unwrap().len(), 4);
    }

    #[test]
    fn audit_log_constructors_do_not_panic() {
        // Smoke test: stderr-only and file-less constructors build cleanly.
        let _stderr = AuditLog::stderr_only();
        let _none = AuditLog::new(None);
    }
}
