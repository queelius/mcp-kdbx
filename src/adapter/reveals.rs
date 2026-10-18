//! Reveal tools: `kdbx_reveal_password`, `kdbx_reveal_protected`,
//! `kdbx_download_attachment`, `kdbx_get_otp`.
//!
//! These are the consent-gated tools (spec section 1, "Reveals"). Each one
//! crosses a secret out of the vault, so each requires an unlocked vault and
//! emits exactly one info-level audit event on success. The security invariant
//! is that the event carries a sha256 of the revealed value, never the value
//! itself: string secrets hash via [`hash_revealed`] (the domain-separated
//! reveal hash), and an attachment's content sha256 is a plain digest used as a
//! fingerprint. The TOTP secret never leaves the process; only the computed code
//! crosses out, and the `get_otp` event logs no code and no secret.
//!
//! Each tool reads the value into an owned `String` (or `Vec<u8>`) before
//! emitting and returning, so the audit emit and the response do not borrow the
//! vault guard.

use crate::adapter::{KdbxServer, canonical_entry_path, locate_entry, responses};
use crate::kdbx_core::audit::{AuditEvent, hash_revealed};
use crate::kdbx_core::error::{CoreError, ErrorCode};
use base64::Engine;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{schemars, tool, tool_router};

/// Size (in bytes) above which a downloaded attachment gets a warn log entry.
/// It is not a rejection threshold: KDBX places no cap and neither do we (spec
/// section 3, "Attachment semantics"). The warn is operational signal only.
const ATTACHMENT_WARN_BYTES: usize = 10 * 1024 * 1024;

/// Input for `kdbx_reveal_password`: the entry, by path or uuid.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct RevealPasswordParams {
    /// Path to the entry whose `Password` field should be revealed. Give
    /// exactly one of `path` or `uuid`.
    #[serde(default)]
    pub path: Option<String>,
    /// The entry's uuid, as returned by the read tools. Give exactly one of
    /// `path` or `uuid`.
    #[serde(default)]
    pub uuid: Option<String>,
}

/// Input for `kdbx_reveal_protected`: the entry (by path or uuid) and the field
/// name.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct RevealProtectedParams {
    /// Path to the entry that holds the field. Give exactly one of `path` or
    /// `uuid`.
    #[serde(default)]
    pub path: Option<String>,
    /// The entry's uuid. Give exactly one of `path` or `uuid`.
    #[serde(default)]
    pub uuid: Option<String>,
    /// The name of the protected field to reveal.
    pub field_name: String,
}

/// Input for `kdbx_download_attachment`: the entry (by path or uuid) and the
/// attachment name.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct DownloadAttachmentParams {
    /// Path to the entry that references the attachment. Give exactly one of
    /// `entry_path` or `uuid`.
    #[serde(default)]
    pub entry_path: Option<String>,
    /// The entry's uuid. Give exactly one of `entry_path` or `uuid`.
    #[serde(default)]
    pub uuid: Option<String>,
    /// The attachment's per-entry name (its filename key on the entry).
    pub name: String,
}

/// Input for `kdbx_get_otp`: the entry (by path or uuid) and an optional
/// evaluation time.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetOtpParams {
    /// Path to the entry that carries the TOTP configuration. Give exactly one
    /// of `path` or `uuid`.
    #[serde(default)]
    pub path: Option<String>,
    /// The entry's uuid. Give exactly one of `path` or `uuid`.
    #[serde(default)]
    pub uuid: Option<String>,
    /// The Unix time (seconds) at which to compute the code. Defaults to now.
    /// Clamped to now plus or minus one TOTP period (previous, current, or
    /// next code); the response's `time_unix` is the time actually used.
    #[serde(default)]
    pub time_unix: Option<u64>,
}

#[tool_router(router = reveals_router, vis = "pub(crate)")]
impl KdbxServer {
    /// Reveal: return an entry's `Password` field. Consent-gated; logs a sha256
    /// of the value, never the value.
    #[tool(
        description = "Reveal the Password field of an entry. This is a consent-gated secret access: it returns the plaintext password and records an audit event with a sha256 of the value (never the value itself). Requires an unlocked vault."
    )]
    async fn kdbx_reveal_password(
        &self,
        Parameters(params): Parameters<RevealPasswordParams>,
    ) -> String {
        let mut vault = self.vault().await;
        if !vault.is_unlocked() {
            return responses::err(&responses::locked_error(vault.take_last_lock()));
        }
        let db = match vault.working_db() {
            Ok(db) => db,
            Err(e) => return responses::err(&e),
        };

        let entry = match locate_entry(db, params.path.as_deref(), params.uuid.as_deref(), "path") {
            Ok(e) => e,
            Err(e) => return responses::err(&e),
        };
        let target_path = canonical_entry_path(db, &entry);

        // Read the value into an owned String before emitting and returning, so
        // we do not hold a borrow into the db across the audit emit.
        let password = match entry.get("Password") {
            Some(v) => v.to_string(),
            None => {
                return responses::err(
                    &CoreError::new(ErrorCode::FieldNotFound)
                        .with_message("entry has no Password field"),
                );
            }
        };
        let target_uuid = entry.id().uuid().to_string();

        self.emit(AuditEvent::RevealPassword {
            target_path,
            target_uuid,
            sha256: hash_revealed(&password),
        });

        responses::ok(serde_json::json!({ "password": password }))
    }

    /// Reveal: return a named protected field's value. A non-protected field is
    /// refused with `FIELD_NOT_PROTECTED`; the agent should read it with a list
    /// or get tool instead. Consent-gated; logs a sha256 of the value.
    #[tool(
        description = "Reveal the value of a named protected field on an entry. Refuses non-protected fields with FIELD_NOT_PROTECTED (read those with a list or get tool instead). Records an audit event with a sha256 of the value, never the value. Requires an unlocked vault."
    )]
    async fn kdbx_reveal_protected(
        &self,
        Parameters(params): Parameters<RevealProtectedParams>,
    ) -> String {
        let mut vault = self.vault().await;
        if !vault.is_unlocked() {
            return responses::err(&responses::locked_error(vault.take_last_lock()));
        }
        let db = match vault.working_db() {
            Ok(db) => db,
            Err(e) => return responses::err(&e),
        };

        let entry = match locate_entry(db, params.path.as_deref(), params.uuid.as_deref(), "path") {
            Ok(e) => e,
            Err(e) => return responses::err(&e),
        };
        let target_path = canonical_entry_path(db, &entry);

        // Look the field up directly so we can distinguish "no such field"
        // (FIELD_NOT_FOUND) from "present but not protected" (FIELD_NOT_PROTECTED).
        let field = match entry.fields.get(&params.field_name) {
            Some(v) => v,
            None => {
                return responses::err(
                    &CoreError::new(ErrorCode::FieldNotFound)
                        .with_message("entry has no field by that name")
                        .with_details(serde_json::json!({ "field_name": params.field_name })),
                );
            }
        };
        if !field.is_protected() {
            return responses::err(
                &CoreError::new(ErrorCode::FieldNotProtected)
                    .with_details(serde_json::json!({ "field_name": params.field_name })),
            );
        }
        let value = field.get().to_string();
        let target_uuid = entry.id().uuid().to_string();

        self.emit(AuditEvent::RevealProtected {
            target_path,
            target_uuid,
            field_name: params.field_name.clone(),
            sha256: hash_revealed(&value),
        });

        responses::ok(serde_json::json!({ "value": value }))
    }

    /// Reveal: return an attachment's bytes, base64-encoded, with its size and a
    /// content sha256. Consent-gated; logs the content sha256 (a plain digest,
    /// not the reveal hash, since this fingerprints bytes rather than a string).
    #[tool(
        description = "Download an entry's attachment by name: returns the bytes base64-encoded, plus size_bytes and a sha256 content fingerprint. There is no size cap; attachments over 10 MB are logged at warn but still returned. Records an audit event with the content sha256. Requires an unlocked vault."
    )]
    async fn kdbx_download_attachment(
        &self,
        Parameters(params): Parameters<DownloadAttachmentParams>,
    ) -> String {
        let mut vault = self.vault().await;
        if !vault.is_unlocked() {
            return responses::err(&responses::locked_error(vault.take_last_lock()));
        }
        let db = match vault.working_db() {
            Ok(db) => db,
            Err(e) => return responses::err(&e),
        };

        let entry = match locate_entry(
            db,
            params.entry_path.as_deref(),
            params.uuid.as_deref(),
            "entry_path",
        ) {
            Ok(e) => e,
            Err(e) => return responses::err(&e),
        };
        let target_path = canonical_entry_path(db, &entry);

        // Find the attachment by its per-entry name, reading the bytes into an
        // owned Vec so the response and emit do not borrow the db.
        let bytes: Vec<u8> = match entry
            .attachments_named()
            .find(|(name, _)| *name == params.name)
        {
            Some((_, attachment)) => attachment.get().clone(),
            None => {
                return responses::err(
                    &CoreError::new(ErrorCode::AttachmentNotFound)
                        .with_message("entry has no attachment by that name")
                        .with_details(serde_json::json!({ "name": params.name })),
                );
            }
        };

        let size_bytes = bytes.len();
        if size_bytes > ATTACHMENT_WARN_BYTES {
            tracing::warn!(
                attachment = %params.name,
                size_bytes,
                "downloading an attachment larger than 10 MB"
            );
        }
        // The content sha256 is a plain digest fingerprint of the bytes (spec
        // section 1: the download_attachment event carries the content sha256),
        // not the domain-separated reveal hash, which is for string secrets.
        let content_sha256 = crate::adapter::views::sha256_hex(&bytes);
        let base64 = base64::engine::general_purpose::STANDARD.encode(&bytes);

        self.emit(AuditEvent::DownloadAttachment {
            target_path,
            attachment_name: params.name.clone(),
            size_bytes: size_bytes as u64,
            sha256: content_sha256.clone(),
        });

        responses::ok(serde_json::json!({
            "name": params.name,
            "size_bytes": size_bytes,
            "sha256": content_sha256,
            "base64": base64,
        }))
    }

    /// Reveal: compute the current TOTP code for an entry. Prefers the modern
    /// `otp` field (an otpauth URI), falling back to the legacy
    /// `TOTP Seed`/`TOTP Settings` pair. The secret never leaves the process;
    /// only the code crosses out, and the audit event logs no code.
    #[tool(
        description = "Compute the current TOTP code for an entry. Reads the modern otp field (otpauth URI) or the legacy TOTP Seed and TOTP Settings pair. Returns the code with its remaining validity, period, and the time_unix it was computed at (an optional time_unix is clamped to now plus or minus one period). The TOTP secret never leaves the process and is never logged; the audit event records no code. Requires an unlocked vault."
    )]
    async fn kdbx_get_otp(&self, Parameters(params): Parameters<GetOtpParams>) -> String {
        let mut vault = self.vault().await;
        if !vault.is_unlocked() {
            return responses::err(&responses::locked_error(vault.take_last_lock()));
        }
        let db = match vault.working_db() {
            Ok(db) => db,
            Err(e) => return responses::err(&e),
        };

        let entry = match locate_entry(db, params.path.as_deref(), params.uuid.as_deref(), "path") {
            Ok(e) => e,
            Err(e) => return responses::err(&e),
        };
        let target_path = canonical_entry_path(db, &entry);

        // Resolve a config (modern otpauth field, then the legacy pair) through
        // the shared resolver, the same one the read views use for has_otp, so
        // the capability flag and this computation cannot drift. The config
        // holds the secret; it stays in this scope and never crosses out.
        let config = match crate::kdbx_core::totp::resolve_config(
            entry.get("otp"),
            entry.get("TOTP Seed"),
            entry.get("TOTP Settings"),
        ) {
            Some(c) => c,
            None => return responses::err(&ErrorCode::NoOtpConfigured.into()),
        };

        // A requested time is clamped to now plus or minus one period, so only
        // the previous, current, or next code can ever cross out.
        let time_unix =
            config.evaluation_time(params.time_unix, crate::kdbx_core::totp::unix_now());
        let code = config.compute_at(time_unix);
        let target_uuid = entry.id().uuid().to_string();

        // The event records the access and both times, never the code or the
        // secret.
        self.emit(AuditEvent::GetOtp {
            target_path,
            target_uuid,
            requested_time_unix: params.time_unix,
            time_unix,
        });

        responses::ok(serde_json::json!({
            "code": code.code.expose(),
            "valid_for_seconds": code.valid_for_seconds,
            "period_seconds": code.period_seconds,
            "time_unix": time_unix,
        }))
    }
}
