//! Write and stage tools: `kdbx_add_entry`, `kdbx_update_field`,
//! `kdbx_diff_pending`, `kdbx_save_pending`, `kdbx_discard_pending`.
//!
//! These are the write side of the stage-then-commit model (spec sections 3 and
//! 4). Every write tool checks the `KDBX_ALLOW_WRITES` gate first and returns
//! `WRITES_DISABLED` before touching the vault, then requires an unlocked vault
//! (`VAULT_LOCKED`). Writes mutate the working db only; nothing reaches disk
//! until `kdbx_save_pending`. The actual mutation, diffing, and atomic save live
//! in `kdbx_core::stage`; this module is the thin adapter that converts the MCP
//! tool inputs into core calls, emits the right audit event, and wraps results
//! in the `{ ok, data } | { ok, error }` envelope.
//!
//! The MCP input for `kdbx_add_entry` carries fields and attachments as maps
//! (`{ name: { value, protected } }` and `{ name: { base64 } }`), matching the
//! spec's JSON shape. We convert those maps into the ordered `Vec` inputs the
//! stage API expects, decoding each attachment's base64 here in the adapter (the
//! stage module takes raw bytes, not base64).

use crate::adapter::{KdbxServer, responses};
use crate::kdbx_core::audit::AuditEvent;
use crate::kdbx_core::error::{CoreError, ErrorCode};
use crate::kdbx_core::path::{VaultPath, vault_path_to_entry};
use crate::kdbx_core::stage;
use base64::Engine;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{schemars, tool, tool_router};
use std::collections::HashMap;

/// One field on a new entry in the `kdbx_add_entry` input map: a value and its
/// protection flag. Keyed by field name in the surrounding map.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
pub struct FieldSpec {
    /// The field value. Stored protected or not per `protected`.
    pub value: String,
    /// Whether to store the field as a protected (encrypted-at-rest) value.
    pub protected: bool,
}

/// One attachment on a new entry in the `kdbx_add_entry` input map: the content
/// as base64. Keyed by attachment name in the surrounding map.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
pub struct AttachmentSpec {
    /// The attachment bytes, base64-encoded (standard alphabet).
    pub base64: String,
}

/// Input for `kdbx_add_entry`: a destination group, a title, and optional
/// field and attachment maps.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AddEntryParams {
    /// The group path to add the entry under, for example `/Web/` or `/`.
    pub group_path: String,
    /// The entry title (the Title field).
    pub title: String,
    /// Custom and standard fields, keyed by name. Each carries a value and a
    /// protected flag.
    #[serde(default)]
    pub fields: HashMap<String, FieldSpec>,
    /// Attachments to link to the entry, keyed by name. Each carries base64
    /// content.
    #[serde(default)]
    pub attachments: HashMap<String, AttachmentSpec>,
}

/// Input for `kdbx_update_field`: which entry, which field, and the new value.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct UpdateFieldParams {
    /// The entry path, for example `/Web/GitHub`.
    pub path: String,
    /// The field name to set or change.
    pub field_name: String,
    /// The new value. An empty value clears the field.
    pub value: String,
    /// Force the field's protection state. When omitted, an existing field keeps
    /// its current protection and a new field defaults to unprotected.
    #[serde(default)]
    pub protected: Option<bool>,
}

#[tool_router(router = writes_router, vis = "pub(crate)")]
impl KdbxServer {
    /// Write: stage a new entry under a group. Requires `KDBX_ALLOW_WRITES=true`
    /// and an unlocked vault. The entry is added to the working db only; it
    /// reaches disk on `kdbx_save_pending`.
    #[tool(
        description = "Stage a new entry under a group. Requires writes to be enabled and the vault unlocked. The entry is staged in memory, not written to disk: commit it with kdbx_save_pending. Fields and attachments are optional maps keyed by name."
    )]
    async fn kdbx_add_entry(&self, Parameters(params): Parameters<AddEntryParams>) -> String {
        if !self.writes_allowed() {
            return responses::err(&CoreError::new(ErrorCode::WritesDisabled));
        }

        let mut vault = self.vault().await;
        if !vault.is_unlocked() {
            return responses::err(&CoreError::new(ErrorCode::VaultLocked));
        }

        let group_path = match VaultPath::parse(&params.group_path) {
            Ok(p) => p,
            Err(e) => return responses::err(&e),
        };

        // Convert the field and attachment maps into the ordered Vec inputs the
        // stage API expects. The attachment base64 is decoded here; bad base64 is
        // a FIELD_NAME_INVALID with a clear message rather than a generic error.
        let mut fields: Vec<stage::FieldInput> = params
            .fields
            .into_iter()
            .map(|(name, spec)| stage::FieldInput {
                name,
                value: spec.value,
                protected: spec.protected,
            })
            .collect();
        // Stable order so the staged entry's fields do not depend on HashMap
        // iteration order.
        fields.sort_by(|a, b| a.name.cmp(&b.name));

        let mut attachments: Vec<stage::AttachmentInput> =
            Vec::with_capacity(params.attachments.len());
        let mut attachment_names: Vec<(String, AttachmentSpec)> =
            params.attachments.into_iter().collect();
        attachment_names.sort_by(|a, b| a.0.cmp(&b.0));
        for (name, spec) in attachment_names {
            let bytes = match base64::engine::general_purpose::STANDARD.decode(&spec.base64) {
                Ok(bytes) => bytes,
                Err(_) => {
                    return responses::err(
                        &CoreError::new(ErrorCode::FieldNameInvalid)
                            .with_message(format!("attachment '{name}' is not valid base64"))
                            .with_details(serde_json::json!({ "attachment": name })),
                    );
                }
            };
            attachments.push(stage::AttachmentInput { name, bytes });
        }

        let input = stage::EntryInput {
            title: params.title,
            fields,
            attachments,
        };

        let working = match vault.working_db_mut() {
            Ok(db) => db,
            Err(e) => return responses::err(&e),
        };

        let entry_id = match stage::add_entry(working, &group_path, &input) {
            Ok(id) => id,
            Err(e) => return responses::err(&e),
        };

        // Capture the audit data into owned values before returning. The new
        // entry's path is built from the working db; the uuid comes off the id.
        let path = vault_path_to_entry(working, entry_id)
            .map(|p| p.format())
            .unwrap_or_else(|| group_path.format());
        let uuid = entry_id.uuid().to_string();

        self.emit(AuditEvent::WriteStaged {
            tool: "kdbx_add_entry".to_string(),
            target_path: path.clone(),
            target_uuid: uuid.clone(),
            field_name: None,
        });

        responses::ok(serde_json::json!({
            "staged": true,
            "path": path,
            "uuid": uuid,
        }))
    }

    /// Write: set or change a single field on an existing entry. Requires
    /// `KDBX_ALLOW_WRITES=true` and an unlocked vault. Staged in memory.
    #[tool(
        description = "Set or change a single field on an existing entry. Requires writes to be enabled and the vault unlocked. The change is staged in memory: commit it with kdbx_save_pending. An empty value clears the field. Omit protected to keep an existing field's protection state."
    )]
    async fn kdbx_update_field(&self, Parameters(params): Parameters<UpdateFieldParams>) -> String {
        if !self.writes_allowed() {
            return responses::err(&CoreError::new(ErrorCode::WritesDisabled));
        }

        let mut vault = self.vault().await;
        if !vault.is_unlocked() {
            return responses::err(&CoreError::new(ErrorCode::VaultLocked));
        }

        let path = match VaultPath::parse(&params.path) {
            Ok(p) => p,
            Err(e) => return responses::err(&e),
        };

        let working = match vault.working_db_mut() {
            Ok(db) => db,
            Err(e) => return responses::err(&e),
        };

        if let Err(e) = stage::update_field(
            working,
            &path,
            &params.field_name,
            &params.value,
            params.protected,
        ) {
            return responses::err(&e);
        }

        // Resolve the entry's uuid for the audit event. The write just succeeded,
        // so the path resolves; fall back to an empty uuid defensively.
        let uuid = path
            .resolve_entry(working)
            .ok()
            .and_then(|id| working.entry(id).map(|e| e.id().uuid().to_string()))
            .unwrap_or_default();

        let path_str = path.format();
        self.emit(AuditEvent::WriteStaged {
            tool: "kdbx_update_field".to_string(),
            target_path: path_str.clone(),
            target_uuid: uuid,
            field_name: Some(params.field_name.clone()),
        });

        responses::ok(serde_json::json!({
            "staged": true,
            "path": path_str,
            "field_name": params.field_name,
        }))
    }

    /// Stage: show the pending diff between the on-disk baseline and the staged
    /// working copy. Requires `KDBX_ALLOW_WRITES=true` and an unlocked vault.
    /// This is a read of the stage, so it emits no audit event. Protected field
    /// values are redacted.
    #[tool(
        description = "Show the pending changes staged in memory: added and modified entries with a per-field diff. Requires writes to be enabled and the vault unlocked. Protected field values are never shown, only that they changed. This does not write anything."
    )]
    async fn kdbx_diff_pending(&self) -> String {
        if !self.writes_allowed() {
            return responses::err(&CoreError::new(ErrorCode::WritesDisabled));
        }

        let vault = self.vault().await;
        if !vault.is_unlocked() {
            return responses::err(&CoreError::new(ErrorCode::VaultLocked));
        }

        let (canonical, working) = match vault.canonical_and_working() {
            Ok(pair) => pair,
            Err(e) => return responses::err(&e),
        };

        let diff = stage::diff_pending(canonical, working);
        responses::ok(diff)
    }

    /// Stage: commit the pending changes to disk atomically. Requires
    /// `KDBX_ALLOW_WRITES=true` and an unlocked vault. Refuses when nothing is
    /// staged (`NO_PENDING_CHANGES`) or when the file changed on disk since
    /// unlock (`VAULT_FILE_MODIFIED`).
    #[tool(
        description = "Commit the staged changes to the vault file atomically. Requires writes to be enabled and the vault unlocked. Refuses when nothing is staged, or when the file changed on disk since it was unlocked. On success the stage settles and the working copy becomes the new baseline."
    )]
    async fn kdbx_save_pending(&self) -> String {
        if !self.writes_allowed() {
            return responses::err(&CoreError::new(ErrorCode::WritesDisabled));
        }

        let mut vault = self.vault().await;
        if !vault.is_unlocked() {
            return responses::err(&CoreError::new(ErrorCode::VaultLocked));
        }

        // Capture the pre-save mtime and the pending count into owned values
        // before the save mutates the vault, so the audit events have what they
        // need without re-borrowing across the save.
        let before_mtime = vault
            .mtime_at_unlock()
            .ok()
            .map(format_system_time)
            .unwrap_or_default();
        let pending_before = if vault.has_pending_changes() { 1 } else { 0 };

        match stage::save_pending(&mut vault) {
            Ok(outcome) => {
                self.emit(AuditEvent::SaveCommitted {
                    num_changes: outcome.num_changes as u64,
                    before_mtime,
                    after_mtime: outcome.written_at.clone(),
                });
                responses::ok(outcome)
            }
            Err(e) => {
                match e.code_enum() {
                    ErrorCode::VaultFileModified => {
                        // The conflict mtime lives in the error details, written
                        // by the stage save path. Read it best-effort.
                        let conflict_mtime = e
                            .details()
                            .and_then(|d| d.get("file_mtime_now"))
                            .and_then(|v| v.as_str())
                            .unwrap_or_default()
                            .to_string();
                        self.emit(AuditEvent::SaveRefused {
                            before_mtime,
                            conflict_mtime,
                            pending_changes: pending_before,
                        });
                    }
                    // Nothing happened: no audit event for an empty stage.
                    ErrorCode::NoPendingChanges => {}
                    // Any other failure is a write failure.
                    _ => {
                        self.emit(AuditEvent::SaveFailed {
                            failure_step: "write".to_string(),
                            error_message: e.message().to_string(),
                            pending_changes: pending_before,
                        });
                    }
                }
                responses::err(&e)
            }
        }
    }

    /// Stage: drop the pending changes and reset the working copy to the on-disk
    /// baseline. Requires `KDBX_ALLOW_WRITES=true` and an unlocked vault.
    /// Discarding with nothing staged is a no-op success.
    #[tool(
        description = "Discard the staged changes and reset the working copy to the on-disk baseline. Requires writes to be enabled and the vault unlocked. Discarding with nothing staged is a no-op success. Reports how many changes were dropped."
    )]
    async fn kdbx_discard_pending(&self) -> String {
        if !self.writes_allowed() {
            return responses::err(&CoreError::new(ErrorCode::WritesDisabled));
        }

        let mut vault = self.vault().await;
        if !vault.is_unlocked() {
            return responses::err(&CoreError::new(ErrorCode::VaultLocked));
        }

        let num_dropped = match stage::discard_pending(&mut vault) {
            Ok(n) => n,
            Err(e) => return responses::err(&e),
        };

        self.emit(AuditEvent::StageDiscarded {
            reason: "manual".to_string(),
            num_dropped: num_dropped as u64,
            // Paths-only summary; an empty list is acceptable for v0.1.
            summary: Vec::new(),
        });

        responses::ok(serde_json::json!({
            "discarded": true,
            "num_dropped": num_dropped,
        }))
    }
}

/// Format a `SystemTime` as `YYYY-MM-DDTHH:MM:SSZ` (UTC), for the save audit
/// events' mtime fields. Mirrors the formatter in `lifecycle.rs`.
fn format_system_time(time: std::time::SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Utc> = time.into();
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
