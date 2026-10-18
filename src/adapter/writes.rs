//! Write and stage tools: `kdbx_add_entry`, `kdbx_update_field`,
//! `kdbx_diff_pending`, `kdbx_save_pending`, `kdbx_discard_pending`.
//!
//! These are the write side of the stage-then-commit model (spec sections 3 and
//! 4). Every write tool checks the `KDBX_ALLOW_WRITES` gate first and returns
//! `WRITES_DISABLED` before touching the vault, then requires an unlocked vault
//! (`VAULT_LOCKED`). Writes mutate the working db only; nothing reaches disk
//! until `kdbx_save_pending`. The actual mutation, diffing, and atomic save live
//! in `engine::stage`; this module is the thin adapter that converts the MCP
//! tool inputs into core calls, emits the right audit event, and wraps results
//! in the `{ ok, data } | { ok, error }` envelope.
//!
//! The MCP input for `kdbx_add_entry` carries fields and attachments as maps
//! (`{ name: { value, protected } }` and `{ name: { base64 } }`), matching the
//! spec's JSON shape. We convert those maps into the ordered `Vec` inputs the
//! stage API expects, decoding each attachment's base64 here in the adapter (the
//! stage module takes raw bytes, not base64).

use crate::adapter::views::format_system_time;
use crate::adapter::{KdbxServer, responses};
use crate::engine::address::{EntryAddress, GroupAddress};
use crate::engine::audit::{AuditEvent, StageDiscardReason, WriteTool};
use crate::engine::error::{CoreError, ErrorCode};
use crate::engine::secret::Secret;
use crate::engine::stage;
use crate::engine::vault_file::SaveStep;
use base64::Engine;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{schemars, tool, tool_router};
use serde::Deserialize;
use std::collections::HashMap;

/// One field on a new entry in the `kdbx_add_entry` input map: a value and its
/// protection flag. Keyed by field name in the surrounding map. The value is a
/// [`Secret`] (redacted in `Debug`).
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
pub struct FieldSpec {
    /// The field value. Stored protected or not per `protected`.
    pub value: Secret<String>,
    /// Whether to store the field as a protected (encrypted-at-rest) value.
    pub protected: bool,
}

/// One attachment on a new entry in the `kdbx_add_entry` input map: the content
/// as base64. Keyed by attachment name in the surrounding map.
#[derive(Debug, Clone, serde::Deserialize, schemars::JsonSchema)]
pub struct AttachmentSpec {
    /// The attachment bytes, base64-encoded (standard alphabet).
    pub base64: Secret<String>,
}

/// Input for `kdbx_add_entry`: a destination group, a title, and optional
/// field and attachment maps.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct AddEntryParams {
    /// The group path to add the entry under, for example `/Web/` or `/`.
    /// Give exactly one of `group_path` or `group_uuid`.
    #[serde(default)]
    pub group_path: Option<String>,
    /// The uuid of the group to add the entry under (as returned by
    /// kdbx_list_groups). Give exactly one of `group_path` or `group_uuid`.
    #[serde(default)]
    pub group_uuid: Option<String>,
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

/// Input for `kdbx_update_field`: which entry (by path or uuid), which field,
/// and the new value.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct UpdateFieldParams {
    /// The entry path, for example `/Web/GitHub`. Give exactly one of `path`
    /// or `uuid`.
    #[serde(default)]
    pub path: Option<String>,
    /// The entry's uuid. Give exactly one of `path` or `uuid`.
    #[serde(default)]
    pub uuid: Option<String>,
    /// The field name to set or change.
    pub field_name: String,
    /// The new value. An empty value clears the field.
    pub value: Secret<String>,
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
        description = "Stage a new entry under a group, named by group_path or group_uuid. Requires writes to be enabled and the vault unlocked. The entry is staged in memory, not written to disk: commit it with kdbx_save_pending. Fields and attachments are optional maps keyed by name."
    )]
    async fn kdbx_add_entry(&self, Parameters(params): Parameters<AddEntryParams>) -> String {
        if !self.writes_allowed() {
            return responses::err(&CoreError::new(ErrorCode::WritesDisabled));
        }

        let mut vault = self.vault().await;
        if !vault.is_unlocked() {
            return responses::err(&responses::locked_error(vault.take_last_lock()));
        }

        let group = match GroupAddress::from_parts(
            params.group_path.as_deref(),
            params.group_uuid.as_deref(),
            "group_path",
            "group_uuid",
        ) {
            Ok(g) => g,
            Err(e) => return responses::err(&e),
        };

        // Convert the field and attachment maps into the ordered Vec inputs the
        // stage API expects. The attachment base64 is decoded here; bad base64 is
        // INVALID_INPUT (a malformed value, not a bad field name) with a clear
        // message.
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
            let bytes = match base64::engine::general_purpose::STANDARD.decode(spec.base64.expose())
            {
                Ok(bytes) => Secret::new(bytes),
                Err(_) => {
                    return responses::err(
                        &CoreError::new(ErrorCode::InvalidInput)
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

        let entry_id = match stage::add_entry(working, &group, &input) {
            Ok(id) => id,
            Err(e) => return responses::err(&e),
        };

        // Capture the audit data into owned values before returning. The new
        // entry's path comes from a fresh view of the working db (None only
        // when its group has no addressable path); the uuid comes off the id.
        let path = vault
            .view()
            .ok()
            .and_then(|view| view.path_string(entry_id.uuid()));
        let uuid = entry_id.uuid().to_string();

        self.emit(AuditEvent::WriteStaged {
            tool: WriteTool::KdbxAddEntry,
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
            return responses::err(&responses::locked_error(vault.take_last_lock()));
        }

        let target = match EntryAddress::from_parts(
            params.path.as_deref(),
            params.uuid.as_deref(),
            "path",
        ) {
            Ok(t) => t,
            Err(e) => return responses::err(&e),
        };

        let working = match vault.working_db_mut() {
            Ok(db) => db,
            Err(e) => return responses::err(&e),
        };

        let entry_id = match stage::update_field(
            working,
            &target,
            &params.field_name,
            params.value.expose(),
            params.protected,
        ) {
            Ok(id) => id,
            Err(e) => return responses::err(&e),
        };

        // Report the canonical path of the entry actually written (re-derived
        // after the write, since a Title change moves it) and its uuid.
        let path = vault
            .view()
            .ok()
            .and_then(|view| view.path_string(entry_id.uuid()));
        let uuid = entry_id.uuid().to_string();
        self.emit(AuditEvent::WriteStaged {
            tool: WriteTool::KdbxUpdateField,
            target_path: path.clone(),
            target_uuid: uuid.clone(),
            field_name: Some(params.field_name.clone()),
        });

        responses::ok(serde_json::json!({
            "staged": true,
            "path": path,
            "uuid": uuid,
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

        let mut vault = self.vault().await;
        if !vault.is_unlocked() {
            return responses::err(&responses::locked_error(vault.take_last_lock()));
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
        description = "Commit the staged changes to the vault file atomically. Requires writes to be enabled and the vault unlocked. Refuses when nothing is staged, or when the file content changed on disk since it was unlocked (VAULT_FILE_MODIFIED: discard and re-unlock to pick up the other change). On success the stage settles and the working copy becomes the new baseline."
    )]
    async fn kdbx_save_pending(&self) -> String {
        if !self.writes_allowed() {
            return responses::err(&CoreError::new(ErrorCode::WritesDisabled));
        }

        let mut vault = self.vault().await;
        if !vault.is_unlocked() {
            return responses::err(&responses::locked_error(vault.take_last_lock()));
        }

        // Capture the pre-save mtime and the pending count into owned values
        // before the save mutates the vault, so the audit events have what they
        // need without re-borrowing across the save.
        let before_mtime = vault
            .mtime_at_unlock()
            .ok()
            .map(format_system_time)
            .unwrap_or_default();
        let pending_before = vault.pending_count() as u64;

        // The save runs the KDF and blocking file I/O (including a bounded wait
        // for the writer lock). block_in_place moves that off the async worker
        // so other tasks (the idle timer) keep running; the server runs on the
        // multi-threaded runtime (#[tokio::main]).
        let result = tokio::task::block_in_place(|| stage::save_pending(&mut vault));
        match result {
            Ok(outcome) => {
                if let Some(reason) = outcome.writer_lock_unavailable {
                    self.emit(AuditEvent::WriterLockUnavailable { reason });
                }
                // The baseline now describes the file just written, so its mtime
                // is the real new file mtime.
                let after_mtime = vault
                    .mtime_at_unlock()
                    .ok()
                    .map(format_system_time)
                    .unwrap_or_default();
                self.emit(AuditEvent::SaveCommitted {
                    num_changes: outcome.num_changes as u64,
                    before_mtime,
                    after_mtime,
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
                        // The save path tags every WRITE_FAILED with the step
                        // that failed (details.step, a SaveStep).
                        let failure_step = e
                            .details()
                            .and_then(|d| d.get("step"))
                            .and_then(|step| SaveStep::deserialize(step).ok());
                        self.emit(AuditEvent::SaveFailed {
                            failure_step,
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
            return responses::err(&responses::locked_error(vault.take_last_lock()));
        }

        // Capture the discarded changes' labels before the working copy is
        // reset. The immutable diff borrow ends once the owned labels are
        // collected, so the mutable discard borrow that follows does not
        // conflict.
        let summary: Vec<String> = match vault.canonical_and_working() {
            Ok((canonical, working)) => stage::diff_pending(canonical, working).entry_labels(),
            Err(_) => Vec::new(),
        };

        let num_dropped = match stage::discard_pending(&mut vault) {
            Ok(n) => n,
            Err(e) => return responses::err(&e),
        };

        self.emit(AuditEvent::StageDiscarded {
            reason: StageDiscardReason::Manual,
            num_dropped: num_dropped as u64,
            summary,
        });

        responses::ok(serde_json::json!({
            "discarded": true,
            "num_dropped": num_dropped,
        }))
    }
}
