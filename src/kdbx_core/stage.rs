//! Working-copy write operations, the diff-kdbx stage diff, and the atomic save.
//!
//! Phase 2, tasks 10 and 12. This module is the write side of the stage-then-
//! commit model (spec sections 3 and 4). Write tools mutate the working db; the
//! canonical db stays as the on-disk baseline. Nothing touches disk until
//! [`save_pending`], which serializes the working db and writes it atomically
//! (temp, fsync, rename, fsync parent dir).
//!
//! ## What lives here
//!
//! - [`add_entry`] and [`update_field`]: stage writes onto the working db,
//!   after validating titles and field names (spec section 3).
//! - [`diff_pending`]: the canonical-vs-working semantic diff, computed by
//!   `diff_kdbx::compute::compute` and mapped to the spec's `kdbx_diff_pending`
//!   shape (spec section 4). Protected fields are redacted: the diff reports
//!   that a protected field changed, never its before/after value.
//! - [`save_pending`] and [`discard_pending`]: commit or drop the stage.
//!
//! ## Protected-vs-nonprotected discriminator
//!
//! The diff mapping leans on one fact: `DiffOptions::default()` masks protected
//! fields to `ValueDisplay::Masked { hash }` and leaves non-protected fields as
//! `ValueDisplay::Plain { value }`. We never pass `show_secrets = true`, so a
//! `Masked` value is exactly a protected field and a `Plain` value is exactly a
//! non-protected one. That is how we decide whether to redact a field change
//! without ever holding a protected plaintext.

use crate::kdbx_core::error::{CoreError, CoreResult, ErrorCode};
use crate::kdbx_core::path::{VaultPath, vault_path_to_entry};
use crate::kdbx_core::vault::Vault;
use diff_kdbx::change_set::{Change, EntryChangeKind, FieldChange, ValueChange, ValueDisplay};
use diff_kdbx::options::DiffOptions;
use keepass::Database;
use keepass::db::{EntryId, Value, fields};
use serde::{Deserialize, Serialize};
use std::time::SystemTime;

// ---------------------------------------------------------------------------
// Input structs (built by the Phase 3 MCP adapter from tool JSON).
// ---------------------------------------------------------------------------

/// One field on a staged entry: a name, a value, and whether it is protected.
#[derive(Debug, Clone, Deserialize)]
pub struct FieldInput {
    pub name: String,
    pub value: String,
    pub protected: bool,
}

/// One attachment on a staged entry: a name and the raw bytes.
///
/// The Phase 3 adapter decodes the wire base64 into `bytes` before building
/// this; decoding is the adapter's job, not this module's. keepass 0.12.7
/// exposes a public attachment-write API (`EntryTrack::add_attachment`), so
/// add_entry can carry attachments. An empty `attachments` vec is the common
/// case and costs nothing.
#[derive(Debug, Clone, Deserialize)]
pub struct AttachmentInput {
    pub name: String,
    pub bytes: Vec<u8>,
}

/// A staged new entry: a title plus zero or more fields and attachments.
#[derive(Debug, Clone, Deserialize)]
pub struct EntryInput {
    pub title: String,
    #[serde(default)]
    pub fields: Vec<FieldInput>,
    #[serde(default)]
    pub attachments: Vec<AttachmentInput>,
}

// ---------------------------------------------------------------------------
// Output types (serialized by the Phase 3 adapter; shapes match spec section 4).
// ---------------------------------------------------------------------------

/// The staged diff: canonical vs working, in the `kdbx_diff_pending` shape.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffPending {
    pub added: Vec<AddedEntry>,
    pub modified: Vec<ModifiedEntry>,
    /// Reserved for a future delete tool. v0.1 has no delete, so this is always
    /// empty: our writes only add entries and update fields.
    pub removed: Vec<serde_json::Value>,
    pub summary: DiffSummary,
}

/// An entry that exists in the working db but not the canonical baseline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddedEntry {
    pub path: String,
    pub uuid: String,
    pub title: String,
    pub group_path: String,
    pub field_count: usize,
    pub has_attachments: bool,
    pub has_otp: bool,
}

/// An entry present in both dbs whose fields or attachments changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModifiedEntry {
    pub path: String,
    pub uuid: String,
    pub title: String,
    pub field_changes: Vec<FieldChangeOut>,
    pub attachment_changes: Vec<AttachmentChangeOut>,
}

/// One field change in a modified entry, in one of two shapes.
///
/// `#[serde(untagged)]` makes serde pick the shape by which fields are present,
/// so this serializes to exactly the two spec forms:
/// - non-protected: `{ "field_name", "before", "after", "protected": false }`
/// - protected:     `{ "field_name", "changed": true, "protected": true }`
///
/// The protected form carries no before/after, so a protected value never
/// appears in a bulk diff even when it changed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum FieldChangeOut {
    /// A non-protected field: the before and after values are shown. An absent
    /// side (a field added or removed) is JSON `null`.
    Plain {
        field_name: String,
        before: serde_json::Value,
        after: serde_json::Value,
        protected: bool,
    },
    /// A protected field: only the fact that it changed, never the value.
    Redacted {
        field_name: String,
        changed: bool,
        protected: bool,
    },
}

/// An attachment change in a modified entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AttachmentChangeOut {
    pub name: String,
    /// One of "added", "removed", "modified".
    pub change: String,
}

/// The counts shown at the top of the diff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DiffSummary {
    pub num_added: usize,
    pub num_modified: usize,
    pub num_removed: usize,
}

/// The result of a successful save.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SaveOutcome {
    pub saved: bool,
    pub num_changes: usize,
    pub vault_path: String,
    pub written_at: String,
}

// ---------------------------------------------------------------------------
// Validation (spec section 3).
// ---------------------------------------------------------------------------

/// Validate an entry title: length 1..=4096, no ASCII control characters.
fn validate_title(title: &str) -> CoreResult<()> {
    let len = title.chars().count();
    if !(1..=4096).contains(&len) {
        return Err(CoreError::new(ErrorCode::EntryTitleInvalid)
            .with_message("title length must be between 1 and 4096 characters")
            .with_details(serde_json::json!({ "length": len })));
    }
    if title.chars().any(|c| (c as u32) < 0x20) {
        return Err(CoreError::new(ErrorCode::EntryTitleInvalid)
            .with_message("title must not contain ASCII control characters"));
    }
    Ok(())
}

/// Validate a field name: length 1..=256, no ASCII control characters, no
/// leading or trailing whitespace.
fn validate_field_name(name: &str) -> CoreResult<()> {
    let len = name.chars().count();
    if !(1..=256).contains(&len) {
        return Err(CoreError::new(ErrorCode::FieldNameInvalid)
            .with_message("field name length must be between 1 and 256 characters")
            .with_details(serde_json::json!({ "name": name, "length": len })));
    }
    if name.chars().any(|c| (c as u32) < 0x20) {
        return Err(CoreError::new(ErrorCode::FieldNameInvalid)
            .with_message("field name must not contain ASCII control characters")
            .with_details(serde_json::json!({ "name": name })));
    }
    if name != name.trim() {
        return Err(CoreError::new(ErrorCode::FieldNameInvalid)
            .with_message("field name must not have leading or trailing whitespace")
            .with_details(serde_json::json!({ "name": name })));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Write operations.
// ---------------------------------------------------------------------------

/// Stage a new entry under the group named by `group_path`.
///
/// Resolves the group in `working` (propagates `GROUP_NOT_FOUND`), validates
/// the title and every field name, then creates the entry: sets Title, then
/// each field (protected or not), then links each attachment under its name.
/// Returns the new entry's id.
pub fn add_entry(
    working: &mut Database,
    group_path: &VaultPath,
    input: &EntryInput,
) -> CoreResult<EntryId> {
    validate_title(&input.title)?;
    for f in &input.fields {
        validate_field_name(&f.name)?;
    }

    let group_id = group_path.resolve_group(working)?;

    // Clone the inputs the closure needs. The edit closure is FnOnce and the
    // keepass write API takes owned values, so we move owned copies in.
    let title = input.title.clone();
    let field_specs: Vec<(String, String, bool)> = input
        .fields
        .iter()
        .map(|f| (f.name.clone(), f.value.clone(), f.protected))
        .collect();
    let attachment_specs: Vec<(String, Vec<u8>)> = input
        .attachments
        .iter()
        .map(|a| (a.name.clone(), a.bytes.clone()))
        .collect();

    let mut group_mut = working.group_mut(group_id).ok_or_else(|| {
        CoreError::new(ErrorCode::GroupNotFound)
            .with_message("group disappeared between resolve and write")
            .with_details(serde_json::json!({ "path": group_path.format() }))
    })?;

    let new_id = group_mut
        .add_entry()
        .edit(|e| {
            e.set_unprotected(fields::TITLE, title);
            for (name, value, protected) in field_specs {
                let v = if protected {
                    Value::protected(value)
                } else {
                    Value::unprotected(value)
                };
                e.set(name, v);
            }
            for (name, bytes) in attachment_specs {
                // Attachment bytes are protected at rest in KDBX. add_attachment
                // takes a Value<Vec<u8>>; we mark it protected to match how
                // KeePass stores binaries.
                e.add_attachment(name, Value::protected(bytes));
            }
        })
        .id();

    Ok(new_id)
}

/// Update or set a single field on the entry named by `entry_path`.
///
/// `protected = None` preserves an existing field's protection state (and
/// defaults to unprotected for a new field); `Some(b)` forces it. An empty
/// value is allowed and clears the field (the Password-regenerate workflow).
/// Propagates `ENTRY_NOT_FOUND` when the path does not resolve to an entry, and
/// validates the field name.
pub fn update_field(
    working: &mut Database,
    entry_path: &VaultPath,
    field_name: &str,
    value: &str,
    protected: Option<bool>,
) -> CoreResult<()> {
    validate_field_name(field_name)?;

    let entry_id = entry_path.resolve_entry(working)?;

    // Decide the protection state before taking the mutable borrow: when the
    // caller did not force it, read the current field's state (false when the
    // field is new).
    let resolved_protected = match protected {
        Some(b) => b,
        None => working
            .entry(entry_id)
            .and_then(|er| er.fields.get(field_name).map(|v| v.is_protected()))
            .unwrap_or(false),
    };

    let name = field_name.to_string();
    let value_owned = value.to_string();

    let mut entry_mut = working.entry_mut(entry_id).ok_or_else(|| {
        CoreError::new(ErrorCode::EntryNotFound)
            .with_message("entry disappeared between resolve and write")
            .with_details(serde_json::json!({ "path": entry_path.format() }))
    })?;

    entry_mut.edit(|e| {
        let v = if resolved_protected {
            Value::protected(value_owned)
        } else {
            Value::unprotected(value_owned)
        };
        e.set(name, v);
    });

    Ok(())
}

// ---------------------------------------------------------------------------
// The stage diff.
// ---------------------------------------------------------------------------

/// Compute the staged diff between the canonical baseline and the working db,
/// mapped to the `kdbx_diff_pending` shape (spec section 4).
///
/// Uses `DiffOptions::default()`, which masks protected fields. We only inspect
/// `Change::Entry` changes with kind Added or Modified: v0.1 write tools add
/// entries and update fields, nothing else. Group changes, database metadata
/// changes, Moved entries, and Removed entries do not arise from our writes, so
/// they are ignored. (A removed entry would need a delete tool we do not have;
/// a moved entry, a move tool we do not have.) Tag and history field changes are
/// likewise ignored: our writes do not intentionally create them.
pub fn diff_pending(canonical: &Database, working: &Database) -> DiffPending {
    let change_set = diff_kdbx::compute::compute(canonical, working, &DiffOptions::default());

    let mut added: Vec<AddedEntry> = Vec::new();
    let mut modified: Vec<ModifiedEntry> = Vec::new();

    for change in &change_set.changes {
        let Change::Entry { uuid, kind, .. } = change else {
            // Ignore Database and Group changes: our writes do not create them.
            continue;
        };

        match kind {
            EntryChangeKind::Added => {
                if let Some(entry) = map_added_entry(working, *uuid) {
                    added.push(entry);
                }
            }
            EntryChangeKind::Modified { fields } => {
                if let Some(entry) = map_modified_entry(working, *uuid, fields) {
                    modified.push(entry);
                }
            }
            // No delete tool (Removed) and no move tool (Moved) in v0.1, so
            // these do not arise from our writes. Leave `removed` empty.
            EntryChangeKind::Removed | EntryChangeKind::Moved { .. } => {}
        }
    }

    // Stable order: sort each list by (group_path, title). For modified entries
    // we have the full path but not a separate group_path field, so we derive
    // the group path from the entry's path via VaultPath::parent.
    added.sort_by(|a, b| {
        (a.group_path.as_str(), a.title.as_str()).cmp(&(b.group_path.as_str(), b.title.as_str()))
    });
    modified.sort_by(|a, b| {
        let ga = group_path_of(&a.path);
        let gb = group_path_of(&b.path);
        (ga.as_str(), a.title.as_str()).cmp(&(gb.as_str(), b.title.as_str()))
    });

    let num_added = added.len();
    let num_modified = modified.len();
    DiffPending {
        added,
        modified,
        removed: Vec::new(),
        summary: DiffSummary {
            num_added,
            num_modified,
            num_removed: 0,
        },
    }
}

/// The containing group path of a formatted entry path, used as a sort key.
/// Falls back to the path itself when it does not parse (which should not
/// happen for paths we built with `vault_path_to_entry`).
fn group_path_of(entry_path: &str) -> String {
    match VaultPath::parse(entry_path) {
        Ok(p) => p.parent().format(),
        Err(_) => entry_path.to_string(),
    }
}

/// Build an [`AddedEntry`] by looking up `uuid` in the working db.
fn map_added_entry(working: &Database, uuid: uuid::Uuid) -> Option<AddedEntry> {
    let entry_ref = working.iter_all_entries().find(|e| e.id().uuid() == uuid)?;
    let eid = entry_ref.id();

    // Build the path once; derive the group path from its parent. The entry was
    // just found in `working`, so this resolves; "/" is a defensive fallback.
    let vpath = vault_path_to_entry(working, eid);
    let path = vpath
        .as_ref()
        .map(|p| p.format())
        .unwrap_or_else(|| "/".to_string());
    let group_path = vpath
        .as_ref()
        .map(|p| p.parent().format())
        .unwrap_or_else(|| "/".to_string());

    let title = entry_ref.get_title().unwrap_or("").to_string();
    let field_count = entry_ref.fields.len();
    let has_attachments = entry_ref.attachments_named().next().is_some();
    // Route has_otp through the same resolver the read views use
    // (src/adapter/views.rs), so kdbx_diff_pending and kdbx_list_entries agree on
    // whether an entry has a usable TOTP source. This covers the modern `otp`
    // field and the legacy "TOTP Seed" + "TOTP Settings" pair, not just a bare
    // `otp` presence check.
    let has_otp = crate::kdbx_core::totp::resolve_config(
        entry_ref.get(fields::OTP),
        entry_ref.get("TOTP Seed"),
        entry_ref.get("TOTP Settings"),
    )
    .is_some();

    Some(AddedEntry {
        path,
        uuid: uuid.hyphenated().to_string(),
        title,
        group_path,
        field_count,
        has_attachments,
        has_otp,
    })
}

/// Build a [`ModifiedEntry`] by looking up `uuid` in the working db and
/// partitioning its field changes into field-level and attachment-level lists.
fn map_modified_entry(
    working: &Database,
    uuid: uuid::Uuid,
    field_changes: &[FieldChange],
) -> Option<ModifiedEntry> {
    let entry_ref = working.iter_all_entries().find(|e| e.id().uuid() == uuid)?;
    let eid = entry_ref.id();

    let path = vault_path_to_entry(working, eid)
        .map(|p| p.format())
        .unwrap_or_else(|| "/".to_string());
    let title = entry_ref.get_title().unwrap_or("").to_string();

    let mut field_out: Vec<FieldChangeOut> = Vec::new();
    let mut attachment_out: Vec<AttachmentChangeOut> = Vec::new();

    for fc in field_changes {
        match fc {
            FieldChange::Modified { name, change } => {
                field_out.push(map_modified_field(name, change));
            }
            FieldChange::Added { name, value } => {
                field_out.push(map_added_field(name, value));
            }
            FieldChange::Removed { name, value } => {
                field_out.push(map_removed_field(name, value));
            }
            FieldChange::AttachmentAdded { name, .. } => {
                attachment_out.push(AttachmentChangeOut {
                    name: name.clone(),
                    change: "added".to_string(),
                });
            }
            FieldChange::AttachmentRemoved { name, .. } => {
                attachment_out.push(AttachmentChangeOut {
                    name: name.clone(),
                    change: "removed".to_string(),
                });
            }
            FieldChange::AttachmentModified { name, .. } => {
                attachment_out.push(AttachmentChangeOut {
                    name: name.clone(),
                    change: "modified".to_string(),
                });
            }
            // Tags and history: our writes do not intentionally create these,
            // and they are not part of the v0.1 diff surface. Ignore them.
            FieldChange::TagAdded { .. }
            | FieldChange::TagRemoved { .. }
            | FieldChange::HistoryGrew { .. }
            | FieldChange::HistoryRewritten { .. } => {}
        }
    }

    Some(ModifiedEntry {
        path,
        uuid: uuid.hyphenated().to_string(),
        title,
        field_changes: field_out,
        attachment_changes: attachment_out,
    })
}

/// Map a value-to-value field change. A protected field (either side masked)
/// is redacted; a non-protected change carries its before/after.
fn map_modified_field(name: &str, change: &ValueChange) -> FieldChangeOut {
    if is_masked(&change.from) || is_masked(&change.to) {
        redacted(name)
    } else {
        FieldChangeOut::Plain {
            field_name: name.to_string(),
            before: plain_to_json(&change.from),
            after: plain_to_json(&change.to),
            protected: false,
        }
    }
}

/// Map a newly-added field: before is null, after is the value (or redacted if
/// the field is protected).
fn map_added_field(name: &str, value: &ValueDisplay) -> FieldChangeOut {
    if is_masked(value) {
        redacted(name)
    } else {
        FieldChangeOut::Plain {
            field_name: name.to_string(),
            before: serde_json::Value::Null,
            after: plain_to_json(value),
            protected: false,
        }
    }
}

/// Map a removed field: before is the value, after is null (or redacted if the
/// field is protected).
fn map_removed_field(name: &str, value: &ValueDisplay) -> FieldChangeOut {
    if is_masked(value) {
        redacted(name)
    } else {
        FieldChangeOut::Plain {
            field_name: name.to_string(),
            before: plain_to_json(value),
            after: serde_json::Value::Null,
            protected: false,
        }
    }
}

/// The redacted form for a protected field change.
fn redacted(name: &str) -> FieldChangeOut {
    FieldChangeOut::Redacted {
        field_name: name.to_string(),
        changed: true,
        protected: true,
    }
}

/// True when a `ValueDisplay` is the masked (protected) form.
fn is_masked(v: &ValueDisplay) -> bool {
    matches!(v, ValueDisplay::Masked { .. })
}

/// Render a non-masked `ValueDisplay` to a JSON string value. A `Masked` value
/// should never reach here (callers redact first); it maps to null defensively
/// so a protected plaintext can never leak through this path.
fn plain_to_json(v: &ValueDisplay) -> serde_json::Value {
    match v {
        ValueDisplay::Plain { value } => serde_json::Value::String(value.clone()),
        ValueDisplay::Masked { .. } => serde_json::Value::Null,
    }
}

// ---------------------------------------------------------------------------
// Save and discard.
// ---------------------------------------------------------------------------

/// Atomically save the working db to the vault file (spec section 3, "Save
/// atomicity").
///
/// Steps: refuse when nothing is pending; refuse when the file changed on disk
/// since unlock (mtime conflict, more than one second of slack); serialize the
/// working db in memory; write to a temp file in the same directory and fsync
/// it; rename it over the vault file; best-effort fsync the parent directory;
/// re-stat for the new mtime; adopt the working db as the new canonical
/// baseline. On a serialize or write failure the stage is preserved and no
/// vault state changes.
pub fn save_pending(vault: &mut Vault) -> CoreResult<SaveOutcome> {
    if !vault.has_pending_changes() {
        return Err(ErrorCode::NoPendingChanges.into());
    }

    let path = vault.path().to_path_buf();
    let mtime_at_unlock = vault.mtime_at_unlock()?;

    // mtime conflict check. A file modified more than one second after the
    // mtime we captured at unlock means something else wrote it (KeePassXC,
    // another mcp-kdbx). One second of slack absorbs filesystem timestamp
    // coarseness.
    let mtime_now = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .map_err(|e| {
            CoreError::new(ErrorCode::WriteFailed)
                .with_message(format!("could not stat vault file: {e}"))
        })?;
    if exceeds_slack(mtime_at_unlock, mtime_now) {
        let pending = if vault.has_pending_changes() { 1 } else { 0 };
        return Err(
            CoreError::new(ErrorCode::VaultFileModified).with_details(serde_json::json!({
                "file_mtime_at_unlock": to_rfc3339(mtime_at_unlock),
                "file_mtime_now": to_rfc3339(mtime_now),
                "pending_changes": pending,
            })),
        );
    }

    // Count the changes before we adopt working as canonical (after mark_saved
    // the two dbs are equal and the count would be zero).
    let num_changes = {
        let (canonical, working) = vault.canonical_and_working()?;
        let d = diff_pending(canonical, working);
        d.summary.num_added + d.summary.num_modified + d.summary.num_removed
    };

    // Serialize the working db to encrypted bytes in memory.
    let bytes = {
        let (working, key) = vault.working_db_and_key()?;
        let mut buf = Vec::new();
        working.save(&mut buf, key.clone()).map_err(|e| {
            CoreError::new(ErrorCode::WriteFailed)
                .with_message(format!("serializing the vault failed: {e}"))
        })?;
        buf
    };

    // Write to a temp file in the same directory, fsync, rename, fsync dir.
    let new_mtime = write_atomically(&path, &bytes)?;

    vault.mark_saved(new_mtime)?;

    Ok(SaveOutcome {
        saved: true,
        num_changes,
        vault_path: absolute_path_string(&path),
        written_at: to_rfc3339(SystemTime::now()),
    })
}

/// Discard the staged changes (delegates to the vault). Returns the prior
/// pending count.
pub fn discard_pending(vault: &mut Vault) -> CoreResult<usize> {
    vault.discard_working()
}

/// True when `now` is more than one second later than `at_unlock`. A `now` at
/// or before `at_unlock` (clock went backward, or no external write) is not a
/// conflict.
fn exceeds_slack(at_unlock: SystemTime, now: SystemTime) -> bool {
    match now.duration_since(at_unlock) {
        Ok(delta) => delta > std::time::Duration::from_secs(1),
        Err(_) => false,
    }
}

/// Write `bytes` to `path` atomically: a uniquely-named temp file in the same
/// directory, `write_all`, fsync the file, rename it over `path`, then a
/// best-effort fsync of the parent directory. Returns the freshly written
/// file's mtime. On any pre-rename failure the temp file is unlinked and
/// `WRITE_FAILED` is returned, so the vault is untouched.
fn write_atomically(path: &std::path::Path, bytes: &[u8]) -> CoreResult<SystemTime> {
    use std::io::Write;

    let parent = path.parent().ok_or_else(|| {
        CoreError::new(ErrorCode::WriteFailed).with_message("vault path has no parent directory")
    })?;

    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "vault.kdbx".to_string());

    let temp_path = parent.join(format!(
        "{}.tmp.{}.{}",
        file_name,
        std::process::id(),
        temp_suffix()
    ));

    // Open and write the temp file. The open uses create_new (O_EXCL), so it
    // refuses to clobber a pre-existing temp file: if the name already exists,
    // another save raced us and we surface WRITE_FAILED rather than overwrite a
    // file that may be in use. Any failure here unlinks the temp and surfaces
    // WRITE_FAILED; the vault file is untouched. (On a create_new failure the
    // name was not ours to begin with, so the remove below is a harmless no-op
    // most of the time, and the surrounding error path is unchanged.)
    let write_result = (|| -> std::io::Result<()> {
        let mut file = std::fs::File::options()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        Ok(())
    })();
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&temp_path);
        return Err(CoreError::new(ErrorCode::WriteFailed)
            .with_message(format!("writing the temp file failed: {e}")));
    }

    // Preserve the user's file hardening across the rename. create_new opens the
    // temp with the umask-default mode (typically 0644), which would silently
    // downgrade a vault the user chmod'ed 0600. Copy the existing vault file's
    // mode onto the temp before the rename when the vault file exists; for a
    // brand-new vault (no existing file) fall back to 0600. A failure to read or
    // set the mode is non-fatal: the save proceeds with the temp's default mode
    // rather than refusing to write.
    preserve_temp_permissions(path, &temp_path);

    // Atomic rename over the vault file.
    if let Err(e) = std::fs::rename(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(CoreError::new(ErrorCode::WriteFailed)
            .with_message(format!("renaming the temp file over the vault failed: {e}")));
    }

    // Best-effort parent-directory fsync for POSIX durability. The rename has
    // already happened, so a failure here does not corrupt anything: log-and-
    // ignore rather than fail the save and leave the caller thinking it did not
    // write.
    if let Ok(dir) = std::fs::File::open(parent) {
        let _ = dir.sync_all();
    }

    // Re-stat for the new mtime. If the metadata read fails (unlikely right
    // after a successful write), fall back to now: the save did succeed.
    let new_mtime = std::fs::metadata(path)
        .and_then(|m| m.modified())
        .unwrap_or_else(|_| SystemTime::now());

    Ok(new_mtime)
}

/// Copy the existing vault file's permission bits onto the temp file so the
/// atomic rename preserves the user's hardening. When the vault file does not
/// yet exist (a first save), fall back to 0600 so a new vault is owner-only
/// rather than world-readable. POSIX-only: it uses the Unix permission model
/// directly. Any error reading or setting permissions is swallowed: the save is
/// more important than the mode tweak, and the temp keeps its default mode.
#[cfg(unix)]
fn preserve_temp_permissions(vault_path: &std::path::Path, temp_path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;

    let perms = match std::fs::metadata(vault_path) {
        Ok(meta) => meta.permissions(),
        // No existing vault file (first save): default to owner-only 0600.
        Err(_) => std::fs::Permissions::from_mode(0o600),
    };
    let _ = std::fs::set_permissions(temp_path, perms);
}

/// Non-Unix fallback: there is no portable POSIX permission model to copy, so
/// leave the temp file's default permissions in place.
#[cfg(not(unix))]
fn preserve_temp_permissions(_vault_path: &std::path::Path, _temp_path: &std::path::Path) {}

/// A per-call suffix for the temp file name. There is no `rand` crate in the
/// dependency set, so derive a value from the current time's nanos. Combined
/// with the pid in the file name, this is unique enough to avoid collisions
/// between concurrent saves; the temp file is short-lived and gets renamed away
/// immediately.
fn temp_suffix() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

/// Format a `SystemTime` as an RFC3339 / ISO 8601 UTC string via chrono.
fn to_rfc3339(t: SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Utc> = t.into();
    dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// The absolute path as a string. Falls back to the lossy display form when the
/// path cannot be canonicalized (for example, a parent that no longer exists).
fn absolute_path_string(path: &std::path::Path) -> String {
    std::fs::canonicalize(path)
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_else(|_| path.to_string_lossy().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kdbx_core::vault::Vault;
    use keepass::{Database, DatabaseKey};
    use std::io::Write;
    use std::path::PathBuf;

    const TEST_PASSWORD: &str = "test-password-do-not-use";

    // -- helpers ----------------------------------------------------------

    /// A database with a root entry "Existing" carrying a non-protected URL and
    /// a protected Password, plus a nested group /Web for add-into-group tests.
    fn build_db() -> Database {
        let mut db = Database::new();
        db.root_mut().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "Existing");
            e.set_unprotected(fields::URL, "https://old.example.com");
            e.set_protected(fields::PASSWORD, "old-secret");
        });
        db.root_mut()
            .add_group()
            .edit(|g| g.name = "Web".to_string());
        db
    }

    fn path(s: &str) -> VaultPath {
        VaultPath::parse(s).expect("parse path")
    }

    fn simple_input(title: &str) -> EntryInput {
        EntryInput {
            title: title.to_string(),
            fields: vec![FieldInput {
                name: "UserName".to_string(),
                value: "alice".to_string(),
                protected: false,
            }],
            attachments: Vec::new(),
        }
    }

    /// Save a database to a fresh tempfile under the test password and return
    /// the temp handle (kept alive) plus its path. Mirrors the vault.rs fixture.
    fn write_fixture(db: &Database) -> (tempfile::NamedTempFile, PathBuf) {
        let mut buf = Vec::new();
        db.save(&mut buf, DatabaseKey::new().with_password(TEST_PASSWORD))
            .expect("save fixture");
        let mut tmp = tempfile::NamedTempFile::new().expect("tempfile");
        tmp.write_all(&buf).expect("write fixture");
        tmp.flush().expect("flush fixture");
        let p = tmp.path().to_path_buf();
        (tmp, p)
    }

    fn unlocked_vault(db: &Database) -> (tempfile::NamedTempFile, Vault) {
        let (tmp, p) = write_fixture(db);
        let mut vault = Vault::new(p);
        vault.unlock(TEST_PASSWORD, None).expect("unlock");
        (tmp, vault)
    }

    // -- add_entry --------------------------------------------------------

    #[test]
    fn add_entry_into_root_is_findable() {
        let mut db = build_db();
        let id =
            add_entry(&mut db, &path("/"), &simple_input("New Root Entry")).expect("add into root");
        let entry = db.entry(id).expect("entry exists");
        assert_eq!(entry.get_title(), Some("New Root Entry"));
        assert_eq!(entry.get("UserName"), Some("alice"));
        // Resolves by path too.
        let resolved = path("/New Root Entry").resolve_entry(&db).expect("resolve");
        assert_eq!(resolved, id);
    }

    #[test]
    fn add_entry_into_nested_group() {
        let mut db = build_db();
        let id =
            add_entry(&mut db, &path("/Web/"), &simple_input("Nested")).expect("add into /Web");
        let resolved = path("/Web/Nested").resolve_entry(&db).expect("resolve");
        assert_eq!(resolved, id);
    }

    #[test]
    fn add_entry_sets_protected_field() {
        let mut db = build_db();
        let input = EntryInput {
            title: "Has Secret".to_string(),
            fields: vec![FieldInput {
                name: "Password".to_string(),
                value: "s3cret".to_string(),
                protected: true,
            }],
            attachments: Vec::new(),
        };
        let id = add_entry(&mut db, &path("/"), &input).expect("add");
        let entry = db.entry(id).expect("entry");
        let pw = entry.fields.get("Password").expect("password field");
        assert!(pw.is_protected(), "Password should be protected");
        assert_eq!(pw.get(), "s3cret");
    }

    #[test]
    fn add_entry_with_attachment() {
        let mut db = build_db();
        let input = EntryInput {
            title: "Has File".to_string(),
            fields: Vec::new(),
            attachments: vec![AttachmentInput {
                name: "note.txt".to_string(),
                bytes: b"hello".to_vec(),
            }],
        };
        let id = add_entry(&mut db, &path("/"), &input).expect("add with attachment");
        let entry = db.entry(id).expect("entry");
        assert!(
            entry.attachments_named().any(|(n, _)| n == "note.txt"),
            "attachment should be present and named"
        );
    }

    #[test]
    fn add_entry_bad_group_is_group_not_found() {
        let mut db = build_db();
        let err = add_entry(&mut db, &path("/Nope/"), &simple_input("X")).expect_err("bad group");
        assert_eq!(err.code_enum(), ErrorCode::GroupNotFound);
    }

    #[test]
    fn add_entry_empty_title_is_invalid() {
        let mut db = build_db();
        let err = add_entry(&mut db, &path("/"), &simple_input("")).expect_err("empty title");
        assert_eq!(err.code_enum(), ErrorCode::EntryTitleInvalid);
    }

    #[test]
    fn add_entry_control_char_title_is_invalid() {
        let mut db = build_db();
        let err = add_entry(&mut db, &path("/"), &simple_input("bad\u{0007}title"))
            .expect_err("control char title");
        assert_eq!(err.code_enum(), ErrorCode::EntryTitleInvalid);
    }

    #[test]
    fn add_entry_empty_field_name_is_invalid() {
        let mut db = build_db();
        let input = EntryInput {
            title: "T".to_string(),
            fields: vec![FieldInput {
                name: "".to_string(),
                value: "v".to_string(),
                protected: false,
            }],
            attachments: Vec::new(),
        };
        let err = add_entry(&mut db, &path("/"), &input).expect_err("empty field name");
        assert_eq!(err.code_enum(), ErrorCode::FieldNameInvalid);
    }

    #[test]
    fn add_entry_leading_space_field_name_is_invalid() {
        let mut db = build_db();
        let input = EntryInput {
            title: "T".to_string(),
            fields: vec![FieldInput {
                name: " Leading".to_string(),
                value: "v".to_string(),
                protected: false,
            }],
            attachments: Vec::new(),
        };
        let err = add_entry(&mut db, &path("/"), &input).expect_err("leading space");
        assert_eq!(err.code_enum(), ErrorCode::FieldNameInvalid);
    }

    // -- update_field -----------------------------------------------------

    #[test]
    fn update_field_changes_a_field() {
        let mut db = build_db();
        update_field(
            &mut db,
            &path("/Existing"),
            "URL",
            "https://new.example.com",
            None,
        )
        .expect("update");
        let id = path("/Existing").resolve_entry(&db).expect("resolve");
        let entry = db.entry(id).expect("entry");
        assert_eq!(entry.get("URL"), Some("https://new.example.com"));
    }

    #[test]
    fn update_field_protected_none_preserves_existing_protection() {
        let mut db = build_db();
        // Password starts protected; update with protected: None must keep it
        // protected.
        update_field(&mut db, &path("/Existing"), "Password", "new-secret", None)
            .expect("update password");
        let id = path("/Existing").resolve_entry(&db).expect("resolve");
        let entry = db.entry(id).expect("entry");
        let pw = entry.fields.get("Password").expect("password");
        assert!(pw.is_protected(), "protection preserved when None");
        assert_eq!(pw.get(), "new-secret");

        // URL starts unprotected; None keeps it unprotected.
        update_field(
            &mut db,
            &path("/Existing"),
            "URL",
            "https://x.example.com",
            None,
        )
        .expect("update url");
        let entry = db.entry(id).expect("entry");
        let url = entry.fields.get("URL").expect("url");
        assert!(!url.is_protected(), "unprotected stays unprotected");
    }

    #[test]
    fn update_field_some_true_forces_protection() {
        let mut db = build_db();
        update_field(&mut db, &path("/Existing"), "URL", "secret-url", Some(true))
            .expect("force protect");
        let id = path("/Existing").resolve_entry(&db).expect("resolve");
        let url = db
            .entry(id)
            .unwrap()
            .fields
            .get("URL")
            .unwrap()
            .is_protected();
        assert!(url, "Some(true) forces protection on");
    }

    #[test]
    fn update_field_empty_value_clears() {
        let mut db = build_db();
        update_field(&mut db, &path("/Existing"), "URL", "", None).expect("clear");
        let id = path("/Existing").resolve_entry(&db).expect("resolve");
        assert_eq!(db.entry(id).unwrap().get("URL"), Some(""));
    }

    #[test]
    fn update_field_bad_path_is_entry_not_found() {
        let mut db = build_db();
        let err = update_field(&mut db, &path("/Ghost"), "URL", "x", None).expect_err("bad entry");
        assert_eq!(err.code_enum(), ErrorCode::EntryNotFound);
    }

    // -- diff_pending -----------------------------------------------------

    #[test]
    fn diff_no_changes_is_empty() {
        let db = build_db();
        let working = db.clone();
        let d = diff_pending(&db, &working);
        assert!(d.added.is_empty());
        assert!(d.modified.is_empty());
        assert!(d.removed.is_empty());
        assert_eq!(d.summary.num_added, 0);
        assert_eq!(d.summary.num_modified, 0);
        assert_eq!(d.summary.num_removed, 0);
    }

    #[test]
    fn diff_added_entry_reports_path_and_field_count() {
        let canonical = build_db();
        let mut working = canonical.clone();
        let input = EntryInput {
            title: "Brand New".to_string(),
            fields: vec![
                FieldInput {
                    name: "UserName".to_string(),
                    value: "bob".to_string(),
                    protected: false,
                },
                FieldInput {
                    name: "URL".to_string(),
                    value: "https://b.example.com".to_string(),
                    protected: false,
                },
            ],
            attachments: Vec::new(),
        };
        add_entry(&mut working, &path("/Web/"), &input).expect("add");

        let d = diff_pending(&canonical, &working);
        assert_eq!(d.summary.num_added, 1);
        assert_eq!(d.added.len(), 1);
        let a = &d.added[0];
        assert_eq!(a.title, "Brand New");
        assert_eq!(a.path, "/Web/Brand New");
        assert_eq!(a.group_path, "/Web");
        // Title plus the two fields.
        assert_eq!(a.field_count, 3);
        assert!(!a.has_attachments);
        assert!(!a.has_otp);
    }

    #[test]
    fn diff_modified_nonprotected_field_carries_before_after() {
        let canonical = build_db();
        let mut working = canonical.clone();
        update_field(
            &mut working,
            &path("/Existing"),
            "URL",
            "https://new.example.com",
            None,
        )
        .expect("update url");

        let d = diff_pending(&canonical, &working);
        assert_eq!(d.summary.num_modified, 1);
        let m = &d.modified[0];
        assert_eq!(m.title, "Existing");
        assert_eq!(m.path, "/Existing");
        // The URL field change must carry before/after, protected false.
        let fc = m
            .field_changes
            .iter()
            .find(|f| f.field_name() == "URL")
            .expect("URL field change present");
        match fc {
            FieldChangeOut::Plain {
                before,
                after,
                protected,
                ..
            } => {
                assert!(!*protected);
                assert_eq!(before, &serde_json::json!("https://old.example.com"));
                assert_eq!(after, &serde_json::json!("https://new.example.com"));
            }
            FieldChangeOut::Redacted { .. } => panic!("URL is not protected"),
        }
    }

    #[test]
    fn diff_modified_protected_field_is_redacted() {
        let canonical = build_db();
        let mut working = canonical.clone();
        update_field(
            &mut working,
            &path("/Existing"),
            "Password",
            "new-secret",
            None,
        )
        .expect("update password");

        let d = diff_pending(&canonical, &working);
        let m = &d.modified[0];
        let fc = m
            .field_changes
            .iter()
            .find(|f| f.field_name() == "Password")
            .expect("Password field change present");
        match fc {
            FieldChangeOut::Redacted {
                changed, protected, ..
            } => {
                assert!(*changed);
                assert!(*protected);
            }
            FieldChangeOut::Plain { .. } => panic!("Password must be redacted, not shown"),
        }
    }

    #[test]
    fn diff_added_protected_field_is_redacted() {
        // The existing protected-redaction test covers the Modified-field arm
        // (an existing protected field whose value changed). This pins the
        // Added-field arm: a brand-new protected custom field on an entry that
        // already exists must also be redacted, never shown.
        const SECRET_PLAINTEXT: &str = "added-protected-plaintext";

        let canonical = build_db();
        let mut working = canonical.clone();
        // A NEW protected field "ApiKey" on the existing entry. protected: true.
        update_field(
            &mut working,
            &path("/Existing"),
            "ApiKey",
            SECRET_PLAINTEXT,
            Some(true),
        )
        .expect("add new protected field");

        let d = diff_pending(&canonical, &working);
        let m = d
            .modified
            .iter()
            .find(|m| m.title == "Existing")
            .expect("modified Existing entry present");
        let fc = m
            .field_changes
            .iter()
            .find(|f| f.field_name() == "ApiKey")
            .expect("ApiKey field change present");

        // It must be the redacted form: changed and protected, no value.
        match fc {
            FieldChangeOut::Redacted {
                changed, protected, ..
            } => {
                assert!(*changed);
                assert!(*protected);
            }
            FieldChangeOut::Plain { .. } => {
                panic!("a newly-added protected field must be redacted, not shown")
            }
        }

        // Serialize the field change and assert the redacted JSON shape: the
        // object has protected and changed true and carries no before/after.
        let fc_json = serde_json::to_value(fc).expect("serialize field change");
        let obj = fc_json.as_object().expect("field change is an object");
        assert_eq!(obj.get("protected"), Some(&serde_json::json!(true)));
        assert_eq!(obj.get("changed"), Some(&serde_json::json!(true)));
        assert!(!obj.contains_key("before"), "no before on a redacted add");
        assert!(!obj.contains_key("after"), "no after on a redacted add");

        // The protected plaintext must never appear anywhere in the serialized
        // diff, not in this field change and not in the whole DiffPending.
        let whole_json = serde_json::to_string(&d).expect("serialize whole diff");
        assert!(
            !whole_json.contains(SECRET_PLAINTEXT),
            "protected plaintext leaked into the serialized diff"
        );
    }

    #[test]
    fn diff_field_change_json_shapes_match_spec() {
        // Non-protected: { field_name, before, after, protected: false }.
        let plain = FieldChangeOut::Plain {
            field_name: "URL".to_string(),
            before: serde_json::json!("a"),
            after: serde_json::json!("b"),
            protected: false,
        };
        let plain_json = serde_json::to_value(&plain).expect("serialize plain");
        assert_eq!(
            plain_json,
            serde_json::json!({
                "field_name": "URL",
                "before": "a",
                "after": "b",
                "protected": false
            })
        );

        // Protected: { field_name, changed: true, protected: true }. No before
        // or after key at all.
        let redacted = FieldChangeOut::Redacted {
            field_name: "Password".to_string(),
            changed: true,
            protected: true,
        };
        let redacted_json = serde_json::to_value(&redacted).expect("serialize redacted");
        assert_eq!(
            redacted_json,
            serde_json::json!({
                "field_name": "Password",
                "changed": true,
                "protected": true
            })
        );
        let obj = redacted_json.as_object().expect("object");
        assert!(
            !obj.contains_key("before"),
            "no before on a redacted change"
        );
        assert!(!obj.contains_key("after"), "no after on a redacted change");
    }

    #[test]
    fn diff_added_entry_with_otp_sets_has_otp() {
        let canonical = build_db();
        let mut working = canonical.clone();
        let input = EntryInput {
            title: "With OTP".to_string(),
            fields: vec![FieldInput {
                name: fields::OTP.to_string(),
                value: "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP".to_string(),
                protected: true,
            }],
            attachments: Vec::new(),
        };
        add_entry(&mut working, &path("/"), &input).expect("add otp entry");
        let d = diff_pending(&canonical, &working);
        let a = d
            .added
            .iter()
            .find(|a| a.title == "With OTP")
            .expect("otp entry");
        assert!(a.has_otp, "has_otp should be true when an otp field is set");
    }

    // -- discard_pending --------------------------------------------------

    #[test]
    fn discard_pending_resets_working() {
        let db = build_db();
        let (_tmp, mut vault) = unlocked_vault(&db);

        // Stage an add on the working db.
        {
            let working = vault.working_db_mut().expect("working");
            add_entry(working, &path("/"), &simple_input("Staged")).expect("stage add");
        }
        assert!(vault.has_pending_changes());

        let prior = discard_pending(&mut vault).expect("discard");
        assert_eq!(prior, 1);
        assert!(!vault.has_pending_changes(), "stage cleared after discard");
    }

    // -- save_pending -----------------------------------------------------

    #[test]
    fn save_pending_persists_and_settles() {
        let db = build_db();
        let (_tmp, mut vault) = unlocked_vault(&db);
        let vault_path = vault.path().to_path_buf();

        // Stage a new entry.
        {
            let working = vault.working_db_mut().expect("working");
            add_entry(working, &path("/"), &simple_input("Saved Entry")).expect("stage add");
        }
        assert!(vault.has_pending_changes());

        let outcome = save_pending(&mut vault).expect("save");
        assert!(outcome.saved);
        assert_eq!(outcome.num_changes, 1);
        assert!(!outcome.written_at.is_empty());

        // No longer pending after a save.
        assert!(!vault.has_pending_changes());

        // Re-open the file from disk: the new entry is present.
        let reopened = Database::open(
            &mut std::fs::File::open(&vault_path).expect("open saved file"),
            DatabaseKey::new().with_password(TEST_PASSWORD),
        )
        .expect("reopen saved vault");
        assert!(
            reopened
                .iter_all_entries()
                .any(|e| e.get_title() == Some("Saved Entry")),
            "saved entry visible after reopen from disk"
        );
    }

    #[test]
    fn save_pending_refuses_when_file_modified_since_unlock() {
        use std::time::Duration;

        let db = build_db();
        let (_tmp, mut vault) = unlocked_vault(&db);
        let vault_path = vault.path().to_path_buf();

        // Stage a change so has_pending_changes is true.
        {
            let working = vault.working_db_mut().expect("working");
            add_entry(working, &path("/"), &simple_input("Staged")).expect("stage add");
        }
        assert!(vault.has_pending_changes());

        // Bump the on-disk file's mtime well past the unlock mtime: more than the
        // one-second slack. set_modified is stable since Rust 1.75 and needs no
        // new dependency. Ten seconds ahead clears the slack with room to spare.
        let bumped = SystemTime::now() + Duration::from_secs(10);
        std::fs::File::open(&vault_path)
            .expect("open vault file")
            .set_modified(bumped)
            .expect("set mtime forward");

        let err = save_pending(&mut vault).expect_err("save must refuse a modified file");
        assert_eq!(err.code_enum(), ErrorCode::VaultFileModified);

        // When details are populated, pending_changes is reported present.
        if let Some(details) = err.details() {
            assert!(
                details.get("pending_changes").is_some(),
                "details should carry pending_changes: {details:?}"
            );
        }

        // The refusal preserves the stage: nothing was committed or dropped.
        assert!(
            vault.has_pending_changes(),
            "stage preserved after a VAULT_FILE_MODIFIED refusal"
        );
    }

    #[test]
    fn save_pending_with_no_changes_is_no_pending_changes() {
        let db = build_db();
        let (_tmp, mut vault) = unlocked_vault(&db);
        // Nothing staged.
        let err = save_pending(&mut vault).expect_err("nothing to save");
        assert_eq!(err.code_enum(), ErrorCode::NoPendingChanges);
    }

    #[test]
    fn second_save_with_no_changes_is_no_pending_changes() {
        let db = build_db();
        let (_tmp, mut vault) = unlocked_vault(&db);
        {
            let working = vault.working_db_mut().expect("working");
            add_entry(working, &path("/"), &simple_input("Once")).expect("stage");
        }
        save_pending(&mut vault).expect("first save");
        let err = save_pending(&mut vault).expect_err("second save, nothing pending");
        assert_eq!(err.code_enum(), ErrorCode::NoPendingChanges);
    }

    #[test]
    #[cfg(unix)]
    fn save_pending_preserves_0600_vault_mode() {
        use std::os::unix::fs::PermissionsExt;

        let db = build_db();
        let (tmp, p) = write_fixture(&db);

        // Harden the on-disk fixture to owner-only 0600 before unlock, the mode a
        // security-conscious user would chmod a vault to. Setting permissions does
        // not change the file's mtime, so the save-time mtime conflict check stays
        // satisfied.
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))
            .expect("chmod fixture to 0600");
        let before = std::fs::metadata(&p).expect("stat before").permissions();
        assert_eq!(before.mode() & 0o777, 0o600, "fixture starts at 0600");

        let mut vault = Vault::new(p.clone());
        vault.unlock(TEST_PASSWORD, None).expect("unlock");

        // Stage a change and save: the atomic temp+rename must not downgrade the
        // mode back to the umask default (typically 0644).
        {
            let working = vault.working_db_mut().expect("working");
            add_entry(working, &path("/"), &simple_input("Hardened")).expect("stage add");
        }
        save_pending(&mut vault).expect("save");

        let after = std::fs::metadata(&p).expect("stat after").permissions();
        assert_eq!(
            after.mode() & 0o777,
            0o600,
            "vault mode preserved across save_pending"
        );

        drop(tmp);
    }

    #[test]
    fn diff_added_entry_with_legacy_otp_pair_sets_has_otp() {
        // The modern-otp case is covered by diff_added_entry_with_otp_sets_has_otp.
        // This pins the legacy "TOTP Seed" + "TOTP Settings" pair so the diff's
        // has_otp agrees with the read views, which also route through
        // totp::resolve_config.
        let canonical = build_db();
        let mut working = canonical.clone();
        let input = EntryInput {
            title: "Legacy OTP".to_string(),
            fields: vec![
                FieldInput {
                    name: "TOTP Seed".to_string(),
                    value: "JBSWY3DPEHPK3PXP".to_string(),
                    protected: true,
                },
                FieldInput {
                    name: "TOTP Settings".to_string(),
                    value: "30;6".to_string(),
                    protected: false,
                },
            ],
            attachments: Vec::new(),
        };
        add_entry(&mut working, &path("/"), &input).expect("add legacy otp entry");
        let d = diff_pending(&canonical, &working);
        let a = d
            .added
            .iter()
            .find(|a| a.title == "Legacy OTP")
            .expect("legacy otp entry");
        assert!(
            a.has_otp,
            "has_otp should be true for a legacy TOTP Seed + Settings pair"
        );
    }

    // A small test-only helper on the output type, to keep assertions readable.
    impl FieldChangeOut {
        fn field_name(&self) -> &str {
            match self {
                FieldChangeOut::Plain { field_name, .. } => field_name,
                FieldChangeOut::Redacted { field_name, .. } => field_name,
            }
        }
    }
}
