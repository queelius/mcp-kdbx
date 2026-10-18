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

use crate::kdbx_core::address::EntryAddress;
use crate::kdbx_core::error::{CoreError, CoreResult, ErrorCode};
use crate::kdbx_core::path::{VaultPath, vault_path_to_entry, vault_path_to_group};
use crate::kdbx_core::secret::Secret;
use crate::kdbx_core::vault::Vault;
use crate::kdbx_core::vault_file::{
    LockUnavailable, SaveStep, WRITER_LOCK_WAIT, WriterLock, read_with_fingerprint,
    resolve_write_target, write_atomically,
};
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
/// The value is a [`Secret`] (any field may hold one), so `Debug` redacts it.
#[derive(Debug, Clone, Deserialize)]
pub struct FieldInput {
    pub name: String,
    pub value: Secret<String>,
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
    pub bytes: Secret<Vec<u8>>,
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
///
/// `path` and `group_path` are `None` (JSON `null`) when the record has no
/// addressable path (an empty title or group name, see
/// [`vault_path_to_entry`]); `uuid` always identifies it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AddedEntry {
    pub path: Option<String>,
    pub uuid: String,
    pub title: String,
    pub group_path: Option<String>,
    pub field_count: usize,
    pub has_attachments: bool,
    pub has_otp: bool,
}

/// An entry present in both dbs whose fields or attachments changed. `path` is
/// `None` when the record has no addressable path, as for [`AddedEntry`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ModifiedEntry {
    pub path: Option<String>,
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

impl DiffPending {
    /// One human-readable label per staged entry (added, then modified): its
    /// vault path, or its UUID when it has no addressable path. The lock
    /// discard summary and the `stage_discarded` audit event both use this, so
    /// they cannot disagree. A path always starts with `/` and a UUID never
    /// does, so the two forms stay distinguishable.
    pub fn entry_labels(&self) -> Vec<String> {
        let added = self
            .added
            .iter()
            .map(|a| a.path.clone().unwrap_or_else(|| a.uuid.clone()));
        let modified = self
            .modified
            .iter()
            .map(|m| m.path.clone().unwrap_or_else(|| m.uuid.clone()));
        added.chain(modified).collect()
    }
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
    /// Set when the filesystem could not take the writer lock and the save
    /// went ahead without it. Not part of the tool response; the adapter
    /// reports it as the warn-level `writer_lock_unavailable` audit event.
    #[serde(skip)]
    pub writer_lock_unavailable: Option<LockUnavailable>,
    pub saved: bool,
    pub num_changes: usize,
    pub vault_path: String,
    pub written_at: String,
}

// ---------------------------------------------------------------------------
// Validation (spec section 3).
// ---------------------------------------------------------------------------

/// The format characters (General_Category Cf) a title or field name may
/// contain: the zero-width non-joiner U+200C and joiner U+200D. Persian,
/// Hindi, Malayalam, and other scripts need them for correct spelling, and
/// emoji sequences need the joiner. Every other format character is refused
/// (bidi controls that reorder text, zero-width spaces and the word joiner
/// that hide a difference, tag characters, the soft hyphen, and any Cf a
/// future Unicode version adds), so this is an allow-list, not a list of
/// known-bad ranges.
const ALLOWED_FORMAT_CHARS: [char; 2] = ['\u{200C}', '\u{200D}'];

/// True when `c` may not appear in a title or field name: a control character
/// (General_Category Cc: ASCII controls, DEL, the C1 range), or a format
/// character (Cf) other than the [`ALLOWED_FORMAT_CHARS`].
fn is_disallowed_name_char(c: char) -> bool {
    use unicode_properties::{GeneralCategory, UnicodeGeneralCategory};
    match c.general_category() {
        GeneralCategory::Control => true,
        GeneralCategory::Format => !ALLOWED_FORMAT_CHARS.contains(&c),
        _ => false,
    }
}

/// The first disallowed character of `s` (see [`is_disallowed_name_char`]), as
/// its code point label (`U+202E`) for the error details.
fn first_invisible_char(s: &str) -> Option<String> {
    s.chars()
        .find(|c| is_disallowed_name_char(*c))
        .map(|c| format!("U+{:04X}", c as u32))
}

/// Validate an entry title: length 1..=4096, no control characters and no
/// format characters outside the allow-list (see [`is_disallowed_name_char`]). Every write to the Title field goes through here: the `title`
/// of `add_entry`, and `update_field` on `Title`.
fn validate_title(title: &str) -> CoreResult<()> {
    let len = title.chars().count();
    if !(1..=4096).contains(&len) {
        return Err(CoreError::new(ErrorCode::EntryTitleInvalid)
            .with_message("title length must be between 1 and 4096 characters")
            .with_details(serde_json::json!({ "length": len })));
    }
    if let Some(code_point) = first_invisible_char(title) {
        return Err(CoreError::new(ErrorCode::EntryTitleInvalid)
            .with_message("title must not contain control or format characters")
            .with_details(serde_json::json!({ "code_point": code_point })));
    }
    Ok(())
}

/// Validate a field name: length 1..=256, no control characters and no format
/// characters outside the allow-list, no leading or trailing whitespace.
fn validate_field_name(name: &str) -> CoreResult<()> {
    let len = name.chars().count();
    if !(1..=256).contains(&len) {
        return Err(CoreError::new(ErrorCode::FieldNameInvalid)
            .with_message("field name length must be between 1 and 256 characters")
            .with_details(serde_json::json!({ "name": name, "length": len })));
    }
    if let Some(code_point) = first_invisible_char(name) {
        return Err(CoreError::new(ErrorCode::FieldNameInvalid)
            .with_message("field name must not contain control or format characters")
            .with_details(serde_json::json!({ "code_point": code_point })));
    }
    if name != name.trim() {
        return Err(CoreError::new(ErrorCode::FieldNameInvalid)
            .with_message("field name must not have leading or trailing whitespace")
            .with_details(serde_json::json!({ "name": name })));
    }
    Ok(())
}

/// Validate a write of `value` to field `name`: the name itself, and, when the
/// field is the Title, the value as a title. This is the one gate every field
/// write passes, so no path can store a title that `validate_title` refuses.
fn validate_field_write(name: &str, value: &str) -> CoreResult<()> {
    validate_field_name(name)?;
    if name == fields::TITLE {
        validate_title(value)?;
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
///
/// keepass stamps a new entry's creation, modification, and access times with
/// the current time. The entry is built with a plain `edit`, not
/// `edit_tracking`: a history snapshot of the blank, just-created entry would
/// be noise.
pub fn add_entry(
    working: &mut Database,
    group_path: &VaultPath,
    input: &EntryInput,
) -> CoreResult<EntryId> {
    validate_title(&input.title)?;
    for f in &input.fields {
        // The title parameter is the one way to set Title on a new entry; a
        // Title key in the fields map would silently override it.
        if f.name == fields::TITLE {
            return Err(CoreError::new(ErrorCode::FieldNameInvalid)
                .with_message("set the title with the title parameter, not in fields")
                .with_details(serde_json::json!({ "name": f.name })));
        }
        validate_field_write(&f.name, f.value.expose())?;
    }

    let group_id = group_path.resolve_group(working)?;

    // Clone the inputs the closure needs. The edit closure is FnOnce and the
    // keepass write API takes owned values, so we move owned copies in.
    let title = input.title.clone();
    let field_specs: Vec<(String, String, bool)> = input
        .fields
        .iter()
        .map(|f| (f.name.clone(), f.value.expose().clone(), f.protected))
        .collect();
    let attachment_specs: Vec<(String, Vec<u8>)> = input
        .attachments
        .iter()
        .map(|a| (a.name.clone(), a.bytes.expose().clone()))
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

/// Update or set a single field on the entry named by `target` (a vault path or
/// a record UUID). Returns the entry's id.
///
/// `protected = None` preserves an existing field's protection state (and
/// defaults to unprotected for a new field); `Some(b)` forces it. An empty
/// value is allowed and clears the field (the Password-regenerate workflow).
///
/// A real change snapshots the previous entry state into the entry's history
/// and updates its modification time (KeePass edit semantics). Setting a field
/// to the value and protection it already has is a no-op.
/// Propagates `ENTRY_NOT_FOUND` when the target does not resolve to an entry,
/// and validates the field name.
pub fn update_field(
    working: &mut Database,
    target: &EntryAddress,
    field_name: &str,
    value: &str,
    protected: Option<bool>,
) -> CoreResult<EntryId> {
    validate_field_write(field_name, value)?;

    let entry_id = target.resolve(working)?;

    // Decide the protection state before taking the mutable borrow: when the
    // caller did not force it, read the current field's state (false when the
    // field is new).
    let current = working
        .entry(entry_id)
        .and_then(|er| er.fields.get(field_name).cloned());
    let resolved_protected = match protected {
        Some(b) => b,
        None => current.as_ref().map(|v| v.is_protected()).unwrap_or(false),
    };
    let new_value = if resolved_protected {
        Value::protected(value.to_string())
    } else {
        Value::unprotected(value.to_string())
    };

    // Setting a field to exactly what it already holds changes nothing: skip
    // it, so it neither snapshots history nor makes the stage dirty.
    if current.as_ref() == Some(&new_value) {
        return Ok(entry_id);
    }

    let name = field_name.to_string();
    let mut entry_mut = working.entry_mut(entry_id).ok_or_else(|| {
        CoreError::new(ErrorCode::EntryNotFound)
            .with_message("entry disappeared between resolve and write")
            .with_details(serde_json::json!({ "uuid": entry_id.uuid().to_string() }))
    })?;

    // edit_tracking snapshots the pre-edit entry into its history when the
    // tracker drops, and EntryTrack::set bumps LastModificationTime, matching
    // what KeePass and KeePassXC do on an edit. (Plain `edit` did neither, so
    // the old value was lost from history on save.)
    entry_mut.edit_tracking(|e| e.set(name, new_value));

    maintain_history(working, entry_id);

    Ok(entry_id)
}

/// KeePass's default `HistoryMaxItems` when the vault does not set one.
const DEFAULT_HISTORY_MAX_ITEMS: isize = 10;

/// KeePass's default `HistoryMaxSize` (6 MiB) when the vault does not set one.
const DEFAULT_HISTORY_MAX_SIZE: isize = 6 * 1024 * 1024;

/// Restore KeePass history order and limits after a tracked edit.
///
/// Order: KeePass stores history oldest first (it appends each backup), and
/// keepass 0.12 keeps the file order when it parses and writes. But its
/// `History::add_entry`, which `edit_tracking` calls, inserts the new snapshot
/// at index 0. Left alone, a loaded entry's history becomes newest, then
/// oldest to second-newest, and the newest backup is written first. Since
/// every tracked edit here goes through this function, the list is oldest
/// first before the edit, so moving index 0 to the end restores the order.
///
/// Limits: keepass 0.12 never applies `Meta::history_max_items` or
/// `history_max_size`, so history grew by a full snapshot per edit. This
/// applies KeePass's `PwEntry.MaintainBackups`: while there are more than
/// `max_items` backups, remove the oldest; then while their total size is over
/// `max_size`, remove the oldest. A negative limit means unlimited; an unset
/// one takes KeePass's default (10 items, 6 MiB). "Oldest" is the smallest
/// LastModificationTime, the first such on a tie (KeePass's
/// `RemoveOldestBackup`). The size of a backup is the bytes of its field names
/// and values plus its attachments, an approximation of KeePass's
/// `PwEntry.GetSize`.
///
/// keepass 0.12 exposes no way to edit a history list in place, so the kept
/// snapshots are re-added newest-to-oldest through `add_entry` (each insert at
/// index 0), which leaves them oldest first. Attachments that only a removed
/// backup used stay in the database's binary pool, as with any keepass 0.12
/// edit; KeePass drops unreferenced binaries when it next saves.
fn maintain_history(working: &mut Database, entry_id: EntryId) {
    let max_items = working
        .meta
        .history_max_items
        .unwrap_or(DEFAULT_HISTORY_MAX_ITEMS);
    let max_size = working
        .meta
        .history_max_size
        .unwrap_or(DEFAULT_HISTORY_MAX_SIZE);

    let Some(entry) = working.entry(entry_id) else {
        return;
    };
    let Some(history) = entry.history.as_ref() else {
        return;
    };
    // (snapshot, size), in stored order: newest first, then oldest first.
    let mut backups: Vec<(keepass::db::Entry, usize)> = history
        .get_entries()
        .iter()
        .enumerate()
        .map(|(i, snapshot)| {
            let attachment_bytes: usize = entry
                .historical(i)
                .map(|h| h.attachments_named().map(|(_, a)| a.get().len()).sum())
                .unwrap_or(0);
            let field_bytes: usize = snapshot
                .fields
                .iter()
                .map(|(name, value)| name.len() + value.get().len())
                .sum();
            (snapshot.clone(), field_bytes + attachment_bytes)
        })
        .collect();
    if !backups.is_empty() {
        backups.rotate_left(1);
    }

    let remove_oldest = |backups: &mut Vec<(keepass::db::Entry, usize)>| {
        let oldest = backups
            .iter()
            .enumerate()
            .min_by_key(|(i, (snapshot, _))| (snapshot.times.last_modification, *i))
            .map(|(i, _)| i);
        if let Some(i) = oldest {
            backups.remove(i);
        }
    };
    if let Ok(max) = usize::try_from(max_items) {
        while backups.len() > max {
            remove_oldest(&mut backups);
        }
    }
    if let Ok(max) = usize::try_from(max_size) {
        while backups.iter().map(|(_, size)| size).sum::<usize>() > max {
            remove_oldest(&mut backups);
        }
    }

    let mut rebuilt = keepass::db::History::default();
    for (snapshot, _) in backups.into_iter().rev() {
        rebuilt.add_entry(snapshot);
    }
    if let Some(mut entry) = working.entry_mut(entry_id) {
        entry.history = Some(rebuilt);
    }
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

    // Stable order: sort each list by (group_path, title), with the uuid as a
    // final tie-break so same-titled siblings order deterministically. Modified
    // entries carry no group_path field, so derive it from the working db.
    added.sort_by(|a, b| {
        (&a.group_path, &a.title, &a.uuid).cmp(&(&b.group_path, &b.title, &b.uuid))
    });
    modified.sort_by_cached_key(|m| {
        (
            group_path_of(working, &m.uuid),
            m.title.clone(),
            m.uuid.clone(),
        )
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

/// The vault path of the group holding the entry whose hyphenated UUID is
/// `uuid`, used as a sort key. `None` when the entry is gone or its group has
/// no addressable path.
fn group_path_of(working: &Database, uuid: &str) -> Option<String> {
    let entry = working
        .iter_all_entries()
        .find(|e| e.id().uuid().hyphenated().to_string() == uuid)?;
    containing_group_path(working, &entry)
}

/// The vault path of the group that holds `entry`, or `None` when that group
/// has no addressable path.
fn containing_group_path(working: &Database, entry: &keepass::db::EntryRef<'_>) -> Option<String> {
    vault_path_to_group(working, entry.parent().id()).map(|p| p.format())
}

/// Build an [`AddedEntry`] by looking up `uuid` in the working db.
fn map_added_entry(working: &Database, uuid: uuid::Uuid) -> Option<AddedEntry> {
    let entry_ref = working.iter_all_entries().find(|e| e.id().uuid() == uuid)?;
    let eid = entry_ref.id();

    // Both paths are None for a record with no addressable path. There is no
    // fallback string: a placeholder like "/" would alias the root group.
    let path = vault_path_to_entry(working, eid).map(|p| p.format());
    let group_path = containing_group_path(working, &entry_ref);

    let title = entry_ref.get_title().unwrap_or("").to_string();
    let field_count = entry_ref.fields.len();
    let has_attachments = entry_ref.attachments_named().next().is_some();
    // Route has_otp through the same resolver the read views use
    // (src/adapter/views.rs), so kdbx_diff_pending and kdbx_list_entries agree on
    // whether an entry has a usable TOTP source (every source the resolver
    // knows, not just a bare `otp` presence check).
    let has_otp = crate::kdbx_core::totp::resolve_for_entry(&entry_ref).is_some();

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

    let path = vault_path_to_entry(working, eid).map(|p| p.format());
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
/// atomicity", as amended by the 2026-10-18 implementation notes).
///
/// Steps:
/// 1. Refuse when nothing is pending (`NO_PENDING_CHANGES`).
/// 2. Serialize (and encrypt) the working db in memory. The KDF runs here,
///    before the writer lock is taken, so the lock is held only for I/O.
/// 3. Resolve symlinks (a linked vault stays linked; see
///    [`resolve_write_target`]) and take the sidecar writer lock
///    ([`WriterLock`]) next to the real file so another mcp-kdbx
///    instance cannot interleave between the check and the rename.
/// 4. Re-read the vault file and compare its content hash with the baseline
///    recorded at unlock (or at the last save). Any difference, whatever the
///    mtimes say, is `VAULT_FILE_MODIFIED` with the real pending-change count.
///    A vault file that can no longer be read is `WRITE_FAILED`.
/// 5. Write atomically (temp, fsync, rename, fsync dir) and adopt the working
///    db as the new canonical baseline, with the fingerprint of the bytes just
///    written.
///
/// On any failure the stage is preserved and no vault state changes.
pub fn save_pending(vault: &mut Vault) -> CoreResult<SaveOutcome> {
    if !vault.has_pending_changes() {
        return Err(ErrorCode::NoPendingChanges.into());
    }

    let path = vault.path().to_path_buf();
    let baseline = vault.file_baseline()?;

    // Count the changes before we adopt working as canonical (after mark_saved
    // the two dbs are equal and the count would be zero).
    let num_changes = vault.pending_count();

    // Serialize the working db to encrypted bytes in memory.
    let bytes = {
        let (working, key) = vault.working_db_and_key()?;
        let mut buf = Vec::new();
        working.save(&mut buf, key.clone()).map_err(|e| {
            CoreError::new(ErrorCode::WriteFailed)
                .with_message(format!("serializing the vault failed: {e}"))
                .with_details(serde_json::json!({ "step": SaveStep::Serialize }))
        })?;
        buf
    };

    // Resolve symlinks so the rename replaces the real file, not the link.
    let target = resolve_write_target(&path)?;

    let lock = WriterLock::acquire(&target, WRITER_LOCK_WAIT)?;

    let (_, current) = read_with_fingerprint(&target).map_err(|e| {
        CoreError::new(ErrorCode::WriteFailed)
            .with_message(format!("could not re-read the vault file: {e}"))
            .with_details(serde_json::json!({ "step": SaveStep::Reread }))
    })?;
    if !current.same_content(&baseline) {
        return Err(
            CoreError::new(ErrorCode::VaultFileModified).with_details(serde_json::json!({
                "file_mtime_at_unlock": to_rfc3339(baseline.mtime()),
                "file_mtime_now": to_rfc3339(current.mtime()),
                "pending_changes": num_changes,
            })),
        );
    }

    let written = write_atomically(&target, &bytes)?;

    vault.mark_saved(written)?;

    Ok(SaveOutcome {
        writer_lock_unavailable: lock.unavailable(),
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

    fn addr(s: &str) -> EntryAddress {
        EntryAddress::Path(path(s))
    }

    fn simple_input(title: &str) -> EntryInput {
        EntryInput {
            title: title.to_string(),
            fields: vec![FieldInput {
                name: "UserName".to_string(),
                value: "alice".to_string().into(),
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
                value: "s3cret".to_string().into(),
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
                bytes: b"hello".to_vec().into(),
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
    fn script_joiners_are_accepted() {
        // ZWNJ and ZWJ are format characters (Cf) that real text needs:
        // Persian, Hindi, and Malayalam spelling, and emoji sequences.
        for good in [
            "\u{645}\u{6cc}\u{200c}\u{62e}\u{648}\u{627}\u{647}\u{645}", // Persian, with ZWNJ
            "\u{915}\u{94d}\u{200d}\u{937}",                             // Devanagari, with ZWJ
            "\u{1f468}\u{200d}\u{1f469}\u{200d}\u{1f467} family",
        ] {
            validate_title(good).unwrap_or_else(|e| panic!("{good:?}: {e}"));
            validate_field_name(good).unwrap_or_else(|e| panic!("{good:?}: {e}"));
        }
    }

    #[test]
    fn every_other_format_character_is_rejected() {
        // Everything in Cf outside the ZWNJ/ZWJ allow-list: tag characters, the
        // word joiner and invisible operators, deprecated format controls, the
        // Mongolian vowel separator, interlinear annotation, and the soft hyphen.
        for c in [
            '\u{E0041}',
            '\u{E0001}',
            '\u{2060}',
            '\u{2064}',
            '\u{206A}',
            '\u{206F}',
            '\u{180E}',
            '\u{FFF9}',
            '\u{FFFB}',
            '\u{AD}',
        ] {
            let title = format!("Git{c}Hub");
            assert_eq!(
                validate_title(&title).map_err(|e| e.code_enum()),
                Err(ErrorCode::EntryTitleInvalid),
                "U+{:04X}",
                c as u32
            );
        }
    }

    #[test]
    fn every_bidi_control_is_rejected() {
        // Unicode's Bidi_Control set, each one individually.
        let bidi = ['\u{61c}', '\u{200e}', '\u{200f}']
            .into_iter()
            .chain('\u{202a}'..='\u{202e}')
            .chain('\u{2066}'..='\u{2069}');
        for c in bidi {
            let title = format!("Git{c}Hub");
            let err = validate_title(&title).expect_err(&format!("U+{:04X}", c as u32));
            assert_eq!(err.code_enum(), ErrorCode::EntryTitleInvalid);
            assert_eq!(
                err.details().unwrap()["code_point"],
                serde_json::json!(format!("U+{:04X}", c as u32))
            );
        }
    }

    #[test]
    fn titles_and_field_names_reject_unicode_control_and_format_chars() {
        // Cc beyond ASCII (DEL, a C1 control) and spoofing format characters
        // (a bidi override, an isolate, a zero-width space, a byte-order mark)
        // are invisible or reorder text,
        // so a title that looks like "GitHub" could name something else.
        for bad in [
            "Git\u{7f}Hub",
            "Git\u{85}Hub",
            "\u{202e}buHtiG",
            "Git\u{200b}Hub",
            "\u{feff}GitHub",
            "\u{2067}x",
        ] {
            assert_eq!(
                validate_title(bad).unwrap_err().code_enum(),
                ErrorCode::EntryTitleInvalid,
                "title {bad:?}"
            );
            assert_eq!(
                validate_field_name(bad).unwrap_err().code_enum(),
                ErrorCode::FieldNameInvalid,
                "field name {bad:?}"
            );
        }
        // Visible Unicode, including combining marks and spaces, stays valid.
        for good in ["Caf\u{e9}", "Cafe\u{301}", "日本語 ☕", "a/b"] {
            validate_title(good).expect(good);
        }
    }

    #[test]
    fn add_entry_refuses_a_title_in_the_fields_map() {
        // The fields map must not be a second, unvalidated way to set Title.
        let mut db = build_db();
        let input = EntryInput {
            title: "Valid".to_string(),
            fields: vec![FieldInput {
                name: fields::TITLE.to_string(),
                value: String::new().into(),
                protected: false,
            }],
            attachments: Vec::new(),
        };
        let err = add_entry(&mut db, &path("/"), &input).expect_err("Title in fields");
        assert_eq!(err.code_enum(), ErrorCode::FieldNameInvalid);
        assert!(path("/Valid").resolve_entry(&db).is_err(), "nothing staged");
    }

    #[test]
    fn update_field_on_title_is_validated_as_a_title() {
        let mut db = build_db();
        for bad in ["", "Git\u{7}Hub", "\u{202e}x"] {
            let err = update_field(&mut db, &addr("/Existing"), fields::TITLE, bad, None)
                .expect_err("invalid title via update_field");
            assert_eq!(err.code_enum(), ErrorCode::EntryTitleInvalid, "{bad:?}");
        }
        // A valid rename works and the entry is reachable at its new path.
        update_field(&mut db, &addr("/Existing"), fields::TITLE, "Renamed", None).unwrap();
        assert!(path("/Renamed").resolve_entry(&db).is_ok());
    }

    #[test]
    fn add_entry_empty_field_name_is_invalid() {
        let mut db = build_db();
        let input = EntryInput {
            title: "T".to_string(),
            fields: vec![FieldInput {
                name: "".to_string(),
                value: "v".to_string().into(),
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
                value: "v".to_string().into(),
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
            &addr("/Existing"),
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
        update_field(&mut db, &addr("/Existing"), "Password", "new-secret", None)
            .expect("update password");
        let id = path("/Existing").resolve_entry(&db).expect("resolve");
        let entry = db.entry(id).expect("entry");
        let pw = entry.fields.get("Password").expect("password");
        assert!(pw.is_protected(), "protection preserved when None");
        assert_eq!(pw.get(), "new-secret");

        // URL starts unprotected; None keeps it unprotected.
        update_field(
            &mut db,
            &addr("/Existing"),
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
        update_field(&mut db, &addr("/Existing"), "URL", "secret-url", Some(true))
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
        update_field(&mut db, &addr("/Existing"), "URL", "", None).expect("clear");
        let id = path("/Existing").resolve_entry(&db).expect("resolve");
        assert_eq!(db.entry(id).unwrap().get("URL"), Some(""));
    }

    /// Backdate every timestamp of the entry at `p` so a modification made
    /// now is visible at KDBX's one-second precision.
    fn backdate(db: &mut Database, p: &str) {
        let id = path(p).resolve_entry(db).unwrap();
        let old = chrono::DateTime::from_timestamp(1_600_000_000, 0)
            .unwrap()
            .naive_utc();
        let mut e = db.entry_mut(id).unwrap();
        e.times.creation = Some(old);
        e.times.last_modification = Some(old);
    }

    #[test]
    fn update_field_snapshots_history_and_bumps_modification_time() {
        let mut db = build_db();
        backdate(&mut db, "/Existing");
        let id = path("/Existing").resolve_entry(&db).unwrap();
        let (created, modified) = {
            let e = db.entry(id).unwrap();
            assert!(e.history.is_none() || e.history.as_ref().unwrap().get_entries().is_empty());
            (e.times.creation, e.times.last_modification)
        };

        update_field(&mut db, &addr("/Existing"), "Password", "new-secret", None).unwrap();

        let e = db.entry(id).unwrap();
        let history = e.history.as_ref().expect("history recorded");
        assert_eq!(history.get_entries().len(), 1, "one snapshot per edit");
        // The snapshot holds the pre-edit value, as KeePass does.
        assert_eq!(
            history.get_entries()[0].get(fields::PASSWORD),
            Some("old-secret")
        );
        assert!(
            e.times.last_modification > modified,
            "modification time bumped"
        );
        assert_eq!(e.times.creation, created, "creation time untouched");
    }

    /// The URL values held by the history snapshots of the entry at `p`, in
    /// stored order.
    fn history_urls(db: &Database, p: &str) -> Vec<String> {
        let id = path(p).resolve_entry(db).unwrap();
        db.entry(id)
            .unwrap()
            .history
            .as_ref()
            .map(|h| {
                h.get_entries()
                    .iter()
                    .map(|e| e.get(fields::URL).unwrap_or("").to_string())
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Set URL to v1..=vN in turn. The snapshots then hold the pre-edit
    /// values: the original URL, then v1..v(N-1).
    fn edit_url_n_times(db: &mut Database, n: usize) {
        for i in 1..=n {
            update_field(db, &addr("/Existing"), fields::URL, &format!("v{i}"), None).unwrap();
        }
    }

    #[test]
    fn history_is_stored_oldest_first_and_trimmed_to_ten_by_default() {
        // KeePass stores history oldest first and, by default, keeps 10
        // items. keepass 0.12 inserts each new snapshot at index 0 and never
        // trims, so the entry would grow without bound in mixed order.
        let mut db = build_db();
        edit_url_n_times(&mut db, 12);
        let urls = history_urls(&db, "/Existing");
        let expected: Vec<String> = (2..=11).map(|i| format!("v{i}")).collect();
        assert_eq!(urls, expected, "the 10 newest snapshots, oldest first");
    }

    #[test]
    fn history_order_survives_save_and_a_further_edit_after_reopen() {
        // Saved oldest first, reopened in file order, and a further edit on the
        // reopened entry appends its snapshot at the end.
        let db = build_db();
        let (_tmp, mut vault) = unlocked_vault(&db);
        edit_url_n_times(vault.working_db_mut().unwrap(), 3);
        save_pending(&mut vault).unwrap();
        let path_on_disk = vault.path().to_path_buf();
        drop(vault);

        let mut reopened = Vault::new(path_on_disk);
        reopened.unlock(TEST_PASSWORD, None).unwrap();
        let working = reopened.working_db_mut().unwrap();
        assert_eq!(
            history_urls(working, "/Existing"),
            ["https://old.example.com", "v1", "v2"]
        );
        update_field(working, &addr("/Existing"), fields::URL, "v4", None).unwrap();
        assert_eq!(
            history_urls(working, "/Existing"),
            ["https://old.example.com", "v1", "v2", "v3"]
        );
    }

    #[test]
    fn history_honors_the_vault_max_items_and_negative_means_unlimited() {
        let mut db = build_db();
        db.meta.history_max_items = Some(3);
        edit_url_n_times(&mut db, 6);
        assert_eq!(history_urls(&db, "/Existing"), ["v3", "v4", "v5"]);

        let mut db = build_db();
        db.meta.history_max_items = Some(-1);
        edit_url_n_times(&mut db, 12);
        assert_eq!(history_urls(&db, "/Existing").len(), 12);
    }

    #[test]
    fn history_honors_the_vault_max_size_dropping_the_oldest() {
        // Each snapshot carries a ~1000-byte URL, so a 2500-byte budget keeps
        // the newest two.
        let mut db = build_db();
        db.meta.history_max_size = Some(2500);
        let big = |c: char| c.to_string().repeat(1000);
        for c in ['a', 'b', 'c', 'd'] {
            update_field(&mut db, &addr("/Existing"), fields::URL, &big(c), None).unwrap();
        }
        assert_eq!(history_urls(&db, "/Existing"), [big('b'), big('c')]);
    }

    #[test]
    fn update_field_with_identical_value_is_a_no_op() {
        // Re-setting the same value and protection must not grow history or
        // make the stage dirty.
        let canonical = build_db();
        let mut working = canonical.clone();
        update_field(
            &mut working,
            &addr("/Existing"),
            "URL",
            "https://old.example.com",
            None,
        )
        .unwrap();
        assert_eq!(working, canonical);
    }

    #[test]
    fn add_entry_sets_creation_and_modification_times_without_history() {
        let mut db = build_db();
        let id = add_entry(&mut db, &path("/"), &simple_input("Timed")).unwrap();
        let e = db.entry(id).unwrap();
        assert!(e.times.creation.is_some());
        assert!(e.times.last_modification.is_some());
        assert!(
            e.history
                .as_ref()
                .is_none_or(|h| h.get_entries().is_empty()),
            "a brand-new entry has no history snapshot of its blank state"
        );
    }

    #[test]
    fn update_field_bad_path_is_entry_not_found() {
        let mut db = build_db();
        let err = update_field(&mut db, &addr("/Ghost"), "URL", "x", None).expect_err("bad entry");
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
                    value: "bob".to_string().into(),
                    protected: false,
                },
                FieldInput {
                    name: "URL".to_string(),
                    value: "https://b.example.com".to_string().into(),
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
        assert_eq!(a.path.as_deref(), Some("/Web/Brand New"));
        assert_eq!(a.group_path.as_deref(), Some("/Web"));
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
            &addr("/Existing"),
            "URL",
            "https://new.example.com",
            None,
        )
        .expect("update url");

        let d = diff_pending(&canonical, &working);
        assert_eq!(d.summary.num_modified, 1);
        let m = &d.modified[0];
        assert_eq!(m.title, "Existing");
        assert_eq!(m.path.as_deref(), Some("/Existing"));
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
            &addr("/Existing"),
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
            &addr("/Existing"),
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
                value: "otpauth://totp/Example?secret=JBSWY3DPEHPK3PXP"
                    .to_string()
                    .into(),
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

    /// Replace the vault file's bytes with a different valid vault (as another
    /// writer would) and stamp it with `mtime`.
    fn external_rewrite(vault_path: &std::path::Path, mtime: SystemTime) {
        let mut other = build_db();
        other
            .root_mut()
            .add_entry()
            .edit(|e| e.set_unprotected(fields::TITLE, "Written Elsewhere"));
        let mut buf = Vec::new();
        other
            .save(&mut buf, DatabaseKey::new().with_password(TEST_PASSWORD))
            .expect("serialize external vault");
        std::fs::write(vault_path, &buf).expect("external write");
        std::fs::File::options()
            .write(true)
            .open(vault_path)
            .expect("open for set_modified")
            .set_modified(mtime)
            .expect("set mtime");
    }

    #[test]
    fn save_pending_refuses_a_backdated_external_write() {
        // A restore or sync tool that preserves an older mtime defeated the old
        // "mtime moved forward by more than 1s" heuristic. Content identity
        // catches it.
        let db = build_db();
        let (_tmp, mut vault) = unlocked_vault(&db);
        let vault_path = vault.path().to_path_buf();
        let at_unlock = vault.mtime_at_unlock().expect("unlocked");
        update_field(
            vault.working_db_mut().unwrap(),
            &addr("/Existing"),
            "URL",
            "x",
            None,
        )
        .unwrap();

        external_rewrite(&vault_path, at_unlock - std::time::Duration::from_secs(60));

        let err = save_pending(&mut vault).expect_err("must refuse");
        assert_eq!(err.code_enum(), ErrorCode::VaultFileModified);
        assert!(vault.has_pending_changes(), "stage preserved on refusal");
        // The external write survives untouched.
        let on_disk = Database::open(
            &mut std::fs::File::open(&vault_path).unwrap(),
            DatabaseKey::new().with_password(TEST_PASSWORD),
        )
        .unwrap();
        assert!(
            on_disk
                .iter_all_entries()
                .any(|e| e.get_title() == Some("Written Elsewhere"))
        );
    }

    #[test]
    fn save_pending_refuses_an_external_write_within_one_second() {
        // The old one-second slack let a write landing within it be clobbered.
        let db = build_db();
        let (_tmp, mut vault) = unlocked_vault(&db);
        let vault_path = vault.path().to_path_buf();
        let at_unlock = vault.mtime_at_unlock().expect("unlocked");
        update_field(
            vault.working_db_mut().unwrap(),
            &addr("/Existing"),
            "URL",
            "x",
            None,
        )
        .unwrap();

        external_rewrite(
            &vault_path,
            at_unlock + std::time::Duration::from_millis(900),
        );

        let err = save_pending(&mut vault).expect_err("must refuse");
        assert_eq!(err.code_enum(), ErrorCode::VaultFileModified);
    }

    #[test]
    fn save_pending_ignores_an_mtime_only_touch() {
        // Identity is the content, not the timestamp: a touch that leaves the
        // bytes unchanged is not a conflict.
        let db = build_db();
        let (_tmp, mut vault) = unlocked_vault(&db);
        let vault_path = vault.path().to_path_buf();
        add_entry(
            vault.working_db_mut().unwrap(),
            &path("/"),
            &simple_input("Staged"),
        )
        .unwrap();
        std::fs::File::options()
            .write(true)
            .open(&vault_path)
            .unwrap()
            .set_modified(SystemTime::now() + std::time::Duration::from_secs(30))
            .unwrap();
        save_pending(&mut vault).expect("an mtime-only touch is not a conflict");
    }

    #[test]
    fn vault_file_modified_reports_the_real_pending_count() {
        let db = build_db();
        let (_tmp, mut vault) = unlocked_vault(&db);
        let vault_path = vault.path().to_path_buf();
        {
            let working = vault.working_db_mut().unwrap();
            add_entry(working, &path("/"), &simple_input("One")).unwrap();
            add_entry(working, &path("/Web/"), &simple_input("Two")).unwrap();
            update_field(working, &addr("/Existing"), "URL", "x", None).unwrap();
        }
        external_rewrite(&vault_path, SystemTime::now());

        let err = save_pending(&mut vault).expect_err("must refuse");
        assert_eq!(err.code_enum(), ErrorCode::VaultFileModified);
        let details = err.details().expect("details");
        assert_eq!(details["pending_changes"], serde_json::json!(3));
        assert!(details["file_mtime_at_unlock"].is_string());
        assert!(details["file_mtime_now"].is_string());
    }

    #[test]
    fn save_pending_updates_the_baseline_to_the_written_file() {
        // After a save the baseline is the file just written: a second save
        // succeeds, and the recorded mtime is the new file's real mtime.
        let db = build_db();
        let (_tmp, mut vault) = unlocked_vault(&db);
        let vault_path = vault.path().to_path_buf();
        add_entry(
            vault.working_db_mut().unwrap(),
            &path("/"),
            &simple_input("First"),
        )
        .unwrap();
        save_pending(&mut vault).expect("first save");
        let on_disk_mtime = std::fs::metadata(&vault_path).unwrap().modified().unwrap();
        assert_eq!(vault.mtime_at_unlock().unwrap(), on_disk_mtime);

        add_entry(
            vault.working_db_mut().unwrap(),
            &path("/"),
            &simple_input("Second"),
        )
        .unwrap();
        save_pending(&mut vault).expect("second save against the new baseline");
    }

    #[test]
    #[cfg(unix)]
    fn save_through_a_symlink_writes_the_target_and_keeps_the_link() {
        // A vault reached through a symlink (dotfile managers, synced folders)
        // must stay a symlink: the save writes next to the target and renames
        // onto it, instead of replacing the link with a regular file.
        let db = build_db();
        let (tmp, target) = write_fixture(&db);
        let dir = tempfile::tempdir().unwrap();
        let link = dir.path().join("link.kdbx");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let mut vault = Vault::new(link.clone());
        vault.unlock(TEST_PASSWORD, None).unwrap();
        add_entry(
            vault.working_db_mut().unwrap(),
            &path("/"),
            &simple_input("Via Link"),
        )
        .unwrap();
        save_pending(&mut vault).expect("save through the link");

        let meta = std::fs::symlink_metadata(&link).unwrap();
        assert!(meta.file_type().is_symlink(), "the link survives the save");
        let reopened = Database::open(
            &mut std::fs::File::open(&target).unwrap(),
            DatabaseKey::new().with_password(TEST_PASSWORD),
        )
        .unwrap();
        assert!(
            reopened
                .iter_all_entries()
                .any(|e| e.get_title() == Some("Via Link")),
            "the target file holds the saved change"
        );
        // Nothing (no temp, no lock file) was left next to the link.
        let leftovers: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .filter(|n| n != "link.kdbx")
            .collect();
        assert!(
            leftovers.is_empty(),
            "stray files next to the link: {leftovers:?}"
        );
        drop(tmp);
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
        // totp::resolve_for_entry.
        let canonical = build_db();
        let mut working = canonical.clone();
        let input = EntryInput {
            title: "Legacy OTP".to_string(),
            fields: vec![
                FieldInput {
                    name: "TOTP Seed".to_string(),
                    value: "JBSWY3DPEHPK3PXP".to_string().into(),
                    protected: true,
                },
                FieldInput {
                    name: "TOTP Settings".to_string(),
                    value: "30;6".to_string().into(),
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
