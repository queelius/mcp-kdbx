//! View builders: turn keepass records into the read-tool JSON shapes.
//!
//! These produce the exact payloads the spec defines for `kdbx_list_groups`,
//! `kdbx_list_entries`, `kdbx_get_entry`, `kdbx_find_entry`, and
//! `kdbx_list_attachments` (spec section 1). They are metadata-only: no
//! protected value, no attachment bytes, and no OTP code ever crosses through
//! here. Protected fields are reported by name with a `protected: true` flag;
//! revealing a value is a separate, consent-gated tool.
//!
//! Each builder takes the database and a record id and returns `None` when the
//! id does not resolve, which the calling tool maps to `ENTRY_NOT_FOUND` or
//! `GROUP_NOT_FOUND`.

use crate::kdbx_core::path::{vault_path_to_entry, vault_path_to_group};
use chrono::NaiveDateTime;
use keepass::Database;
use keepass::db::{EntryId, GroupId};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::time::SystemTime;

/// The KDBX-canonical field names. These are surfaced through their own keys
/// (username, url, notes) or are implicitly protected (password) and a title;
/// everything else is a custom field listed in `custom_field_names`.
const STANDARD_FIELDS: &[&str] = &["Title", "UserName", "Password", "URL", "Notes"];

/// The longer of an entry's notes shown in a list view (spec: first 200 chars).
const NOTES_PREVIEW_CHARS: usize = 200;

/// Build the list-view summary of an entry (the `kdbx_list_entries` and
/// `kdbx_find_entry` element shape). Metadata only.
pub fn entry_summary(db: &Database, entry_id: EntryId) -> Option<Value> {
    let entry = db.entry(entry_id)?;
    let notes = entry.get("Notes");
    let notes_preview = notes.map(|n| {
        let preview: String = n.chars().take(NOTES_PREVIEW_CHARS).collect();
        preview
    });
    Some(json!({
        "title": entry.get_title().unwrap_or(""),
        "path": entry_path(db, entry_id),
        "uuid": entry.id().uuid().to_string(),
        "username": entry.get("UserName"),
        "url": entry.get("URL"),
        "notes_preview": notes_preview,
        "custom_field_names": custom_field_names(&entry),
        "has_attachments": has_attachments(&entry),
        "has_otp": has_otp(&entry),
        "modified_at": format_time(entry.times.last_modification),
    }))
}

/// Build the full detail view of an entry (the `kdbx_get_entry` shape): full
/// notes and the three timestamps, still without any protected value or
/// attachment bytes.
pub fn entry_detail(db: &Database, entry_id: EntryId) -> Option<Value> {
    let entry = db.entry(entry_id)?;
    Some(json!({
        "title": entry.get_title().unwrap_or(""),
        "path": entry_path(db, entry_id),
        "uuid": entry.id().uuid().to_string(),
        "username": entry.get("UserName"),
        "url": entry.get("URL"),
        "notes": entry.get("Notes"),
        "custom_field_names": custom_field_names(&entry),
        "has_attachments": has_attachments(&entry),
        "has_otp": has_otp(&entry),
        "created_at": format_time(entry.times.creation),
        "modified_at": format_time(entry.times.last_modification),
        "accessed_at": format_time(entry.times.last_access),
    }))
}

/// Build the summary of a group (the `kdbx_list_groups` element shape).
pub fn group_summary(db: &Database, group_id: GroupId) -> Option<Value> {
    let group = db.group(group_id)?;
    Some(json!({
        "name": group.name.clone(),
        "path": group_path(db, group_id),
        "uuid": group.id().uuid().to_string(),
        "num_entries": group.entries().count(),
        "num_subgroups": group.groups().count(),
        "notes": group.notes.clone(),
    }))
}

/// Build the attachment list for an entry (the `kdbx_list_attachments` shape):
/// name, size in bytes, and the hex SHA-256 of the content. No bytes returned;
/// downloading bytes is the consent-gated `kdbx_download_attachment`.
pub fn attachment_list(db: &Database, entry_id: EntryId) -> Option<Value> {
    let entry = db.entry(entry_id)?;
    let attachments: Vec<Value> = entry
        .attachments_named()
        .map(|(name, attachment)| {
            let bytes = attachment.get();
            json!({
                "name": name.to_string(),
                "size_bytes": bytes.len(),
                "sha256": sha256_hex(bytes),
            })
        })
        .collect();
    Some(json!({ "attachments": attachments }))
}

/// The custom (non-standard) fields of an entry, each with its protected flag.
fn custom_field_names(entry: &keepass::db::EntryRef<'_>) -> Vec<Value> {
    let mut fields: Vec<Value> = entry
        .fields
        .iter()
        .filter(|(name, _)| !STANDARD_FIELDS.contains(&name.as_str()))
        .map(|(name, value)| json!({ "name": name.clone(), "protected": value.is_protected() }))
        .collect();
    // Stable order so list output is deterministic across the HashMap iteration.
    fields.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    fields
}

/// Whether the entry references any attachment.
fn has_attachments(entry: &keepass::db::EntryRef<'_>) -> bool {
    entry.attachments_named().next().is_some()
}

/// Whether the entry has a usable TOTP source. Uses the same resolver as
/// `kdbx_get_otp`, so the `has_otp` flag is true exactly when a code could be
/// produced, covering both the modern `otp` field and the legacy `TOTP Seed` +
/// `TOTP Settings` pair.
fn has_otp(entry: &keepass::db::EntryRef<'_>) -> bool {
    crate::kdbx_core::totp::resolve_config(
        entry.get("otp"),
        entry.get("TOTP Seed"),
        entry.get("TOTP Settings"),
    )
    .is_some()
}

/// The canonical path string of an entry, or null when it cannot be built.
fn entry_path(db: &Database, entry_id: EntryId) -> Option<String> {
    vault_path_to_entry(db, entry_id).map(|p| p.format())
}

/// The canonical path string of a group, or null when it cannot be built.
fn group_path(db: &Database, group_id: GroupId) -> Option<String> {
    vault_path_to_group(db, group_id).map(|p| p.format())
}

/// Format an optional KDBX timestamp as `YYYY-MM-DDTHH:MM:SSZ`, or null.
fn format_time(time: Option<NaiveDateTime>) -> Option<String> {
    time.map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
}

/// Lowercase hex SHA-256 of `bytes`. Used for attachment content fingerprints
/// (metadata, not a reveal), so it is a plain digest with no domain prefix. The
/// single definition the adapter shares: the read views and the
/// `kdbx_download_attachment` reveal both report the same fingerprint, so they
/// cannot drift.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// Format a `SystemTime` as `YYYY-MM-DDTHH:MM:SSZ` (UTC). The single definition
/// the adapter shares for audit-event mtime fields (the unlock file mtime and
/// the save before/after mtimes), so the lifecycle and write tools format times
/// the same way.
pub(crate) fn format_system_time(time: SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Utc> = time.into();
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::Database;
    use keepass::db::fields;

    /// Build a database with one entry under a nested group, carrying standard
    /// fields, a custom protected field, and a custom plain field.
    fn db_with_entry() -> (Database, EntryId, GroupId) {
        let mut db = Database::new();
        let web = db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "Web".to_string())
            .id();
        let entry_id = {
            let mut g = db.group_mut(web).unwrap();
            let mut e = g.add_entry();
            let id = e.id();
            e.edit(|e| {
                e.set_unprotected(fields::TITLE, "MyBank");
                e.set_unprotected(fields::USERNAME, "alice");
                e.set_unprotected(fields::URL, "https://bank.example");
                e.set_unprotected("Notes", "a note");
                e.set_protected(fields::PASSWORD, "hunter2");
                e.set_protected("RecoveryCode", "abcd-efgh");
                e.set_unprotected("Reference", "ticket-9");
            });
            id
        };
        (db, entry_id, web)
    }

    #[test]
    fn entry_summary_is_metadata_only_with_path_and_customs() {
        let (db, id, _) = db_with_entry();
        let v = entry_summary(&db, id).expect("entry exists");
        assert_eq!(v["title"], json!("MyBank"));
        assert_eq!(v["path"], json!("/Web/MyBank"));
        assert_eq!(v["username"], json!("alice"));
        assert_eq!(v["url"], json!("https://bank.example"));
        assert_eq!(v["has_otp"], json!(false));
        assert_eq!(v["has_attachments"], json!(false));
        // No password or protected value appears anywhere in the summary.
        let serialized = v.to_string();
        assert!(!serialized.contains("hunter2"));
        assert!(!serialized.contains("abcd-efgh"));
        // custom_field_names lists the two customs with protected flags, sorted
        // by name ascending: "RecoveryCode" sorts before "Reference" ('c' < 'f').
        let customs = v["custom_field_names"].as_array().unwrap();
        assert_eq!(customs.len(), 2);
        assert_eq!(customs[0]["name"], json!("RecoveryCode"));
        assert_eq!(customs[0]["protected"], json!(true));
        assert_eq!(customs[1]["name"], json!("Reference"));
        assert_eq!(customs[1]["protected"], json!(false));
    }

    #[test]
    fn entry_detail_has_full_notes_and_timestamps() {
        let (db, id, _) = db_with_entry();
        let v = entry_detail(&db, id).expect("entry exists");
        assert_eq!(v["notes"], json!("a note"));
        assert!(v.get("created_at").is_some());
        assert!(v.get("modified_at").is_some());
        assert!(v.get("accessed_at").is_some());
        assert!(!v.to_string().contains("hunter2"));
    }

    #[test]
    fn group_summary_counts_children() {
        let (db, _, web) = db_with_entry();
        let v = group_summary(&db, web).expect("group exists");
        assert_eq!(v["name"], json!("Web"));
        assert_eq!(v["path"], json!("/Web"));
        assert_eq!(v["num_entries"], json!(1));
        assert_eq!(v["num_subgroups"], json!(0));
    }

    #[test]
    fn unknown_ids_return_none() {
        let (db, _, _) = db_with_entry();
        let other = {
            let mut d = Database::new();
            d.root_mut()
                .add_entry()
                .edit(|e| e.set_unprotected(fields::TITLE, "x"));
            d.iter_all_entries().next().unwrap().id()
        };
        assert!(entry_summary(&db, other).is_none());
        assert!(entry_detail(&db, other).is_none());
    }
}
