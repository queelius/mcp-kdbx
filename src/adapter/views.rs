//! View builders: turn keepass records into the read-tool JSON shapes.
//!
//! These produce the exact payloads the spec defines for `kdbx_list_groups`,
//! `kdbx_list_entries`, `kdbx_get_entry`, `kdbx_find_entry`, and
//! `kdbx_list_attachments` (spec section 1). They are metadata-only: no
//! protected value, no attachment bytes, and no OTP code ever crosses through
//! here. Protected fields are reported by name with a `protected: true` flag;
//! revealing a value is a separate, consent-gated tool.
//!
//! Which values may be emitted is decided by kdbx-core's one secret predicate,
//! `kdbx_core::visibility::is_secret` (protected, or a Password; never the
//! Title), the rule search and the stage diff share. A standard field
//! (UserName, URL, Notes) that the user marked protected is emitted as `null`
//! under its own key and flagged `protected: true` in `standard_field_names`,
//! exactly as a protected custom field is flagged in `custom_field_names`.
//! Title is the one exception: it is the entry's address in a path, so it is
//! shown even when protected.
//!
//! Each builder takes the database and a record id and returns `None` when the
//! id does not resolve, which the calling tool maps to `ENTRY_NOT_FOUND` or
//! `GROUP_NOT_FOUND`.

use crate::engine::view::View;
use chrono::NaiveDateTime;
use kdbx_core::fields::StandardField;
use kdbx_core::visibility::is_secret;
use keepass::Database;
use keepass::db::{EntryId, GroupId};
use serde_json::{Value, json};
use std::time::SystemTime;

/// The longer of an entry's notes shown in a list view (spec: first 200 chars).
const NOTES_PREVIEW_CHARS: usize = 200;

/// Build the list-view summary of an entry (the `kdbx_list_entries` and
/// `kdbx_find_entry` element shape). Metadata only.
pub fn entry_summary(db: &Database, view: &View, entry_id: EntryId) -> Option<Value> {
    let entry = db.entry(entry_id)?;
    let notes_preview = metadata_value(&entry, StandardField::Notes).map(|n| {
        let preview: String = n.chars().take(NOTES_PREVIEW_CHARS).collect();
        preview
    });
    Some(json!({
        "title": entry.get_title().unwrap_or(""),
        "path": view.path_string(entry_id.uuid()),
        "uuid": entry.id().uuid().to_string(),
        "username": metadata_value(&entry, StandardField::UserName),
        "url": metadata_value(&entry, StandardField::Url),
        "notes_preview": notes_preview,
        "standard_field_names": standard_field_names(&entry),
        "custom_field_names": custom_field_names(&entry),
        "has_attachments": has_attachments(&entry),
        "has_otp": has_otp(&entry),
        "modified_at": format_time(entry.times.last_modification),
    }))
}

/// Build the full detail view of an entry (the `kdbx_get_entry` shape): full
/// notes and the three timestamps, still without any protected value or
/// attachment bytes.
pub fn entry_detail(db: &Database, view: &View, entry_id: EntryId) -> Option<Value> {
    let entry = db.entry(entry_id)?;
    Some(json!({
        "title": entry.get_title().unwrap_or(""),
        "path": view.path_string(entry_id.uuid()),
        "uuid": entry.id().uuid().to_string(),
        "username": metadata_value(&entry, StandardField::UserName),
        "url": metadata_value(&entry, StandardField::Url),
        "notes": metadata_value(&entry, StandardField::Notes),
        "standard_field_names": standard_field_names(&entry),
        "custom_field_names": custom_field_names(&entry),
        "has_attachments": has_attachments(&entry),
        "has_otp": has_otp(&entry),
        "created_at": format_time(entry.times.creation),
        "modified_at": format_time(entry.times.last_modification),
        "accessed_at": format_time(entry.times.last_access),
    }))
}

/// Build the summary of a group (the `kdbx_list_groups` element shape).
pub fn group_summary(db: &Database, view: &View, group_id: GroupId) -> Option<Value> {
    let group = db.group(group_id)?;
    Some(json!({
        "name": group.name.clone(),
        "path": view.path_string(group_id.uuid()),
        "uuid": group.id().uuid().to_string(),
        "num_entries": group.entries().count(),
        "num_subgroups": group.groups().count(),
        "notes": group.notes.clone(),
    }))
}

/// Build the attachment list for an entry (the `kdbx_list_attachments` shape):
/// name, size in bytes, and the keyed fingerprint of the content, in name
/// order. No bytes returned; downloading bytes is the consent-gated
/// `kdbx_download_attachment`.
///
/// Read from the view's snapshot, which never holds attachment bytes: each
/// attachment is already a fingerprint there, computed under the random
/// session key, so it equals the fingerprint a download of the same bytes
/// returns in this session, and gives the client nothing to test
/// master-password guesses against.
pub fn attachment_list(view: &View, entry_id: EntryId) -> Option<Value> {
    let entry = view.snapshot().find_entry(entry_id.uuid())?;
    let attachments: Vec<Value> = entry
        .attachments
        .iter()
        .map(|(name, info)| {
            json!({
                "name": name,
                "size_bytes": info.size,
                "fingerprint": info.fingerprint.to_hex(),
            })
        })
        .collect();
    Some(json!({ "attachments": attachments }))
}

/// The standard fields present on an entry, each with its protected flag, in
/// canonical order (Title, UserName, Password, URL, Notes). The same
/// `{name, protected}` shape as [`custom_field_names`]: together the two lists
/// inventory every field, and a `protected: true` record tells the agent the
/// value is withheld here and must be read with a reveal tool
/// (`kdbx_reveal_password` for Password, `kdbx_reveal_protected` otherwise).
fn standard_field_names(entry: &keepass::db::EntryRef<'_>) -> Vec<Value> {
    StandardField::ALL
        .iter()
        .map(|f| f.kdbx_name())
        .filter_map(|name| entry.fields.get(name).map(|value| field_flag(name, value)))
        .collect()
}

/// The custom (non-standard) fields of an entry, each with its protected flag.
fn custom_field_names(entry: &keepass::db::EntryRef<'_>) -> Vec<Value> {
    let mut fields: Vec<Value> = entry
        .fields
        .iter()
        .filter(|(name, _)| StandardField::from_kdbx_name(name).is_none())
        .map(|(name, value)| field_flag(name, value))
        .collect();
    // Stable order so list output is deterministic across the HashMap iteration.
    fields.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    fields
}

/// The value of the standard field `field` when it may be exposed as
/// metadata: present and not a secret per kdbx-core's
/// `visibility::is_secret`. `None` for an absent field and for any secret,
/// whose value is reachable only through a consent-gated reveal tool.
fn metadata_value<'a>(
    entry: &'a keepass::db::EntryRef<'_>,
    field: StandardField,
) -> Option<&'a str> {
    let name = field.kdbx_name();
    let value = entry.fields.get(name)?;
    (!is_secret(name, value.is_protected())).then(|| value.get().as_str())
}

/// The `{name, protected}` record both field lists use.
fn field_flag(name: &str, value: &keepass::db::Value<String>) -> Value {
    json!({ "name": name, "protected": value.is_protected() })
}

/// Whether the entry references any attachment.
fn has_attachments(entry: &keepass::db::EntryRef<'_>) -> bool {
    entry.attachments_named().next().is_some()
}

/// Whether the entry has a usable TOTP source. Uses the same resolver as
/// `kdbx_get_otp`, so the `has_otp` flag is true exactly when a code could be
/// produced (a malformed configuration is false).
fn has_otp(entry: &keepass::db::EntryRef<'_>) -> bool {
    crate::engine::otp::has_otp(entry)
}

/// Format an optional KDBX timestamp as `YYYY-MM-DDTHH:MM:SSZ`, or null.
fn format_time(time: Option<NaiveDateTime>) -> Option<String> {
    time.map(|t| t.format("%Y-%m-%dT%H:%M:%SZ").to_string())
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
        let v = entry_summary(&db, &View::capture_ephemeral(&db), id).expect("entry exists");
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
        let v = entry_detail(&db, &View::capture_ephemeral(&db), id).expect("entry exists");
        assert_eq!(v["notes"], json!("a note"));
        assert!(v.get("created_at").is_some());
        assert!(v.get("modified_at").is_some());
        assert!(v.get("accessed_at").is_some());
        assert!(!v.to_string().contains("hunter2"));
    }

    /// Build a database with one entry whose UserName, URL, and Notes are all
    /// marked protected (KeePassXC's per-attribute "Protect" toggle, or KeePass
    /// 2's "protect in memory" option), plus a protected Password.
    fn db_with_protected_standard_fields() -> (Database, EntryId) {
        let mut db = Database::new();
        let entry_id = {
            let mut root = db.root_mut();
            let mut e = root.add_entry();
            let id = e.id();
            e.edit(|e| {
                e.set_unprotected(fields::TITLE, "Covert");
                e.set_protected(fields::USERNAME, "secret-user");
                e.set_protected(fields::URL, "https://secret.example");
                e.set_protected(fields::NOTES, "secret notes body");
                e.set_protected(fields::PASSWORD, "hunter2");
            });
            id
        };
        (db, entry_id)
    }

    /// The `{name, protected}` record for `name` in a view's
    /// `standard_field_names` list, or panic when it is absent.
    fn standard_field<'a>(view: &'a Value, name: &str) -> &'a Value {
        view["standard_field_names"]
            .as_array()
            .expect("standard_field_names is an array")
            .iter()
            .find(|f| f["name"] == json!(name))
            .unwrap_or_else(|| panic!("{name} missing from standard_field_names: {view}"))
    }

    /// No secret value of the protected-standard-fields entry appears anywhere
    /// in `view`.
    fn assert_no_protected_value_leaks(view: &Value) {
        let serialized = view.to_string();
        for secret in [
            "secret-user",
            "https://secret.example",
            "secret notes body",
            "hunter2",
        ] {
            assert!(
                !serialized.contains(secret),
                "protected value {secret:?} leaked into view: {serialized}"
            );
        }
    }

    #[test]
    fn entry_summary_nulls_and_marks_protected_standard_fields() {
        let (db, id) = db_with_protected_standard_fields();
        let v = entry_summary(&db, &View::capture_ephemeral(&db), id).expect("entry exists");
        assert_eq!(v["username"], Value::Null);
        assert_eq!(v["url"], Value::Null);
        assert_eq!(v["notes_preview"], Value::Null);
        for name in ["UserName", "URL", "Notes", "Password"] {
            assert_eq!(standard_field(&v, name)["protected"], json!(true));
        }
        // Title is the address; it stays visible.
        assert_eq!(v["title"], json!("Covert"));
        assert_eq!(standard_field(&v, "Title")["protected"], json!(false));
        assert_no_protected_value_leaks(&v);
    }

    #[test]
    fn entry_detail_nulls_and_marks_protected_standard_fields() {
        let (db, id) = db_with_protected_standard_fields();
        let v = entry_detail(&db, &View::capture_ephemeral(&db), id).expect("entry exists");
        assert_eq!(v["username"], Value::Null);
        assert_eq!(v["url"], Value::Null);
        assert_eq!(v["notes"], Value::Null);
        for name in ["UserName", "URL", "Notes", "Password"] {
            assert_eq!(standard_field(&v, name)["protected"], json!(true));
        }
        assert_no_protected_value_leaks(&v);
    }

    #[test]
    fn unprotected_standard_fields_are_unchanged_and_listed_unprotected() {
        let (db, id, _) = db_with_entry();
        for v in [
            entry_summary(&db, &View::capture_ephemeral(&db), id).expect("entry exists"),
            entry_detail(&db, &View::capture_ephemeral(&db), id).expect("entry exists"),
        ] {
            assert_eq!(v["username"], json!("alice"));
            assert_eq!(v["url"], json!("https://bank.example"));
            for name in ["Title", "UserName", "URL", "Notes"] {
                assert_eq!(standard_field(&v, name)["protected"], json!(false));
            }
            assert_eq!(standard_field(&v, "Password")["protected"], json!(true));
            // Canonical order, present fields only, and no customs mixed in.
            let names: Vec<&str> = v["standard_field_names"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| f["name"].as_str().unwrap())
                .collect();
            assert_eq!(names, ["Title", "UserName", "Password", "URL", "Notes"]);
        }
        let summary = entry_summary(&db, &View::capture_ephemeral(&db), id).unwrap();
        assert_eq!(summary["notes_preview"], json!("a note"));
        let detail = entry_detail(&db, &View::capture_ephemeral(&db), id).unwrap();
        assert_eq!(detail["notes"], json!("a note"));
    }

    #[test]
    fn absent_standard_fields_are_null_and_unlisted() {
        let mut db = Database::new();
        let id = {
            let mut root = db.root_mut();
            let mut e = root.add_entry();
            let id = e.id();
            e.edit(|e| e.set_unprotected(fields::TITLE, "Bare"));
            id
        };
        let v = entry_summary(&db, &View::capture_ephemeral(&db), id).expect("entry exists");
        assert_eq!(v["username"], Value::Null);
        assert_eq!(v["url"], Value::Null);
        assert_eq!(v["notes_preview"], Value::Null);
        assert_eq!(
            v["standard_field_names"],
            json!([{ "name": "Title", "protected": false }])
        );
    }

    #[test]
    fn protected_title_stays_visible_as_the_entry_address() {
        let mut db = Database::new();
        let id = {
            let mut root = db.root_mut();
            let mut e = root.add_entry();
            let id = e.id();
            e.edit(|e| e.set_protected(fields::TITLE, "Addressed"));
            id
        };
        for v in [
            entry_summary(&db, &View::capture_ephemeral(&db), id).unwrap(),
            entry_detail(&db, &View::capture_ephemeral(&db), id).unwrap(),
        ] {
            assert_eq!(v["title"], json!("Addressed"));
            assert!(
                v["path"].as_str().unwrap().ends_with("/Addressed"),
                "path still built from the title: {v}"
            );
            assert_eq!(standard_field(&v, "Title")["protected"], json!(true));
        }
    }

    #[test]
    fn an_unprotected_password_never_reaches_a_view() {
        // kdbx-core's is_secret: the Password is a secret whatever its flag.
        let mut db = Database::new();
        let id = db
            .root_mut()
            .add_entry()
            .edit(|e| {
                e.set_unprotected(fields::TITLE, "Open");
                e.set_unprotected(fields::PASSWORD, "flag-off-secret");
            })
            .id();
        let view = View::capture_ephemeral(&db);
        for v in [
            entry_summary(&db, &view, id).unwrap(),
            entry_detail(&db, &view, id).unwrap(),
        ] {
            assert!(!v.to_string().contains("flag-off-secret"), "{v}");
            // The field list reports the stored flag as metadata.
            assert_eq!(standard_field(&v, "Password")["protected"], json!(false));
        }
    }

    #[test]
    fn group_summary_counts_children() {
        let (db, _, web) = db_with_entry();
        let v = group_summary(&db, &View::capture_ephemeral(&db), web).expect("group exists");
        assert_eq!(v["name"], json!("Web"));
        assert_eq!(v["path"], json!("/Web/"));
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
        assert!(entry_summary(&db, &View::capture_ephemeral(&db), other).is_none());
        assert!(entry_detail(&db, &View::capture_ephemeral(&db), other).is_none());
    }
}
