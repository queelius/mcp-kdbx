//! Which entry field values may cross out of the vault as plain metadata.
//!
//! KDBX protection is a per-field flag, not a property of the field's name. The
//! Password is protected by default, but any field can carry the flag: KeePassXC
//! has a per-attribute "Protect" toggle and KeePass 2 can protect UserName,
//! URL, and Notes in memory. So "is this value a secret" must be answered from
//! the stored flag, never from a list of names.
//!
//! [`metadata_value`] is the single rule both consumers share: the read views
//! (`adapter::views`) use it for the values they emit, and the search
//! (`engine::search`) uses it for the values it compares against. Keeping one
//! definition means a field is searchable exactly when it is visible, so search
//! can never become an oracle on a value the views hide.
//!
//! The one deliberate exception is the Title. Entries are addressed by title in
//! vault paths (`/Group/Title`), and every read tool returns those paths, so a
//! protected Title is already visible through `path` and hiding the `title` key
//! would protect nothing. It is reported as metadata regardless of its flag.

use keepass::db::{Entry, fields};

/// The KDBX-canonical standard fields, in canonical order (Title, UserName,
/// Password, URL, Notes). Every other field name is a custom field.
pub const STANDARD_FIELDS: [&str; 5] = fields::KNOWN_FIELDS;

/// The field shown as metadata even when protected, because it is the entry's
/// address in a vault path. See the module docs.
pub const ADDRESS_FIELD: &str = fields::TITLE;

/// True when `name` is one of the [`STANDARD_FIELDS`].
pub fn is_standard_field(name: &str) -> bool {
    STANDARD_FIELDS.contains(&name)
}

/// The value of field `name` when it may be exposed as metadata: the field is
/// present and either unprotected or the [`ADDRESS_FIELD`]. Returns `None` for
/// an absent field and for any other protected field, whose value is reachable
/// only through a consent-gated reveal tool.
pub fn metadata_value<'a>(entry: &'a Entry, name: &str) -> Option<&'a str> {
    let value = entry.fields.get(name)?;
    if value.is_protected() && name != ADDRESS_FIELD {
        return None;
    }
    Some(value.get().as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::Database;

    /// Build a database holding one root entry with the given fields, where each
    /// field is `(name, value, protected)`, and return it.
    fn db_with(fields_spec: &[(&str, &str, bool)]) -> Database {
        let mut db = Database::new();
        db.root_mut().add_entry().edit(|e| {
            for (name, value, protected) in fields_spec {
                if *protected {
                    e.set_protected(*name, *value);
                } else {
                    e.set_unprotected(*name, *value);
                }
            }
        });
        db
    }

    fn only_entry(db: &Database) -> keepass::db::EntryRef<'_> {
        db.iter_all_entries().next().expect("one entry")
    }

    #[test]
    fn unprotected_values_are_visible() {
        let db = db_with(&[(fields::USERNAME, "alice", false), ("Port", "22", false)]);
        let entry = only_entry(&db);
        assert_eq!(metadata_value(&entry, fields::USERNAME), Some("alice"));
        assert_eq!(metadata_value(&entry, "Port"), Some("22"));
    }

    #[test]
    fn protected_values_are_hidden_whatever_the_field_name() {
        let db = db_with(&[
            (fields::USERNAME, "alice", true),
            (fields::URL, "https://x.example", true),
            (fields::NOTES, "n", true),
            (fields::PASSWORD, "pw", true),
            ("PIN", "4321", true),
        ]);
        let entry = only_entry(&db);
        for name in [
            fields::USERNAME,
            fields::URL,
            fields::NOTES,
            fields::PASSWORD,
            "PIN",
        ] {
            assert_eq!(metadata_value(&entry, name), None, "{name} leaked");
        }
    }

    #[test]
    fn protected_title_is_the_address_exception() {
        let db = db_with(&[(fields::TITLE, "Addressed", true)]);
        assert_eq!(
            metadata_value(&only_entry(&db), fields::TITLE),
            Some("Addressed")
        );
    }

    #[test]
    fn absent_field_is_none() {
        let db = db_with(&[]);
        assert_eq!(metadata_value(&only_entry(&db), fields::URL), None);
    }

    #[test]
    fn standard_fields_are_the_five_canonical_names() {
        assert_eq!(
            STANDARD_FIELDS,
            ["Title", "UserName", "Password", "URL", "Notes"]
        );
        assert!(is_standard_field("Notes"));
        assert!(!is_standard_field("notes"));
        assert!(!is_standard_field("PIN"));
    }
}
