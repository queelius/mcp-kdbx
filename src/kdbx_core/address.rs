//! `EntryAddress`: how an entry-targeting tool names its entry.
//!
//! An entry can be addressed two ways:
//!
//! - by vault path (`/Web/GitHub`, see [`crate::kdbx_core::path`]), which is
//!   readable but session-scoped (`:N` ordinals can shift across sessions) and
//!   absent for a record whose title or ancestor group name is empty; or
//! - by record UUID, which the spec names as the cross-session-stable
//!   identifier and which every read view returns.
//!
//! Every entry-targeting tool accepts exactly one of the two. Supplying both or
//! neither is `INVALID_INPUT` with a message that says so, rather than picking
//! one silently: if the two disagreed, any choice would act on an entry the
//! caller may not have meant.

use crate::kdbx_core::error::{CoreError, CoreResult, ErrorCode};
use crate::kdbx_core::path::VaultPath;
use keepass::Database;
use keepass::db::EntryId;
use uuid::Uuid;

/// A parsed entry address: a vault path or a record UUID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EntryAddress {
    /// Address by vault path.
    Path(VaultPath),
    /// Address by record UUID.
    Uuid(Uuid),
}

impl EntryAddress {
    /// Build an address from a tool's optional `path` and `uuid` inputs.
    ///
    /// Exactly one must be present. Both or neither is `INVALID_INPUT`. A path
    /// is parsed with [`VaultPath::parse`] (its errors propagate unchanged); a
    /// UUID that does not parse is `INVALID_INPUT`. `path_param` names the
    /// tool's path parameter (`path` or `entry_path`) so the message matches
    /// the schema the agent sees.
    pub fn from_parts(
        path: Option<&str>,
        uuid: Option<&str>,
        path_param: &str,
    ) -> CoreResult<EntryAddress> {
        match (path, uuid) {
            (Some(p), None) => VaultPath::parse(p).map(EntryAddress::Path),
            (None, Some(u)) => Uuid::parse_str(u).map(EntryAddress::Uuid).map_err(|_| {
                CoreError::new(ErrorCode::InvalidInput)
                    .with_message("uuid is not a valid UUID")
                    .with_details(serde_json::json!({ "uuid": u }))
            }),
            (Some(_), Some(_)) => Err(CoreError::new(ErrorCode::InvalidInput).with_message(
                format!("provide exactly one of {path_param} or uuid, not both"),
            )),
            (None, None) => Err(CoreError::new(ErrorCode::InvalidInput)
                .with_message(format!("provide exactly one of {path_param} or uuid"))),
        }
    }

    /// Resolve the address against `db` to an entry id.
    ///
    /// A path resolves through [`VaultPath::resolve_entry`]. A UUID matches the
    /// live entry with that record UUID (history snapshots are not entries);
    /// no match is `ENTRY_NOT_FOUND`.
    pub fn resolve(&self, db: &Database) -> CoreResult<EntryId> {
        match self {
            EntryAddress::Path(path) => path.resolve_entry(db),
            EntryAddress::Uuid(uuid) => db
                .iter_all_entries()
                .map(|e| e.id())
                .find(|id| id.uuid() == *uuid)
                .ok_or_else(|| {
                    CoreError::new(ErrorCode::EntryNotFound)
                        .with_message("no entry has that uuid")
                        .with_details(serde_json::json!({ "uuid": uuid.to_string() }))
                }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::fields;

    fn db_with_two_entries() -> (Database, EntryId, EntryId) {
        let mut db = Database::new();
        let titled = db
            .root_mut()
            .add_entry()
            .edit(|e| e.set_unprotected(fields::TITLE, "Titled"))
            .id();
        let untitled = db.root_mut().add_entry().id();
        (db, titled, untitled)
    }

    #[test]
    fn path_alone_resolves() {
        let (db, titled, _) = db_with_two_entries();
        let addr = EntryAddress::from_parts(Some("/Titled"), None, "path").unwrap();
        assert_eq!(addr.resolve(&db).unwrap(), titled);
    }

    #[test]
    fn uuid_alone_resolves_even_an_untitled_entry() {
        let (db, _, untitled) = db_with_two_entries();
        let u = untitled.uuid().to_string();
        let addr = EntryAddress::from_parts(None, Some(&u), "path").unwrap();
        assert_eq!(addr.resolve(&db).unwrap(), untitled);
    }

    #[test]
    fn both_or_neither_is_invalid_input_naming_the_param() {
        let both = EntryAddress::from_parts(
            Some("/Titled"),
            Some("6f9619ff-8b86-d011-b42d-00c04fc964ff"),
            "entry_path",
        )
        .unwrap_err();
        assert_eq!(both.code_enum(), ErrorCode::InvalidInput);
        assert!(both.message().contains("entry_path"));

        let neither = EntryAddress::from_parts(None, None, "path").unwrap_err();
        assert_eq!(neither.code_enum(), ErrorCode::InvalidInput);
        assert!(neither.message().contains("path or uuid"));
    }

    #[test]
    fn malformed_uuid_is_invalid_input() {
        let err = EntryAddress::from_parts(None, Some("not-a-uuid"), "path").unwrap_err();
        assert_eq!(err.code_enum(), ErrorCode::InvalidInput);
    }

    #[test]
    fn unknown_uuid_is_entry_not_found() {
        let (db, _, _) = db_with_two_entries();
        let addr =
            EntryAddress::from_parts(None, Some("6f9619ff-8b86-d011-b42d-00c04fc964ff"), "path")
                .unwrap();
        assert_eq!(
            addr.resolve(&db).unwrap_err().code_enum(),
            ErrorCode::EntryNotFound
        );
    }
}
