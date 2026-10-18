//! `EntryAddress` and `GroupAddress`: how a tool names its target record.
//!
//! An entry or group can be addressed two ways:
//!
//! - by vault path (`/Web/GitHub`, see [`crate::kdbx_core::path`]), which is
//!   readable but session-scoped (`:N` ordinals can shift across sessions) and
//!   absent for a record whose title or ancestor group name is empty; or
//! - by record UUID, which the spec names as the cross-session-stable
//!   identifier and which every read view returns.
//!
//! Every addressed tool accepts exactly one of the two. Supplying both or
//! neither is `INVALID_INPUT` with a message that says so, rather than picking
//! one silently: if the two disagreed, any choice would act on an entry the
//! caller may not have meant.

use crate::kdbx_core::error::{CoreError, CoreResult, ErrorCode};
use crate::kdbx_core::path::VaultPath;
use keepass::Database;
use keepass::db::{EntryId, GroupId};
use uuid::Uuid;

/// What a tool's two address inputs named, once exactly one was present.
enum Named<'a> {
    Path(&'a str),
    Uuid(Uuid),
}

/// The one rule every addressed tool shares: exactly one of the path input
/// and the uuid input. Both or neither is `INVALID_INPUT` naming the two
/// parameters (as the agent sees them in the schema); a malformed UUID is
/// `INVALID_INPUT` too.
fn exactly_one<'a>(
    path: Option<&'a str>,
    uuid: Option<&str>,
    path_param: &str,
    uuid_param: &str,
) -> CoreResult<Named<'a>> {
    match (path, uuid) {
        (Some(p), None) => Ok(Named::Path(p)),
        (None, Some(u)) => Uuid::parse_str(u).map(Named::Uuid).map_err(|_| {
            CoreError::new(ErrorCode::InvalidInput)
                .with_message(format!("{uuid_param} is not a valid UUID"))
                .with_details(serde_json::json!({ uuid_param: u }))
        }),
        (Some(_), Some(_)) => Err(
            CoreError::new(ErrorCode::InvalidInput).with_message(format!(
                "provide exactly one of {path_param} or {uuid_param}, not both"
            )),
        ),
        (None, None) => Err(
            CoreError::new(ErrorCode::InvalidInput).with_message(format!(
                "provide exactly one of {path_param} or {uuid_param}"
            )),
        ),
    }
}

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
    /// Exactly one must be present (see `exactly_one`). A path is parsed with
    /// [`VaultPath::parse`] (its errors propagate unchanged). `path_param`
    /// names the tool's path parameter (`path` or `entry_path`) so the message
    /// matches the schema the agent sees.
    pub fn from_parts(
        path: Option<&str>,
        uuid: Option<&str>,
        path_param: &str,
    ) -> CoreResult<EntryAddress> {
        match exactly_one(path, uuid, path_param, "uuid")? {
            Named::Path(p) => VaultPath::parse(p).map(EntryAddress::Path),
            Named::Uuid(u) => Ok(EntryAddress::Uuid(u)),
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

/// A parsed group address: a vault path or a record UUID. The group-targeting
/// tools (`kdbx_list_groups`, `kdbx_list_entries`, `kdbx_add_entry`) take one,
/// under the same exactly-one rule as entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GroupAddress {
    /// Address by vault path (`/Web` and `/Web/` alike).
    Path(VaultPath),
    /// Address by record UUID.
    Uuid(Uuid),
}

impl GroupAddress {
    /// Build an address from a tool's optional path and uuid inputs, named
    /// `path_param` and `uuid_param` in its schema. Exactly one must be
    /// present.
    pub fn from_parts(
        path: Option<&str>,
        uuid: Option<&str>,
        path_param: &str,
        uuid_param: &str,
    ) -> CoreResult<GroupAddress> {
        match exactly_one(path, uuid, path_param, uuid_param)? {
            Named::Path(p) => VaultPath::parse(p).map(GroupAddress::Path),
            Named::Uuid(u) => Ok(GroupAddress::Uuid(u)),
        }
    }

    /// The root group (`/`).
    pub fn root() -> GroupAddress {
        GroupAddress::Path(VaultPath::parse("/").expect("the root path parses"))
    }

    /// Resolve the address against `db` to a group id. A path resolves
    /// through [`VaultPath::resolve_group`]; a UUID matches any group,
    /// including the root. No match is `GROUP_NOT_FOUND`.
    pub fn resolve(&self, db: &Database) -> CoreResult<GroupId> {
        match self {
            GroupAddress::Path(path) => path.resolve_group(db),
            GroupAddress::Uuid(uuid) => db
                .iter_all_groups()
                .map(|g| g.id())
                .find(|id| id.uuid() == *uuid)
                .ok_or_else(|| {
                    CoreError::new(ErrorCode::GroupNotFound)
                        .with_message("no group has that uuid")
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

    #[test]
    fn group_address_resolves_by_path_or_uuid_including_the_root() {
        let mut db = Database::new();
        let web = db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "Web".to_string())
            .id();
        let by_path = GroupAddress::from_parts(Some("/Web"), None, "group_path", "uuid").unwrap();
        assert_eq!(by_path.resolve(&db).unwrap(), web);
        let u = web.uuid().to_string();
        let by_uuid = GroupAddress::from_parts(None, Some(&u), "group_path", "uuid").unwrap();
        assert_eq!(by_uuid.resolve(&db).unwrap(), web);
        let root = db.root().id().uuid().to_string();
        let root_addr = GroupAddress::from_parts(None, Some(&root), "group_path", "uuid").unwrap();
        assert_eq!(root_addr.resolve(&db).unwrap(), db.root().id());
        assert_eq!(GroupAddress::root().resolve(&db).unwrap(), db.root().id());

        let both = GroupAddress::from_parts(Some("/Web"), Some(&u), "group_path", "group_uuid")
            .unwrap_err();
        assert_eq!(both.code_enum(), ErrorCode::InvalidInput);
        assert!(both.message().contains("group_path or group_uuid"));
        let missing = GroupAddress::from_parts(
            None,
            Some("6f9619ff-8b86-d011-b42d-00c04fc964ff"),
            "group_path",
            "uuid",
        )
        .unwrap()
        .resolve(&db)
        .unwrap_err();
        assert_eq!(missing.code_enum(), ErrorCode::GroupNotFound);
    }
}
