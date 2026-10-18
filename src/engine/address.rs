//! `EntryAddress` and `GroupAddress`: how a tool names its target record.
//!
//! An entry or group can be addressed two ways:
//!
//! - by vault path (`/Web/GitHub`, kdbx-core's ecosystem grammar), which is
//!   readable but session-scoped (`:N` ordinals can shift across sessions) and
//!   absent for a record whose title or ancestor group name is empty; or
//! - by record UUID, which the spec names as the cross-session-stable
//!   identifier and which every read view returns.
//!
//! Every addressed tool accepts exactly one of the two. Supplying both or
//! neither is `INVALID_INPUT` with a message that says so, rather than picking
//! one silently: if the two disagreed, any choice would act on an entry the
//! caller may not have meant.

use crate::engine::error::{CoreError, CoreResult, ErrorCode};
use crate::engine::view::{View, entry_id, group_id};
use kdbx_core::path::{PathError, ResolveError, VaultPath};
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

/// Parse a path string with the ecosystem grammar. A malformed path is
/// `PATH_INVALID` (distinct from the not-found codes, which mean a
/// well-formed path matched nothing), with kdbx-core's reason leading the
/// message.
pub fn parse_path(input: &str) -> CoreResult<VaultPath> {
    VaultPath::parse(input).map_err(|e| path_invalid(input, &e))
}

/// `PATH_INVALID` for `input`: kdbx-core's reason, then the grammar summary.
fn path_invalid(input: &str, e: &PathError) -> CoreError {
    let code = ErrorCode::PathInvalid;
    CoreError::new(code)
        .with_message(format!("{e}. {}", code.default_message()))
        .with_details(serde_json::json!({ "path": input }))
}

/// Map a well-formed path that matched nothing onto the existing not-found
/// codes: a missing group at any level is `GROUP_NOT_FOUND`, a missing entry
/// `ENTRY_NOT_FOUND`, and a group-shaped path given where an entry is wanted
/// (a trailing slash never names an entry) `ENTRY_NOT_FOUND` too. The details
/// name the path and, for a missing segment, its name and ordinal.
fn not_found(path: &VaultPath, e: &ResolveError) -> CoreError {
    let formatted = path.format();
    let segment_details = |segment: Option<&kdbx_core::path::Segment>| match segment {
        Some(segment) => serde_json::json!({
            "path": formatted,
            "segment": segment.name(),
            "ordinal": segment.ordinal().unwrap_or(1),
        }),
        None => serde_json::json!({ "path": formatted }),
    };
    match e {
        ResolveError::GroupNotFound { segment } => CoreError::new(ErrorCode::GroupNotFound)
            .with_message(e.to_string())
            .with_details(segment_details(path.segments().get(*segment))),
        ResolveError::EntryNotFound => CoreError::new(ErrorCode::EntryNotFound)
            .with_message(e.to_string())
            .with_details(segment_details(path.segments().last())),
        // GroupShapedPath, and any reason a later kdbx-core adds: the path
        // names no entry.
        _ => CoreError::new(ErrorCode::EntryNotFound)
            .with_message(e.to_string())
            .with_details(serde_json::json!({ "path": formatted })),
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
    /// [`parse_path`]. `path_param` names the tool's path parameter (`path`
    /// or `entry_path`) so the message matches the schema the agent sees.
    pub fn from_parts(
        path: Option<&str>,
        uuid: Option<&str>,
        path_param: &str,
    ) -> CoreResult<EntryAddress> {
        match exactly_one(path, uuid, path_param, "uuid")? {
            Named::Path(p) => parse_path(p).map(EntryAddress::Path),
            Named::Uuid(u) => Ok(EntryAddress::Uuid(u)),
        }
    }

    /// Resolve the address against `view` (a capture of `db`) to the live
    /// entry id in `db`.
    ///
    /// A path resolves through kdbx-core's `VaultPath::resolve_entry` (a
    /// group-shaped path never names an entry). A UUID matches the entry with
    /// that record UUID (history snapshots are not entries). No match is
    /// `ENTRY_NOT_FOUND`.
    pub fn resolve(&self, db: &Database, view: &View) -> CoreResult<EntryId> {
        let uuid = match self {
            EntryAddress::Path(path) => {
                path.resolve_entry(view.snapshot())
                    .map_err(|e| not_found(path, &e))?
                    .uuid
            }
            EntryAddress::Uuid(uuid) => *uuid,
        };
        entry_id(db, uuid).ok_or_else(|| {
            CoreError::new(ErrorCode::EntryNotFound)
                .with_message("no entry has that uuid")
                .with_details(serde_json::json!({ "uuid": uuid.to_string() }))
        })
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
            Named::Path(p) => parse_path(p).map(GroupAddress::Path),
            Named::Uuid(u) => Ok(GroupAddress::Uuid(u)),
        }
    }

    /// The root group (`/`).
    pub fn root() -> GroupAddress {
        GroupAddress::Path(VaultPath::root())
    }

    /// Resolve the address against `view` (a capture of `db`) to the live
    /// group id in `db`. A path resolves through kdbx-core's
    /// `VaultPath::resolve_group`, which reads every segment as a group (so
    /// `/Web` and `/Web/` name the same group); a UUID matches any group,
    /// including the root. No match is `GROUP_NOT_FOUND`.
    pub fn resolve(&self, db: &Database, view: &View) -> CoreResult<GroupId> {
        let uuid = match self {
            GroupAddress::Path(path) => {
                path.resolve_group(view.snapshot())
                    .map_err(|e| not_found(path, &e))?
                    .uuid
            }
            GroupAddress::Uuid(uuid) => *uuid,
        };
        group_id(db, uuid).ok_or_else(|| {
            CoreError::new(ErrorCode::GroupNotFound)
                .with_message("no group has that uuid")
                .with_details(serde_json::json!({ "uuid": uuid.to_string() }))
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::db::fields;

    /// Resolve an entry path in `db` the way every entry tool does.
    fn entry_at(db: &Database, path: &str) -> CoreResult<EntryId> {
        EntryAddress::from_parts(Some(path), None, "path")?
            .resolve(db, &View::capture_ephemeral(db))
    }

    /// Resolve a group path in `db` the way every group tool does.
    fn group_at(db: &Database, path: &str) -> CoreResult<GroupId> {
        GroupAddress::from_parts(Some(path), None, "group_path", "uuid")?
            .resolve(db, &View::capture_ephemeral(db))
    }

    /// A database with group /Web holding three entries titled "Dup" and one
    /// titled "Solo".
    fn db_with_duplicates() -> (Database, Vec<EntryId>) {
        let mut db = Database::new();
        let web = db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "Web".to_string())
            .id();
        let mut dups = Vec::new();
        for _ in 0..3 {
            let id = db
                .group_mut(web)
                .unwrap()
                .add_entry()
                .edit(|e| e.set_unprotected(fields::TITLE, "Dup"))
                .id();
            dups.push(id);
        }
        db.group_mut(web)
            .unwrap()
            .add_entry()
            .edit(|e| e.set_unprotected(fields::TITLE, "Solo"));
        (db, dups)
    }

    #[test]
    fn malformed_paths_are_path_invalid() {
        // Including the escapes kdbx-core made strict: an unknown escape is
        // malformed, not a literal character.
        for bad in ["Bank", "/Web//x", "/dangling\\", "/a:0", "/unknown\\q", ""] {
            let err = EntryAddress::from_parts(Some(bad), None, "path").unwrap_err();
            assert_eq!(err.code_enum(), ErrorCode::PathInvalid, "{bad:?}");
            assert_eq!(err.details().unwrap()["path"], serde_json::json!(bad));
        }
    }

    #[test]
    fn control_character_escapes_name_real_characters() {
        // `\n` is a line feed (the shared text escape), so a title holding one
        // is addressable, and its emitted path round-trips.
        let mut db = Database::new();
        let id = db
            .root_mut()
            .add_entry()
            .edit(|e| e.set_unprotected(fields::TITLE, "two\nlines"))
            .id();
        let view = View::capture_ephemeral(&db);
        let emitted = view.path_string(id.uuid()).unwrap();
        assert_eq!(emitted, "/two\\nlines");
        assert_eq!(entry_at(&db, &emitted).unwrap(), id);
    }

    #[test]
    fn duplicate_titles_resolve_by_uuid_order_in_every_clone() {
        // keepass 0.12 keeps children in a per-process randomized hash set;
        // the ordinal must follow record UUID order, identically in the
        // canonical db and its working clone.
        let (db, mut dups) = db_with_duplicates();
        dups.sort_by_key(|id| id.uuid());
        let clone = db.clone();
        for (n, expected) in dups.iter().enumerate() {
            let path = format!("/Web/Dup:{}", n + 1);
            assert_eq!(entry_at(&db, &path).unwrap(), *expected, "{path}");
            assert_eq!(entry_at(&clone, &path).unwrap(), *expected, "{path}");
        }
        assert_eq!(entry_at(&db, "/Web/Dup").unwrap(), dups[0]);
        let past_end = entry_at(&db, "/Web/Dup:4").unwrap_err();
        assert_eq!(past_end.code_enum(), ErrorCode::EntryNotFound);
        assert_eq!(past_end.details().unwrap()["ordinal"], serde_json::json!(4));
    }

    #[test]
    fn every_emitted_path_resolves_back_to_its_own_record() {
        let (db, _) = db_with_duplicates();
        let view = View::capture_ephemeral(&db);
        for entry in db.iter_all_entries() {
            let path = view.path_string(entry.id().uuid()).expect("titled");
            assert_eq!(entry_at(&db, &path).unwrap(), entry.id(), "{path}");
        }
        for group in db.iter_all_groups() {
            let path = view.path_string(group.id().uuid()).expect("named");
            assert!(path.ends_with('/'), "group paths keep their slash: {path}");
            assert_eq!(group_at(&db, &path).unwrap(), group.id(), "{path}");
        }
    }

    #[test]
    fn not_found_codes_name_the_missing_segment() {
        let (db, _) = db_with_duplicates();
        let group = group_at(&db, "/Web/Nope/").unwrap_err();
        assert_eq!(group.code_enum(), ErrorCode::GroupNotFound);
        assert_eq!(
            group.details().unwrap()["segment"],
            serde_json::json!("Nope")
        );
        // A missing group on the way to an entry is still GROUP_NOT_FOUND.
        let via = entry_at(&db, "/Nope/Dup").unwrap_err();
        assert_eq!(via.code_enum(), ErrorCode::GroupNotFound);
        let entry = entry_at(&db, "/Web/Ghost").unwrap_err();
        assert_eq!(entry.code_enum(), ErrorCode::EntryNotFound);
        assert_eq!(
            entry.details().unwrap()["segment"],
            serde_json::json!("Ghost")
        );
        // A trailing slash addresses a group, never an entry.
        for shaped in ["/Web/Solo/", "/"] {
            let err = entry_at(&db, shaped).unwrap_err();
            assert_eq!(err.code_enum(), ErrorCode::EntryNotFound, "{shaped}");
        }
        // Group tools accept the entry-shaped spelling of a group path.
        assert_eq!(
            group_at(&db, "/Web").unwrap(),
            group_at(&db, "/Web/").unwrap()
        );
    }

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
        assert_eq!(
            addr.resolve(&db, &View::capture_ephemeral(&db)).unwrap(),
            titled
        );
    }

    #[test]
    fn uuid_alone_resolves_even_an_untitled_entry() {
        let (db, _, untitled) = db_with_two_entries();
        let u = untitled.uuid().to_string();
        let addr = EntryAddress::from_parts(None, Some(&u), "path").unwrap();
        assert_eq!(
            addr.resolve(&db, &View::capture_ephemeral(&db)).unwrap(),
            untitled
        );
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
            addr.resolve(&db, &View::capture_ephemeral(&db))
                .unwrap_err()
                .code_enum(),
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
        assert_eq!(
            by_path.resolve(&db, &View::capture_ephemeral(&db)).unwrap(),
            web
        );
        let u = web.uuid().to_string();
        let by_uuid = GroupAddress::from_parts(None, Some(&u), "group_path", "uuid").unwrap();
        assert_eq!(
            by_uuid.resolve(&db, &View::capture_ephemeral(&db)).unwrap(),
            web
        );
        let root = db.root().id().uuid().to_string();
        let root_addr = GroupAddress::from_parts(None, Some(&root), "group_path", "uuid").unwrap();
        assert_eq!(
            root_addr
                .resolve(&db, &View::capture_ephemeral(&db))
                .unwrap(),
            db.root().id()
        );
        assert_eq!(
            GroupAddress::root()
                .resolve(&db, &View::capture_ephemeral(&db))
                .unwrap(),
            db.root().id()
        );

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
        .resolve(&db, &View::capture_ephemeral(&db))
        .unwrap_err();
        assert_eq!(missing.code_enum(), ErrorCode::GroupNotFound);
    }
}
