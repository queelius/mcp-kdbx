//! Read tools: `kdbx_list_groups`, `kdbx_list_entries`, `kdbx_list_attachments`,
//! `kdbx_get_entry`, `kdbx_find_entry`.
//!
//! These five tools are the bulk-read surface. Each requires an unlocked vault
//! and returns metadata only: no protected value, no attachment bytes, and no
//! OTP code (revealing those is a separate, consent-gated tool group). The
//! shapes come straight from the view builders in [`crate::adapter::views`],
//! which the spec section 1 defines. Reads are not in the spec's logged-events
//! table, so these tools emit no audit events; they still count as activity
//! because every call goes through [`KdbxServer::vault`].

use crate::adapter::{KdbxServer, locate_entry, responses, views};
use crate::kdbx_core::error::ErrorCode;
use crate::kdbx_core::path::VaultPath;
use crate::kdbx_core::search::{self, Field};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{schemars, tool, tool_router};

/// Input for `kdbx_list_groups`: the parent group whose direct child groups are
/// listed. Defaults to the root path `/` when omitted.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ListGroupsParams {
    /// The path of the parent group, like `/Web`. Defaults to `/` (the root
    /// group) when omitted.
    #[serde(default = "default_root_path")]
    pub parent_path: String,
}

/// Input for `kdbx_list_entries`: the group whose direct entries are listed.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ListEntriesParams {
    /// The path of the group whose entries to list, like `/Web/Banking`.
    pub group_path: String,
}

/// Input for `kdbx_list_attachments`: the entry whose attachment metadata is
/// listed, by path or uuid.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ListAttachmentsParams {
    /// The path of the entry, like `/Web/Banking/MyBank`. Give exactly one of
    /// `entry_path` or `uuid`.
    #[serde(default)]
    pub entry_path: Option<String>,
    /// The entry's uuid. Give exactly one of `entry_path` or `uuid`.
    #[serde(default)]
    pub uuid: Option<String>,
}

/// Input for `kdbx_get_entry`: the entry to fetch in detail, by path or uuid.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct GetEntryParams {
    /// The path of the entry, like `/Web/Banking/MyBank`. Give exactly one of
    /// `path` or `uuid`.
    #[serde(default)]
    pub path: Option<String>,
    /// The entry's uuid. Give exactly one of `path` or `uuid`.
    #[serde(default)]
    pub uuid: Option<String>,
}

/// Input for `kdbx_find_entry`: a substring query and an optional field set.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct FindEntryParams {
    /// The substring to look for. Plain substring match, case-insensitive: no
    /// regex, no globs, no boolean operators.
    pub query: String,
    /// Which fields to search. Allowed values are `title`, `username`, `url`,
    /// and `notes`. Defaults to `title`, `username`, and `url` when omitted;
    /// notes is searched only when asked for explicitly. Unknown values are
    /// ignored.
    #[serde(default)]
    pub fields: Option<Vec<String>>,
}

/// The default `parent_path` for `kdbx_list_groups`: the root group.
fn default_root_path() -> String {
    "/".to_string()
}

#[tool_router(router = reads_router, vis = "pub(crate)")]
impl KdbxServer {
    /// Read: list the direct child groups of a parent group.
    #[tool(
        description = "List the direct child groups of a group. Provide parent_path (defaults to '/', the root). Returns each child group's name, path, uuid, entry and subgroup counts, and notes. Metadata only."
    )]
    async fn kdbx_list_groups(&self, Parameters(params): Parameters<ListGroupsParams>) -> String {
        let mut vault = self.vault().await;
        if !vault.is_unlocked() {
            return responses::err(&responses::locked_error(vault.take_last_lock()));
        }
        let db = match vault.working_db() {
            Ok(db) => db,
            Err(e) => return responses::err(&e),
        };
        let parent = match VaultPath::parse(&params.parent_path) {
            Ok(p) => p,
            Err(e) => return responses::err(&e),
        };
        let parent_id = match parent.resolve_group(db) {
            Ok(id) => id,
            Err(e) => return responses::err(&e),
        };
        // db.group returns None only if the id vanished; resolve_group just gave
        // it to us, so an empty child list is the worst case.
        let child_ids: Vec<_> = match db.group(parent_id) {
            Some(group) => group.group_ids().collect(),
            None => Vec::new(),
        };
        let groups: Vec<_> = child_ids
            .into_iter()
            .filter_map(|id| views::group_summary(db, id))
            .collect();
        responses::ok(serde_json::json!({ "groups": groups }))
    }

    /// Read: list the direct entries of a group.
    #[tool(
        description = "List the direct entries of a group. Provide group_path. Returns each entry's title, path, uuid, username, url, a notes preview, standard and custom field names with protected flags, attachment and otp flags, and the modified timestamp. Metadata only: no passwords or protected values. A username, url, or notes field marked protected is returned as null and flagged protected in standard_field_names; read it with kdbx_reveal_protected."
    )]
    async fn kdbx_list_entries(&self, Parameters(params): Parameters<ListEntriesParams>) -> String {
        let mut vault = self.vault().await;
        if !vault.is_unlocked() {
            return responses::err(&responses::locked_error(vault.take_last_lock()));
        }
        let db = match vault.working_db() {
            Ok(db) => db,
            Err(e) => return responses::err(&e),
        };
        let group_path = match VaultPath::parse(&params.group_path) {
            Ok(p) => p,
            Err(e) => return responses::err(&e),
        };
        let group_id = match group_path.resolve_group(db) {
            Ok(id) => id,
            Err(e) => return responses::err(&e),
        };
        let entry_ids: Vec<_> = match db.group(group_id) {
            Some(group) => group.entry_ids().collect(),
            None => Vec::new(),
        };
        let entries: Vec<_> = entry_ids
            .into_iter()
            .filter_map(|id| views::entry_summary(db, id))
            .collect();
        responses::ok(serde_json::json!({ "entries": entries }))
    }

    /// Read: list the attachments of an entry (names, sizes, content hashes).
    #[tool(
        description = "List the attachments of an entry. Provide entry_path. Returns each attachment's name, size in bytes, and sha256 of its content. No attachment bytes: downloading bytes is a separate consent-gated tool."
    )]
    async fn kdbx_list_attachments(
        &self,
        Parameters(params): Parameters<ListAttachmentsParams>,
    ) -> String {
        let mut vault = self.vault().await;
        if !vault.is_unlocked() {
            return responses::err(&responses::locked_error(vault.take_last_lock()));
        }
        let db = match vault.working_db() {
            Ok(db) => db,
            Err(e) => return responses::err(&e),
        };
        let entry_id = match locate_entry(
            db,
            params.entry_path.as_deref(),
            params.uuid.as_deref(),
            "entry_path",
        ) {
            Ok(e) => e.id(),
            Err(e) => return responses::err(&e),
        };
        // attachment_list returns the full { attachments: [...] } object, which
        // is exactly the data payload. None means the id stopped resolving.
        match views::attachment_list(db, entry_id) {
            Some(data) => responses::ok(data),
            None => responses::err(&ErrorCode::EntryNotFound.into()),
        }
    }

    /// Read: fetch the full detail view of one entry.
    #[tool(
        description = "Fetch the full detail of an entry. Provide path. Returns title, path, uuid, username, url, full notes, standard and custom field names with protected flags, attachment and otp flags, and the created, modified, and accessed timestamps. No password, protected values, or attachment bytes. A username, url, or notes field marked protected is returned as null and flagged protected in standard_field_names; read it with kdbx_reveal_protected."
    )]
    async fn kdbx_get_entry(&self, Parameters(params): Parameters<GetEntryParams>) -> String {
        let mut vault = self.vault().await;
        if !vault.is_unlocked() {
            return responses::err(&responses::locked_error(vault.take_last_lock()));
        }
        let db = match vault.working_db() {
            Ok(db) => db,
            Err(e) => return responses::err(&e),
        };
        let entry_id =
            match locate_entry(db, params.path.as_deref(), params.uuid.as_deref(), "path") {
                Ok(e) => e.id(),
                Err(e) => return responses::err(&e),
            };
        match views::entry_detail(db, entry_id) {
            Some(data) => responses::ok(data),
            None => responses::err(&ErrorCode::EntryNotFound.into()),
        }
    }

    /// Read: find entries whose requested fields contain the query as a
    /// substring.
    #[tool(
        description = "Find entries whose fields contain a substring. Provide query and optionally fields (a subset of title, username, url, notes; default title, username, url). Returns matching entries in list-entry shape, the total matched_count, and a truncated flag set when more than 100 entries matched. Metadata only. Protected field values are never searched."
    )]
    async fn kdbx_find_entry(&self, Parameters(params): Parameters<FindEntryParams>) -> String {
        let mut vault = self.vault().await;
        if !vault.is_unlocked() {
            return responses::err(&responses::locked_error(vault.take_last_lock()));
        }
        let db = match vault.working_db() {
            Ok(db) => db,
            Err(e) => return responses::err(&e),
        };
        // Map the requested field strings to Field variants, dropping any value
        // that is not one of the four searchable fields. An empty resulting set
        // (no field key given, or only unknowns) lets search apply its default
        // (title, username, url), matching the spec's documented default.
        let fields: Vec<Field> = params
            .fields
            .unwrap_or_default()
            .iter()
            .filter_map(|name| parse_field(name))
            .collect();

        let results = search::find_entry(db, &params.query, &fields);
        let entries: Vec<_> = results
            .entries
            .iter()
            .filter_map(|m| views::entry_summary(db, m.entry_id))
            .collect();
        responses::ok(serde_json::json!({
            "entries": entries,
            "matched_count": results.matched_count,
            "truncated": results.truncated,
        }))
    }
}

/// Map a field name string (case-insensitive) to a [`Field`] variant, or `None`
/// for an unrecognized name. The four searchable fields are the only valid
/// values; anything else is dropped by the caller.
fn parse_field(name: &str) -> Option<Field> {
    match name.to_lowercase().as_str() {
        "title" => Some(Field::Title),
        "username" => Some(Field::Username),
        "url" => Some(Field::Url),
        "notes" => Some(Field::Notes),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_field_maps_the_four_searchable_names() {
        assert_eq!(parse_field("title"), Some(Field::Title));
        assert_eq!(parse_field("username"), Some(Field::Username));
        assert_eq!(parse_field("url"), Some(Field::Url));
        assert_eq!(parse_field("notes"), Some(Field::Notes));
    }

    #[test]
    fn parse_field_is_case_insensitive() {
        assert_eq!(parse_field("Title"), Some(Field::Title));
        assert_eq!(parse_field("URL"), Some(Field::Url));
        assert_eq!(parse_field("UserName"), Some(Field::Username));
    }

    #[test]
    fn parse_field_drops_unknown_names() {
        assert_eq!(parse_field("password"), None);
        assert_eq!(parse_field(""), None);
        assert_eq!(parse_field("otp"), None);
    }

    #[test]
    fn default_root_path_is_slash() {
        assert_eq!(default_root_path(), "/");
    }
}
