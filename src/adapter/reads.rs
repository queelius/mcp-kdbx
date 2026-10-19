//! Read tools: `kdbx_list_groups`, `kdbx_list_entries`, `kdbx_list_attachments`,
//! `kdbx_get_entry`, `kdbx_find_entry`.
//!
//! These five tools are the bulk-read surface. Each requires an unlocked vault
//! and returns metadata only: no protected value, no attachment bytes, and no
//! OTP code (revealing those is a separate, consent-gated tool group). The
//! shapes (spec section 1) come straight from the view builders in
//! [`crate::adapter::views`], which read only the vault's cached snapshot,
//! never the live database. Reads are not in the spec's logged-events
//! table, so these tools emit no audit events; they still count as activity
//! because every call goes through [`KdbxServer::vault`].

use crate::adapter::{KdbxServer, responses, view_of, views};
use crate::engine::address::{EntryAddress, GroupAddress};
use crate::engine::search::{self, Field};
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{schemars, tool, tool_router};

/// Input for `kdbx_list_groups`: the parent group whose direct child groups are
/// listed. Defaults to the root path `/` when omitted.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ListGroupsParams {
    /// The path of the parent group, like `/Web`. Give at most one of
    /// `parent_path` or `uuid`; with neither, the root group `/` is listed.
    #[serde(default)]
    pub parent_path: Option<String>,
    /// The parent group's uuid (as returned by a previous kdbx_list_groups).
    #[serde(default)]
    pub uuid: Option<String>,
}

/// Input for `kdbx_list_entries`: the group whose direct entries are listed.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct ListEntriesParams {
    /// The path of the group whose entries to list, like `/Web/Banking`. Give
    /// exactly one of `group_path` or `uuid`.
    #[serde(default)]
    pub group_path: Option<String>,
    /// The group's uuid (as returned by kdbx_list_groups). Give exactly one of
    /// `group_path` or `uuid`.
    #[serde(default)]
    pub uuid: Option<String>,
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
    /// Which fields to search: any of `title`, `username`, `url`, `notes`.
    /// Defaults to `title`, `username`, and `url` when omitted or empty; notes
    /// is searched only when asked for explicitly. Any other value is
    /// rejected.
    #[serde(default)]
    pub fields: Option<Vec<Field>>,
}

#[tool_router(router = reads_router, vis = "pub(crate)")]
impl KdbxServer {
    /// Read: list the direct child groups of a parent group.
    #[tool(
        description = "List the direct child groups of a group. Provide parent_path or the parent's uuid (with neither, the root '/'). Returns each child group's name, path, uuid, entry and subgroup counts, and notes. Metadata only."
    )]
    async fn kdbx_list_groups(&self, Parameters(params): Parameters<ListGroupsParams>) -> String {
        let mut vault = self.vault().await;
        if !vault.is_unlocked() {
            return responses::err(&responses::locked_error(vault.take_last_lock()));
        }
        let view = match view_of(&vault) {
            Ok(view) => view,
            Err(e) => return responses::err(&e),
        };
        // With neither parent_path nor uuid, list the root group's children.
        let parent = match (&params.parent_path, &params.uuid) {
            (None, None) => Ok(GroupAddress::root()),
            (path, uuid) => {
                GroupAddress::from_parts(path.as_deref(), uuid.as_deref(), "parent_path", "uuid")
            }
        };
        let parent = match parent.and_then(|p| p.resolve_in(view)) {
            Ok(group) => group,
            Err(e) => return responses::err(&e),
        };
        let groups: Vec<_> = parent
            .groups
            .iter()
            .map(|group| views::group_summary(view, group))
            .collect();
        responses::ok(serde_json::json!({ "groups": groups }))
    }

    /// Read: list the direct entries of a group.
    #[tool(
        description = "List the direct entries of a group. Provide group_path or the group's uuid. Returns each entry's title, path, uuid, username, url, a notes preview, standard and custom field names with protected flags, attachment and otp flags, and the modified timestamp. Metadata only: no passwords or protected values. A username, url, or notes field marked protected is returned as null and flagged protected in standard_field_names; read it with kdbx_reveal_protected."
    )]
    async fn kdbx_list_entries(&self, Parameters(params): Parameters<ListEntriesParams>) -> String {
        let mut vault = self.vault().await;
        if !vault.is_unlocked() {
            return responses::err(&responses::locked_error(vault.take_last_lock()));
        }
        let view = match view_of(&vault) {
            Ok(view) => view,
            Err(e) => return responses::err(&e),
        };
        let group = match GroupAddress::from_parts(
            params.group_path.as_deref(),
            params.uuid.as_deref(),
            "group_path",
            "uuid",
        )
        .and_then(|g| g.resolve_in(view))
        {
            Ok(group) => group,
            Err(e) => return responses::err(&e),
        };
        let entries: Vec<_> = group
            .entries
            .iter()
            .map(|entry| views::entry_summary(view, entry))
            .collect();
        responses::ok(serde_json::json!({ "entries": entries }))
    }

    /// Read: list the attachments of an entry (names, sizes, fingerprints).
    #[tool(
        description = "List the attachments of an entry. Provide entry_path. Returns each attachment's name, size in bytes, and a fingerprint of its content keyed per session (equal to what kdbx_download_attachment returns for the same bytes until the next unlock; not stable across unlocks). No attachment bytes: downloading bytes is a separate consent-gated tool."
    )]
    async fn kdbx_list_attachments(
        &self,
        Parameters(params): Parameters<ListAttachmentsParams>,
    ) -> String {
        let mut vault = self.vault().await;
        if !vault.is_unlocked() {
            return responses::err(&responses::locked_error(vault.take_last_lock()));
        }
        let view = match view_of(&vault) {
            Ok(view) => view,
            Err(e) => return responses::err(&e),
        };
        match EntryAddress::from_parts(
            params.entry_path.as_deref(),
            params.uuid.as_deref(),
            "entry_path",
        )
        .and_then(|address| address.resolve_in(view))
        {
            // The full { attachments: [...] } object is the data payload.
            Ok(entry) => responses::ok(views::attachment_list(entry)),
            Err(e) => responses::err(&e),
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
        let view = match view_of(&vault) {
            Ok(view) => view,
            Err(e) => return responses::err(&e),
        };
        match EntryAddress::from_parts(params.path.as_deref(), params.uuid.as_deref(), "path")
            .and_then(|address| address.resolve_in(view))
        {
            Ok(entry) => responses::ok(views::entry_detail(view, entry)),
            Err(e) => responses::err(&e),
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
        let view = match view_of(&vault) {
            Ok(view) => view,
            Err(e) => return responses::err(&e),
        };
        // The fields arrive as typed Field values (serde rejected anything
        // else). An empty set lets search apply its default (title, username,
        // url), matching the spec's documented default.
        let fields: Vec<Field> = params.fields.unwrap_or_default();

        let results = search::find_entry(view, &params.query, &fields);
        let entries: Vec<_> = results
            .entries
            .iter()
            .map(|m| views::entry_summary(view, m.entry))
            .collect();
        responses::ok(serde_json::json!({
            "entries": entries,
            "matched_count": results.matched_count,
            "truncated": results.truncated,
        }))
    }
}
