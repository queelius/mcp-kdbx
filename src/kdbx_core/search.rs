//! Substring entry search across configurable fields (spec section 3, "Search
//! semantics").
//!
//! [`find_entry`] walks every entry depth-first from the database root, tracking
//! the group path as it descends, and returns the entries whose requested fields
//! contain the query as a plain substring. The match is plain substring only:
//! no regex, no boolean operators, no globs.
//!
//! Matching is case-insensitive via [`str::to_lowercase`], which is
//! Unicode-aware (it maps, for example, the German sharp S and accented Latin
//! letters). For v0.1 this is the stand-in for full Unicode case folding. The
//! known limitation is that `to_lowercase` is a simple lowercase mapping, not
//! the full case-folding algorithm, so a few scripts that fold rather than
//! lowercase (and special cases like the Turkish dotless i) will not match the
//! way a full case-fold would. KDBX titles are short Latin strings in practice,
//! so this is acceptable for now and can be revisited if it bites.
//!
//! This module depends only on `keepass` and `std`. It builds the group path
//! inline during the walk rather than going through `crate::kdbx_core::path`,
//! since tracking the path as we recurse is simpler and matches the shape that
//! the read tooling (Phase 3) needs.

/// One field of an entry that a search may look at.
///
/// The string used to read each variant from a keepass entry is fixed here, so
/// adding a searchable field is a one-line change with no parallel lookup table
/// to keep in sync.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Field {
    Title,
    Username,
    Url,
    Notes,
}

impl Field {
    /// The keepass field name this variant reads. `get_title` and `get` on an
    /// entry both key off these strings.
    fn keepass_name(&self) -> &'static str {
        match self {
            Field::Title => "Title",
            Field::Username => "UserName",
            Field::Url => "URL",
            Field::Notes => "Notes",
        }
    }
}

/// The default field set when the caller passes an empty slice: title,
/// username, and url (spec section 3). Notes is searched only when requested
/// explicitly, since notes can be long and noisy.
const DEFAULT_FIELDS: &[Field] = &[Field::Title, Field::Username, Field::Url];

/// The maximum number of matches returned. Beyond this the list is capped and
/// [`SearchResults::truncated`] is set.
const MAX_RESULTS: usize = 100;

/// One entry that matched the query. Carries enough for the Phase 3 read
/// adapter to build the `list_entries`-shaped response: the entry's UUID and
/// title, the group path it lives under, and the keepass `EntryId` for any
/// follow-up resolution.
#[derive(Debug, Clone)]
pub struct SearchMatch {
    /// The entry UUID, formatted as a hyphenated string.
    pub uuid: String,
    /// The entry title, or the empty string when it has none.
    pub title: String,
    /// The path of the group that holds the entry, like `/Web/Banking`. The
    /// root group is the leading `/`.
    pub group_path: String,
    /// The keepass handle for the entry, for later resolution.
    pub entry_id: keepass::db::EntryId,
}

/// The result of a search: the (capped, sorted) matches, how many entries
/// matched in total, and whether the returned list was cut short.
#[derive(Debug, Clone)]
pub struct SearchResults {
    /// The matches, stable-sorted by `(group_path, title)` and capped at
    /// [`MAX_RESULTS`].
    pub entries: Vec<SearchMatch>,
    /// How many entries matched across the whole database, before the cap.
    pub matched_count: usize,
    /// True when more than [`MAX_RESULTS`] entries matched, so `entries` holds
    /// only the first [`MAX_RESULTS`] in sorted order.
    pub truncated: bool,
}

/// Find entries whose requested `fields` contain `query` as a substring.
///
/// When `fields` is empty the default set (title, username, url) is used. The
/// query and each field value are lowercased before comparison, so the match is
/// case-insensitive. Matches are stable-sorted by `(group_path, title)` and
/// capped at 100, with `truncated` set when more matched.
pub fn find_entry(db: &keepass::Database, query: &str, fields: &[Field]) -> SearchResults {
    let active_fields: &[Field] = if fields.is_empty() {
        DEFAULT_FIELDS
    } else {
        fields
    };
    let needle = query.to_lowercase();

    let mut matches: Vec<SearchMatch> = Vec::new();
    let root_id = db.root().id();
    collect_matches(db, root_id, "", &needle, active_fields, &mut matches);

    // Stable sort keeps insertion (depth-first) order among entries that share a
    // (group_path, title) key, so the result is deterministic.
    matches.sort_by(|a, b| {
        a.group_path
            .cmp(&b.group_path)
            .then_with(|| a.title.cmp(&b.title))
    });

    let matched_count = matches.len();
    let truncated = matched_count > MAX_RESULTS;
    if truncated {
        matches.truncate(MAX_RESULTS);
    }

    SearchResults {
        entries: matches,
        matched_count,
        truncated,
    }
}

/// Recurse from `group_id`, appending a [`SearchMatch`] for every entry under it
/// (directly or in a descendant group) that matches `needle` on one of
/// `fields`. `path_so_far` is the group path built from ancestors; the empty
/// string means we are entering the root.
///
/// This mirrors `find_entry_with_path` in web-kdbx: the root group becomes the
/// leading `/`, and each level appends `/Name`.
fn collect_matches(
    db: &keepass::Database,
    group_id: keepass::db::GroupId,
    path_so_far: &str,
    needle: &str,
    fields: &[Field],
    out: &mut Vec<SearchMatch>,
) {
    let group = match db.group(group_id) {
        Some(g) => g,
        None => return,
    };

    let here = if path_so_far.is_empty() {
        format!("/{}", group.name)
    } else {
        format!("{}/{}", path_so_far, group.name)
    };

    // Entries directly in this group.
    let entry_ids: Vec<keepass::db::EntryId> = group.entry_ids().collect();
    for eid in entry_ids {
        if let Some(er) = db.entry(eid) {
            if entry_matches(&er, needle, fields) {
                out.push(SearchMatch {
                    uuid: er.id().uuid().to_string(),
                    title: er.get_title().unwrap_or("").to_string(),
                    group_path: here.clone(),
                    entry_id: er.id(),
                });
            }
        }
    }

    // Recurse into child groups.
    let child_ids: Vec<keepass::db::GroupId> = group.group_ids().collect();
    for child_id in child_ids {
        collect_matches(db, child_id, &here, needle, fields, out);
    }
}

/// True when any requested field's lowercased value contains `needle`. `needle`
/// is assumed already lowercased by the caller.
fn entry_matches(entry: &keepass::db::EntryRef<'_>, needle: &str, fields: &[Field]) -> bool {
    fields.iter().any(|f| {
        entry
            .get(f.keepass_name())
            .map(|v| v.to_lowercase().contains(needle))
            .unwrap_or(false)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::Database;
    use keepass::db::fields;

    /// A field to set on a seeded entry: (keepass field name, value).
    type SeedField = (&'static str, &'static str);

    /// One entry to seed: its group path segments (empty for the root group)
    /// and the fields to set on it.
    struct Seed {
        group_path: &'static [&'static str],
        fields: Vec<SeedField>,
    }

    /// Build an in-memory database from a list of seeds. Groups named in a
    /// seed's `group_path` are created on demand under the root. Returns the
    /// database; entry UUIDs are auto-assigned by keepass.
    fn build_db(seeds: &[Seed]) -> Database {
        let mut db = Database::new();
        for seed in seeds {
            // Resolve or create the target group, descending from the root.
            let mut group_id = db.root().id();
            for segment in seed.group_path {
                // Look for an existing child group with this name.
                let existing = db.group(group_id).and_then(|g| {
                    g.group_ids()
                        .find(|gid| db.group(*gid).map(|c| c.name == *segment).unwrap_or(false))
                });
                group_id = match existing {
                    Some(gid) => gid,
                    None => {
                        let mut gm = db.group_mut(group_id).expect("group exists");
                        let mut child = gm.add_group();
                        // Group.name is a public field; GroupMut derefs to Group.
                        child.name = segment.to_string();
                        child.id()
                    }
                };
            }

            let mut gm = db.group_mut(group_id).expect("target group exists");
            let entry_fields = seed.fields.clone();
            gm.add_entry().edit(|e| {
                for (name, value) in &entry_fields {
                    e.set_unprotected(*name, value.to_string());
                }
            });
        }
        db
    }

    /// Convenience: a seed in the root group with the given fields.
    fn root_seed(fields: Vec<SeedField>) -> Seed {
        Seed {
            group_path: &[],
            fields,
        }
    }

    #[test]
    fn substring_match_on_title() {
        let db = build_db(&[
            root_seed(vec![(fields::TITLE, "GitHub Login")]),
            root_seed(vec![(fields::TITLE, "Bank of Somewhere")]),
        ]);
        let results = find_entry(&db, "hub", &[]);
        assert_eq!(results.matched_count, 1);
        assert_eq!(results.entries.len(), 1);
        assert_eq!(results.entries[0].title, "GitHub Login");
        assert!(!results.truncated);
    }

    #[test]
    fn substring_match_on_username() {
        let db = build_db(&[
            root_seed(vec![
                (fields::TITLE, "Something"),
                (fields::USERNAME, "alice@example.com"),
            ]),
            root_seed(vec![
                (fields::TITLE, "Other"),
                (fields::USERNAME, "bob@example.com"),
            ]),
        ]);
        let results = find_entry(&db, "alice", &[]);
        assert_eq!(results.matched_count, 1);
        assert_eq!(results.entries[0].title, "Something");
    }

    #[test]
    fn substring_match_on_url() {
        let db = build_db(&[
            root_seed(vec![
                (fields::TITLE, "A"),
                (fields::URL, "https://example.com/login"),
            ]),
            root_seed(vec![
                (fields::TITLE, "B"),
                (fields::URL, "https://other.test/"),
            ]),
        ]);
        let results = find_entry(&db, "example.com", &[]);
        assert_eq!(results.matched_count, 1);
        assert_eq!(results.entries[0].title, "A");
    }

    #[test]
    fn match_is_case_insensitive() {
        let db = build_db(&[root_seed(vec![(fields::TITLE, "GitHub Login")])]);
        // Query in a different case than the stored title still matches.
        let upper = find_entry(&db, "GITHUB", &[]);
        assert_eq!(upper.matched_count, 1);
        let mixed = find_entry(&db, "gItHuB", &[]);
        assert_eq!(mixed.matched_count, 1);
    }

    #[test]
    fn default_fields_do_not_search_notes() {
        // The matching substring lives only in Notes. With the default field
        // set (title, username, url) there is no match.
        let db = build_db(&[root_seed(vec![
            (fields::TITLE, "Plain"),
            ("Notes", "recovery code: zebra"),
        ])]);
        let default_run = find_entry(&db, "zebra", &[]);
        assert_eq!(default_run.matched_count, 0);
        assert!(default_run.entries.is_empty());
        assert!(!default_run.truncated);

        // Asking for Notes explicitly finds it.
        let notes_run = find_entry(&db, "zebra", &[Field::Notes]);
        assert_eq!(notes_run.matched_count, 1);
        assert_eq!(notes_run.entries[0].title, "Plain");
    }

    #[test]
    fn explicit_single_field_ignores_other_fields() {
        // The query matches the username but we only search titles, so no hit.
        let db = build_db(&[root_seed(vec![
            (fields::TITLE, "Mail"),
            (fields::USERNAME, "carol"),
        ])]);
        let title_only = find_entry(&db, "carol", &[Field::Title]);
        assert_eq!(title_only.matched_count, 0);

        let username_only = find_entry(&db, "carol", &[Field::Username]);
        assert_eq!(username_only.matched_count, 1);
    }

    #[test]
    fn stable_sort_by_group_path_then_title() {
        // All entries share the substring "acct". They sit in different groups
        // and have different titles; the result must be ordered by
        // (group_path, title).
        let db = build_db(&[
            Seed {
                group_path: &["Web"],
                fields: vec![(fields::TITLE, "zeta acct")],
            },
            Seed {
                group_path: &["Web"],
                fields: vec![(fields::TITLE, "alpha acct")],
            },
            Seed {
                group_path: &["Apps"],
                fields: vec![(fields::TITLE, "mid acct")],
            },
            root_seed(vec![(fields::TITLE, "root acct")]),
        ]);

        let results = find_entry(&db, "acct", &[]);
        assert_eq!(results.matched_count, 4);

        let order: Vec<(&str, &str)> = results
            .entries
            .iter()
            .map(|m| (m.group_path.as_str(), m.title.as_str()))
            .collect();

        // Root group path is "/NewDatabase" style: the keepass default root
        // name. We assert relative ordering rather than the exact root name:
        // entries are grouped by path, and within "/.../Web" alpha precedes
        // zeta.
        let web_alpha = order
            .iter()
            .position(|(p, t)| p.ends_with("/Web") && *t == "alpha acct")
            .expect("Web/alpha present");
        let web_zeta = order
            .iter()
            .position(|(p, t)| p.ends_with("/Web") && *t == "zeta acct")
            .expect("Web/zeta present");
        let apps_mid = order
            .iter()
            .position(|(p, t)| p.ends_with("/Apps") && *t == "mid acct")
            .expect("Apps/mid present");

        // Within the same group, sort is by title.
        assert!(web_alpha < web_zeta, "alpha must precede zeta within /Web");
        // "/.../Apps" sorts before "/.../Web" lexicographically (A < W).
        assert!(apps_mid < web_alpha, "Apps group must precede Web group");
    }

    #[test]
    fn cap_at_100_sets_truncated() {
        // 101 matching entries: matched_count reports the true total, the list
        // is capped at 100, and truncated is set.
        let mut seeds = Vec::new();
        for i in 0..101 {
            // Zero-pad so title sort order is stable and total exceeds the cap.
            seeds.push(root_seed(vec![(
                fields::TITLE,
                Box::leak(format!("match-{i:03}").into_boxed_str()) as &'static str,
            )]));
        }
        let db = build_db(&seeds);
        let results = find_entry(&db, "match-", &[]);
        assert_eq!(results.matched_count, 101);
        assert_eq!(results.entries.len(), MAX_RESULTS);
        assert!(results.truncated);
    }

    #[test]
    fn no_match_returns_empty_not_truncated() {
        let db = build_db(&[
            root_seed(vec![(fields::TITLE, "GitHub")]),
            root_seed(vec![(fields::TITLE, "GitLab")]),
        ]);
        let results = find_entry(&db, "bitbucket", &[]);
        assert_eq!(results.matched_count, 0);
        assert!(results.entries.is_empty());
        assert!(!results.truncated);
    }

    #[test]
    fn finds_entries_in_nested_groups() {
        let db = build_db(&[Seed {
            group_path: &["Web", "Banking"],
            fields: vec![(fields::TITLE, "MyBank")],
        }]);
        let results = find_entry(&db, "mybank", &[]);
        assert_eq!(results.matched_count, 1);
        let m = &results.entries[0];
        assert!(
            m.group_path.ends_with("/Web/Banking"),
            "group_path was {}",
            m.group_path
        );
    }
}
