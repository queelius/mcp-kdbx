//! Substring entry search across configurable fields (spec section 3, "Search
//! semantics").
//!
//! [`find_entry`] walks every entry of a [`View`] (a kdbx-core snapshot of the
//! working db) and returns the entries whose requested fields contain the
//! query as a plain substring. The match is plain substring only: no regex,
//! no boolean operators, no globs.
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
//! Secret values are never compared. A field is read through
//! `kdbx_core::visibility::metadata_value`, the same rule the read views use,
//! so a field is searchable exactly when the views would show it. Without this,
//! repeated substring queries against a protected UserName, URL, or Notes
//! would recover the value with no reveal and no audit event. (The snapshot
//! holds only a fingerprint for such a value anyway, so the rule is also
//! structural.)

use crate::engine::view::View;
use kdbx_core::fields::StandardField;
use kdbx_core::visibility::metadata_value;
use uuid::Uuid;

/// One field of an entry that a search may look at.
///
/// This enum is also the tool input type: it deserializes from the lowercase
/// variant name (`title`, `username`, `url`, `notes`) and anything else is a
/// deserialization error, and its JSON Schema enumerates exactly those values.
/// Each variant reads one KDBX standard field ([`Field::standard`]). Adding a
/// searchable field is one variant plus one arm there.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, schemars::JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Field {
    Title,
    Username,
    Url,
    Notes,
}

impl Field {
    /// The KDBX standard field this variant reads.
    fn standard(self) -> StandardField {
        match self {
            Field::Title => StandardField::Title,
            Field::Username => StandardField::UserName,
            Field::Url => StandardField::Url,
            Field::Notes => StandardField::Notes,
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

/// One entry that matched the query: its record UUID (which the adapter maps
/// back to the live entry), its title, and the canonical path of the group
/// that holds it (`None` when that group has no addressable path).
#[derive(Debug, Clone)]
pub struct SearchMatch {
    /// The entry's record UUID.
    pub uuid: Uuid,
    /// The entry title, or the empty string when it has none.
    pub title: String,
    /// The canonical path of the containing group, like `/Web/Banking/`.
    pub group_path: Option<String>,
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

/// Find entries of `view` whose requested `fields` contain `query` as a
/// substring.
///
/// When `fields` is empty the default set (title, username, url) is used. The
/// query and each field value are lowercased before comparison, so the match is
/// case-insensitive. Matches are stable-sorted by `(group_path, title)` (the
/// group path from the view's path index) and capped at 100, with `truncated`
/// set when more matched.
pub fn find_entry(view: &View, query: &str, fields: &[Field]) -> SearchResults {
    let active_fields: &[Field] = if fields.is_empty() {
        DEFAULT_FIELDS
    } else {
        fields
    };
    let needle = query.to_lowercase();

    let mut matches: Vec<SearchMatch> = view
        .snapshot()
        .entries()
        .filter(|entry| {
            active_fields.iter().any(|f| {
                metadata_value(entry, f.standard().kdbx_name())
                    .is_some_and(|v| v.to_lowercase().contains(&needle))
            })
        })
        .map(|entry| SearchMatch {
            uuid: entry.uuid,
            title: entry.title().unwrap_or("").to_string(),
            group_path: view.parent_path_string(entry.uuid),
        })
        .collect();

    // Stable sort keeps walk order among entries that share a
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

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::Database;
    use keepass::db::fields;

    #[test]
    fn field_deserializes_only_the_four_lowercase_names() {
        for (wire, field) in [
            ("title", Field::Title),
            ("username", Field::Username),
            ("url", Field::Url),
            ("notes", Field::Notes),
        ] {
            let parsed: Field = serde_json::from_value(serde_json::json!(wire)).unwrap();
            assert_eq!(parsed, field);
        }
        // Unknown names are an error, not silently dropped (a typo used to
        // shrink the search to the default set without telling anyone).
        for bad in ["password", "Title", "otp", ""] {
            assert!(
                serde_json::from_value::<Field>(serde_json::json!(bad)).is_err(),
                "{bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn field_reads_the_kdbx_standard_fields() {
        assert_eq!(Field::Title.standard().kdbx_name(), fields::TITLE);
        assert_eq!(Field::Username.standard().kdbx_name(), fields::USERNAME);
        assert_eq!(Field::Url.standard().kdbx_name(), fields::URL);
        assert_eq!(Field::Notes.standard().kdbx_name(), fields::NOTES);
    }

    /// Search `db` through a fresh view, as the adapter searches the vault's.
    fn find_entry(db: &Database, query: &str, fields: &[Field]) -> SearchResults {
        super::find_entry(&View::capture_ephemeral(db), query, fields)
    }

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
            .map(|m| (m.group_path.as_deref().unwrap(), m.title.as_str()))
            .collect();

        // Group paths are canonical vault paths (the root's name is never
        // part of one), so the order is exact: the root "/" first, then
        // "/Apps/", then "/Web/", titles ascending within a group.
        assert_eq!(
            order,
            [
                ("/", "root acct"),
                ("/Apps/", "mid acct"),
                ("/Web/", "alpha acct"),
                ("/Web/", "zeta acct"),
            ]
        );
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

    /// Build a database with one root entry carrying the given unprotected and
    /// protected fields.
    fn db_with_protection(unprotected: &[SeedField], protected: &[SeedField]) -> Database {
        let mut db = Database::new();
        db.root_mut().add_entry().edit(|e| {
            for (name, value) in unprotected {
                e.set_unprotected(*name, *value);
            }
            for (name, value) in protected {
                e.set_protected(*name, *value);
            }
        });
        db
    }

    const ALL_FIELDS: &[Field] = &[Field::Title, Field::Username, Field::Url, Field::Notes];

    #[test]
    fn protected_fields_are_never_matched() {
        // The needle occurs only inside protected UserName, URL, and Notes. No
        // field set, default or explicit, may match it: find_entry must not be
        // an oracle on protected values.
        let db = db_with_protection(
            &[(fields::TITLE, "Covert")],
            &[
                (fields::USERNAME, "zebra-user"),
                (fields::URL, "https://zebra.example"),
                (fields::NOTES, "zebra notes"),
            ],
        );
        assert_eq!(find_entry(&db, "zebra", &[]).matched_count, 0);
        assert_eq!(find_entry(&db, "zebra", ALL_FIELDS).matched_count, 0);
        for field in ALL_FIELDS {
            assert_eq!(
                find_entry(&db, "zebra", &[*field]).matched_count,
                0,
                "matched a protected value via {field:?}"
            );
        }
    }

    #[test]
    fn unprotected_fields_still_match_next_to_protected_ones() {
        let db = db_with_protection(
            &[
                (fields::TITLE, "Mixed"),
                (fields::URL, "https://open.example"),
                (fields::NOTES, "open notes"),
            ],
            &[(fields::USERNAME, "hidden-user")],
        );
        assert_eq!(find_entry(&db, "open.example", &[]).matched_count, 1);
        assert_eq!(
            find_entry(&db, "open notes", &[Field::Notes]).matched_count,
            1
        );
        assert_eq!(find_entry(&db, "hidden", ALL_FIELDS).matched_count, 0);
    }

    #[test]
    fn protected_title_still_matches_as_visible_metadata() {
        // Title is the entry's address and is shown by every read view even
        // when protected, so searching it reveals nothing new.
        let db = db_with_protection(&[], &[(fields::TITLE, "Addressed")]);
        assert_eq!(find_entry(&db, "address", &[]).matched_count, 1);
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
        assert_eq!(m.group_path.as_deref(), Some("/Web/Banking/"));
    }
}
