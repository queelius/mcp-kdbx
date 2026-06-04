//! `VaultPath`: parsing, formatting, and resolution against a `keepass::Database`.
//!
//! A vault path is a forward-slash-rooted path into the group tree, where the
//! final segment names either a group or an entry. It mirrors a filesystem path
//! but addresses KDBX records, not files. The grammar and resolution algorithm
//! come from spec section 1 ("Path conventions") and section 3 ("Path
//! resolution algorithm").
//!
//! Grammar in brief:
//! - Paths start with `/`. The leading empty segment is discarded.
//! - `/` separates segments. Inside a segment, `\/` is a literal slash and
//!   `\\` is a literal backslash.
//! - A trailing slash marks the path as a group path. The root path `/` is
//!   always a group path. Canonical formatted output carries no trailing slash.
//! - A segment may carry a `:N` suffix (1-based ordinal) to disambiguate
//!   siblings that share a name, following KDBX iteration order.
//!
//! Names compare case-sensitively after Unicode NFC normalization, so a
//! precomposed accented name and its decomposed equivalent resolve the same.
//!
//! Resolution walks segments left-to-right from the database root. Non-final
//! segments must each name a group. The final segment names a group (when the
//! path is a group path) or an entry (otherwise). Anything that does not match,
//! including injection-shaped input like `/../../etc`, simply fails to resolve;
//! there is no filesystem access at any point.

use crate::kdbx_core::error::{CoreError, CoreResult, ErrorCode};
use keepass::Database;
use keepass::db::{EntryId, GroupId};

/// A parsed vault path: an ordered list of segments plus a flag recording
/// whether the input ended with a trailing slash (which marks a group path).
///
/// Construct one with [`VaultPath::parse`]. The struct keeps the segments in
/// resolution order, root-first. The root path `/` parses to an empty segment
/// list with `is_group = true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VaultPath {
    segments: Vec<Segment>,
    /// True when the input ended in `/` (or was the bare root `/`), meaning the
    /// final segment must resolve to a group rather than an entry.
    is_group: bool,
}

/// One path segment: a record name plus an optional 1-based ordinal.
///
/// The ordinal disambiguates siblings that share a name. `None` is treated the
/// same as `Some(1)`: pick the first sibling with that name.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Segment {
    /// The record name, with any `\/` and `\\` escapes already decoded and the
    /// `:N` ordinal suffix already stripped off.
    name: String,
    /// The 1-based ordinal from a `:N` suffix, or `None` when absent.
    ordinal: Option<usize>,
}

/// The result of resolving a [`VaultPath`]: either a group or an entry handle.
///
/// The handles are the keepass id newtypes, stable for the lifetime of the
/// in-memory database. Cross-session-stable identity is the record UUID, not
/// these ids or the path ordinals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved {
    /// The path resolved to a group.
    Group(GroupId),
    /// The path resolved to an entry.
    Entry(EntryId),
}

impl VaultPath {
    /// Parse a path string per spec section 1.
    ///
    /// Returns `GROUP_NOT_FOUND`-free parse errors as `FIELD_NAME_INVALID` is
    /// not appropriate here; malformed paths use `GroupNotFound` with a message,
    /// matching how resolution reports "nothing resolves". A path that does not
    /// start with `/`, that contains a dangling backslash escape, or that
    /// carries a malformed `:N` ordinal is rejected.
    ///
    /// The leading empty segment (from the rooting `/`) is discarded. A trailing
    /// slash sets `is_group` and is otherwise dropped. The bare root `/` parses
    /// to zero segments with `is_group = true`.
    pub fn parse(input: &str) -> CoreResult<VaultPath> {
        if !input.starts_with('/') {
            return Err(CoreError::new(ErrorCode::GroupNotFound)
                .with_message("path must start with '/'")
                .with_details(serde_json::json!({ "path": input })));
        }

        // Split into raw segments while honoring backslash escapes. A `\` makes
        // the next character literal, so `\/` does not split and `\\` is one
        // backslash. A trailing unescaped `/` produces a final empty raw
        // segment, which we read as the group-path marker.
        let mut raw_segments: Vec<String> = Vec::new();
        let mut current = String::new();
        let mut chars = input.chars();
        // Drop the rooting slash. We know it is present from the check above.
        chars.next();

        let mut escaped = false;
        for ch in chars {
            if escaped {
                // Only `\/` and `\\` are meaningful escapes. We pass through any
                // other escaped character literally rather than rejecting it, so
                // a stray backslash before an ordinary character is forgiving.
                current.push(ch);
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '/' {
                raw_segments.push(std::mem::take(&mut current));
            } else {
                current.push(ch);
            }
        }
        if escaped {
            return Err(CoreError::new(ErrorCode::GroupNotFound)
                .with_message("path ends with a dangling '\\' escape")
                .with_details(serde_json::json!({ "path": input })));
        }
        raw_segments.push(current);

        // A trailing slash leaves a final empty raw segment: it is the group
        // marker, not a real segment. The bare root `/` leaves a single empty
        // raw segment, which is also the group marker (zero real segments).
        let mut is_group = false;
        if raw_segments.last().map(String::is_empty).unwrap_or(false) {
            is_group = true;
            raw_segments.pop();
        }

        // An empty raw segment that is not the trailing one means a `//` in the
        // path, which names a record with an empty name. KDBX record names are
        // not normally empty, so reject it as malformed rather than silently
        // searching for an empty name.
        if raw_segments.iter().any(String::is_empty) {
            return Err(CoreError::new(ErrorCode::GroupNotFound)
                .with_message("path contains an empty segment ('//')")
                .with_details(serde_json::json!({ "path": input })));
        }

        let mut segments = Vec::with_capacity(raw_segments.len());
        for raw in raw_segments {
            segments.push(Segment::parse(&raw, input)?);
        }

        Ok(VaultPath { segments, is_group })
    }

    /// True when this path addresses a group (it ended in `/`, or it is root).
    pub fn is_group_path(&self) -> bool {
        self.is_group
    }

    /// True when this is the root path `/`.
    pub fn is_root(&self) -> bool {
        self.segments.is_empty()
    }

    /// Render the path back to its canonical string form.
    ///
    /// Round-trips with [`VaultPath::parse`]: re-emits the `\/` and `\\` escapes
    /// a segment needs and re-emits any `:N` ordinal suffix. Canonical form has
    /// no trailing slash, so a group path and the equivalent entry-shaped path
    /// format identically. The root path formats as `/`.
    pub fn format(&self) -> String {
        if self.segments.is_empty() {
            return "/".to_string();
        }
        let mut out = String::new();
        for seg in &self.segments {
            out.push('/');
            out.push_str(&seg.format());
        }
        out
    }

    /// Resolve this path against `db`, returning a group or entry handle.
    ///
    /// Walks segments from the root. Each non-final segment must name a group.
    /// The final segment resolves to a group when this is a group path (or the
    /// root path), otherwise to an entry. Matching is case-sensitive after NFC
    /// normalization. Returns `GroupNotFound` when an intermediate group is
    /// missing or when a group-path final segment does not match a group, and
    /// `EntryNotFound` when an entry-path final segment does not match an entry.
    pub fn resolve(&self, db: &Database) -> CoreResult<Resolved> {
        let root_id = db.root().id();

        // The root path addresses the root group directly.
        if self.segments.is_empty() {
            return Ok(Resolved::Group(root_id));
        }

        // Walk every segment except the last as a group step.
        let mut current_group = root_id;
        let last = self.segments.len() - 1;
        for seg in &self.segments[..last] {
            current_group = self.step_into_group(db, current_group, seg)?;
        }

        let final_seg = &self.segments[last];
        if self.is_group {
            let gid = self.step_into_group(db, current_group, final_seg)?;
            Ok(Resolved::Group(gid))
        } else {
            // An entry-shaped final segment may still name a group if no entry
            // matches; we report ENTRY_NOT_FOUND in that case, matching the
            // user's stated intent (no trailing slash means "I want an entry").
            let eid = self.match_entry(db, current_group, final_seg)?;
            Ok(Resolved::Entry(eid))
        }
    }

    /// Resolve and require a group. Returns `GroupNotFound` when the path
    /// resolves to an entry or to nothing.
    pub fn resolve_group(&self, db: &Database) -> CoreResult<GroupId> {
        match self.resolve(db)? {
            Resolved::Group(id) => Ok(id),
            Resolved::Entry(_) => Err(CoreError::new(ErrorCode::GroupNotFound)
                .with_message("path resolves to an entry, not a group")
                .with_details(serde_json::json!({ "path": self.format() }))),
        }
    }

    /// Resolve and require an entry. Returns `EntryNotFound` when the path
    /// resolves to a group or to nothing.
    pub fn resolve_entry(&self, db: &Database) -> CoreResult<EntryId> {
        match self.resolve(db)? {
            Resolved::Entry(id) => Ok(id),
            Resolved::Group(_) => Err(CoreError::new(ErrorCode::EntryNotFound)
                .with_message("path resolves to a group, not an entry")
                .with_details(serde_json::json!({ "path": self.format() }))),
        }
    }

    /// Find the child group of `parent` named by `seg`, honoring the ordinal.
    /// Returns `GroupNotFound` when no matching child group exists.
    fn step_into_group(
        &self,
        db: &Database,
        parent: GroupId,
        seg: &Segment,
    ) -> CoreResult<GroupId> {
        let parent_ref = db.group(parent).ok_or_else(|| {
            CoreError::new(ErrorCode::GroupNotFound)
                .with_message("intermediate group is missing")
                .with_details(serde_json::json!({ "path": self.format() }))
        })?;

        let target = nfc_normalize(&seg.name);
        let wanted = seg.ordinal.unwrap_or(1);
        let mut seen = 0usize;
        for child_id in parent_ref.group_ids() {
            if let Some(child) = db.group(child_id) {
                if nfc_normalize(&child.name) == target {
                    seen += 1;
                    if seen == wanted {
                        return Ok(child_id);
                    }
                }
            }
        }

        Err(CoreError::new(ErrorCode::GroupNotFound)
            .with_message(format!("no group named '{}' at this level", seg.name))
            .with_details(serde_json::json!({
                "path": self.format(),
                "segment": seg.name,
                "ordinal": wanted,
            })))
    }

    /// Find the entry of `parent` named by `seg`, honoring the ordinal. An entry
    /// matches on its title. Returns `EntryNotFound` when no matching entry
    /// exists.
    fn match_entry(&self, db: &Database, parent: GroupId, seg: &Segment) -> CoreResult<EntryId> {
        let parent_ref = db.group(parent).ok_or_else(|| {
            CoreError::new(ErrorCode::EntryNotFound)
                .with_message("containing group is missing")
                .with_details(serde_json::json!({ "path": self.format() }))
        })?;

        let target = nfc_normalize(&seg.name);
        let wanted = seg.ordinal.unwrap_or(1);
        let mut seen = 0usize;
        for entry_id in parent_ref.entry_ids() {
            if let Some(entry) = db.entry(entry_id) {
                let title = entry.get_title().unwrap_or("");
                if nfc_normalize(title) == target {
                    seen += 1;
                    if seen == wanted {
                        return Ok(entry_id);
                    }
                }
            }
        }

        Err(CoreError::new(ErrorCode::EntryNotFound)
            .with_message(format!("no entry titled '{}' in this group", seg.name))
            .with_details(serde_json::json!({
                "path": self.format(),
                "segment": seg.name,
                "ordinal": wanted,
            })))
    }
}

impl std::fmt::Display for VaultPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.format())
    }
}

impl Segment {
    /// Parse one already-unsplit raw segment string into a name and ordinal.
    ///
    /// `raw` has had its slash escapes resolved by the splitter, so it may
    /// contain literal `/` and `\` characters. The `:N` ordinal suffix is
    /// recognized only when `N` is a sequence of ASCII digits forming a value of
    /// at least 1. `full_path` is threaded through only for error context.
    fn parse(raw: &str, full_path: &str) -> CoreResult<Segment> {
        if let Some((name, ord_str)) = split_ordinal_suffix(raw) {
            let ordinal: usize = ord_str.parse().map_err(|_| {
                CoreError::new(ErrorCode::GroupNotFound)
                    .with_message("malformed ':N' ordinal suffix")
                    .with_details(serde_json::json!({ "path": full_path, "segment": raw }))
            })?;
            if ordinal == 0 {
                return Err(CoreError::new(ErrorCode::GroupNotFound)
                    .with_message("ordinal ':N' is 1-based; ':0' is not valid")
                    .with_details(serde_json::json!({ "path": full_path, "segment": raw })));
            }
            Ok(Segment {
                name: name.to_string(),
                ordinal: Some(ordinal),
            })
        } else {
            Ok(Segment {
                name: raw.to_string(),
                ordinal: None,
            })
        }
    }

    /// Render this segment back to its escaped string form, including the `:N`
    /// suffix when present.
    fn format(&self) -> String {
        let mut out = escape_segment(&self.name);
        if let Some(n) = self.ordinal {
            out.push(':');
            out.push_str(&n.to_string());
        }
        out
    }
}

/// Split a raw segment into `(name, ordinal_digits)` when it ends in `:N` with
/// `N` a non-empty run of ASCII digits and a non-empty name. Returns `None` when
/// there is no such suffix, so a bare name like `Banking` or a name that simply
/// contains a colon (`http:8080`) without a trailing digit run is left intact.
fn split_ordinal_suffix(raw: &str) -> Option<(&str, &str)> {
    let colon = raw.rfind(':')?;
    // Need a name before the colon and digits after it.
    if colon == 0 {
        return None;
    }
    let digits = &raw[colon + 1..];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((&raw[..colon], digits))
}

/// Escape a segment name for output: a literal `\` becomes `\\` and a literal
/// `/` becomes `\/`. Other characters pass through. This is the inverse of the
/// unescaping the splitter does during parse.
fn escape_segment(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for ch in name.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '/' => out.push_str("\\/"),
            other => out.push(other),
        }
    }
    out
}

/// Normalize a string to Unicode NFC (canonical decomposition followed by
/// canonical composition) for name comparison.
///
/// We do not pull in a full Unicode normalization crate here; the dependency set
/// is fixed for v0.1. Instead we apply canonical composition over the combining
/// marks that show up in real record names: a base character followed by one or
/// more combining diacritical marks (the U+0300..U+036F block) is composed into
/// its precomposed form where one exists. Strings already in precomposed form
/// pass through unchanged, so a precomposed name and its decomposed equivalent
/// compare equal. Characters outside this common case are left as-is.
///
/// This is enough for the v0.1 path-resolution contract (precomposed vs
/// decomposed accented Latin names resolve the same). A later version can swap
/// in a full normalizer without changing the call sites.
fn nfc_normalize(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(base) = chars.next() {
        let mut composed = base;
        // Fold any run of trailing combining marks into the base where a
        // canonical composition exists.
        while let Some(&mark) = chars.peek() {
            if let Some(next) = compose_pair(composed, mark) {
                composed = next;
                chars.next();
            } else {
                break;
            }
        }
        out.push(composed);
    }
    out
}

/// Canonically compose a base character and a single combining mark into a
/// precomposed character, when a canonical equivalent exists. Returns `None`
/// when there is no composition for the pair.
///
/// This table covers the common Latin precomposed letters used in names. It is
/// deliberately small: the goal is correct comparison of the accented names that
/// occur in practice, not full Unicode coverage.
fn compose_pair(base: char, mark: char) -> Option<char> {
    let composed = match (base, mark) {
        // Combining grave accent U+0300.
        ('A', '\u{0300}') => 'À',
        ('E', '\u{0300}') => 'È',
        ('I', '\u{0300}') => 'Ì',
        ('O', '\u{0300}') => 'Ò',
        ('U', '\u{0300}') => 'Ù',
        ('a', '\u{0300}') => 'à',
        ('e', '\u{0300}') => 'è',
        ('i', '\u{0300}') => 'ì',
        ('o', '\u{0300}') => 'ò',
        ('u', '\u{0300}') => 'ù',
        // Combining acute accent U+0301.
        ('A', '\u{0301}') => 'Á',
        ('E', '\u{0301}') => 'É',
        ('I', '\u{0301}') => 'Í',
        ('O', '\u{0301}') => 'Ó',
        ('U', '\u{0301}') => 'Ú',
        ('Y', '\u{0301}') => 'Ý',
        ('a', '\u{0301}') => 'á',
        ('e', '\u{0301}') => 'é',
        ('i', '\u{0301}') => 'í',
        ('o', '\u{0301}') => 'ó',
        ('u', '\u{0301}') => 'ú',
        ('y', '\u{0301}') => 'ý',
        ('n', '\u{0301}') => 'ń',
        ('c', '\u{0301}') => 'ć',
        ('s', '\u{0301}') => 'ś',
        ('z', '\u{0301}') => 'ź',
        // Combining circumflex U+0302.
        ('A', '\u{0302}') => 'Â',
        ('E', '\u{0302}') => 'Ê',
        ('I', '\u{0302}') => 'Î',
        ('O', '\u{0302}') => 'Ô',
        ('U', '\u{0302}') => 'Û',
        ('a', '\u{0302}') => 'â',
        ('e', '\u{0302}') => 'ê',
        ('i', '\u{0302}') => 'î',
        ('o', '\u{0302}') => 'ô',
        ('u', '\u{0302}') => 'û',
        // Combining tilde U+0303.
        ('A', '\u{0303}') => 'Ã',
        ('N', '\u{0303}') => 'Ñ',
        ('O', '\u{0303}') => 'Õ',
        ('a', '\u{0303}') => 'ã',
        ('n', '\u{0303}') => 'ñ',
        ('o', '\u{0303}') => 'õ',
        // Combining diaeresis U+0308.
        ('A', '\u{0308}') => 'Ä',
        ('E', '\u{0308}') => 'Ë',
        ('I', '\u{0308}') => 'Ï',
        ('O', '\u{0308}') => 'Ö',
        ('U', '\u{0308}') => 'Ü',
        ('a', '\u{0308}') => 'ä',
        ('e', '\u{0308}') => 'ë',
        ('i', '\u{0308}') => 'ï',
        ('o', '\u{0308}') => 'ö',
        ('u', '\u{0308}') => 'ü',
        ('y', '\u{0308}') => 'ÿ',
        // Combining ring above U+030A.
        ('A', '\u{030A}') => 'Å',
        ('a', '\u{030A}') => 'å',
        // Combining cedilla U+0327.
        ('C', '\u{0327}') => 'Ç',
        ('c', '\u{0327}') => 'ç',
        // Combining caron U+030C.
        ('C', '\u{030C}') => 'Č',
        ('S', '\u{030C}') => 'Š',
        ('Z', '\u{030C}') => 'Ž',
        ('c', '\u{030C}') => 'č',
        ('s', '\u{030C}') => 'š',
        ('z', '\u{030C}') => 'ž',
        _ => return None,
    };
    Some(composed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::Database;
    use keepass::db::fields;

    // Parsing and formatting.

    #[test]
    fn root_path_parses_to_empty_group_path() {
        let p = VaultPath::parse("/").expect("root parses");
        assert!(p.is_root());
        assert!(p.is_group_path());
        assert_eq!(p.format(), "/");
    }

    #[test]
    fn simple_path_round_trips() {
        let p = VaultPath::parse("/Web/Banking/MyBank").expect("parse");
        assert!(!p.is_group_path());
        assert_eq!(p.format(), "/Web/Banking/MyBank");
    }

    #[test]
    fn trailing_slash_marks_group_and_canonical_form_drops_it() {
        let with_slash = VaultPath::parse("/Web/Banking/").expect("parse group path");
        let without = VaultPath::parse("/Web/Banking").expect("parse entry path");
        assert!(with_slash.is_group_path());
        assert!(!without.is_group_path());
        // Canonical form is identical: no trailing slash on output.
        assert_eq!(with_slash.format(), "/Web/Banking");
        assert_eq!(without.format(), "/Web/Banking");
    }

    #[test]
    fn escaped_slash_is_literal_in_a_segment() {
        // A title "a/b" lives in one segment via the "\/" escape.
        let p = VaultPath::parse("/Web/a\\/b").expect("parse escaped slash");
        // Two segments: "Web" and "a/b".
        assert_eq!(p.format(), "/Web/a\\/b");
        // Resolution-facing: the second segment name is "a/b".
        assert_eq!(p.segments.len(), 2);
        assert_eq!(p.segments[1].name, "a/b");
    }

    #[test]
    fn escaped_backslash_is_literal_backslash() {
        // A title containing a single backslash: "a\b" encodes as "a\\b".
        let p = VaultPath::parse("/a\\\\b").expect("parse escaped backslash");
        assert_eq!(p.segments.len(), 1);
        assert_eq!(p.segments[0].name, "a\\b");
        // Round-trips back to the doubled form.
        assert_eq!(p.format(), "/a\\\\b");
    }

    #[test]
    fn ordinal_suffix_parses_and_round_trips() {
        let p = VaultPath::parse("/Web/MyBank:2").expect("parse ordinal");
        assert_eq!(p.segments.len(), 2);
        assert_eq!(p.segments[1].name, "MyBank");
        assert_eq!(p.segments[1].ordinal, Some(2));
        assert_eq!(p.format(), "/Web/MyBank:2");
    }

    #[test]
    fn colon_without_trailing_digits_is_part_of_the_name() {
        // "http:port" has a colon but no digit run, so it is one literal name.
        let p = VaultPath::parse("/http:port").expect("parse colon name");
        assert_eq!(p.segments[0].name, "http:port");
        assert_eq!(p.segments[0].ordinal, None);
    }

    // Malformed input.

    #[test]
    fn missing_leading_slash_is_rejected() {
        let err = VaultPath::parse("Web/Banking").expect_err("no leading slash");
        assert_eq!(err.code_enum(), ErrorCode::GroupNotFound);
    }

    #[test]
    fn empty_string_is_rejected() {
        let err = VaultPath::parse("").expect_err("empty");
        assert_eq!(err.code_enum(), ErrorCode::GroupNotFound);
    }

    #[test]
    fn double_slash_is_rejected() {
        let err = VaultPath::parse("/Web//Banking").expect_err("double slash");
        assert_eq!(err.code_enum(), ErrorCode::GroupNotFound);
    }

    #[test]
    fn dangling_backslash_is_rejected() {
        let err = VaultPath::parse("/Web/a\\").expect_err("dangling escape");
        assert_eq!(err.code_enum(), ErrorCode::GroupNotFound);
    }

    #[test]
    fn zero_ordinal_is_rejected() {
        let err = VaultPath::parse("/Web/MyBank:0").expect_err("zero ordinal");
        assert_eq!(err.code_enum(), ErrorCode::GroupNotFound);
    }

    // NFC normalization, isolated from a database.

    #[test]
    fn nfc_composes_decomposed_accent() {
        // "é" as base 'e' + combining acute (U+0301) should compose to the
        // single precomposed code point, matching a literal "é".
        let decomposed = "Caf\u{0065}\u{0301}";
        let precomposed = "Caf\u{00e9}";
        assert_ne!(
            decomposed, precomposed,
            "inputs differ before normalization"
        );
        assert_eq!(nfc_normalize(decomposed), nfc_normalize(precomposed));
        assert_eq!(nfc_normalize(decomposed), precomposed);
    }

    // Resolution against an in-memory database.

    /// Build a small database:
    ///   /                  (root)
    ///   /Web               (group)
    ///   /Web/Banking       (group)
    ///   /Web/Banking/MyBank   (entry)
    ///   /Web/Dup           (entry, first)
    ///   /Web/Dup           (entry, second)
    ///   /Café              (group, title stored precomposed)
    fn build_db() -> Database {
        let mut db = Database::new();

        // Build the tree by capturing group ids and re-fetching mutable
        // handles, matching the proven keepass 0.12 write pattern (see
        // diff-kdbx compute.rs walk_nested_group). This sidesteps nested
        // mutable-borrow concerns from holding one GroupMut while spawning a
        // child from it.
        let web_id = db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "Web".to_string())
            .id();

        let banking_id = db
            .group_mut(web_id)
            .unwrap()
            .add_group()
            .edit(|g| g.name = "Banking".to_string())
            .id();

        db.group_mut(banking_id)
            .unwrap()
            .add_entry()
            .edit(|e| e.set_unprotected(fields::TITLE, "MyBank"));

        // Two sibling entries under /Web that share the title "Dup".
        db.group_mut(web_id).unwrap().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "Dup");
            e.set_unprotected(fields::USERNAME, "first");
        });
        db.group_mut(web_id).unwrap().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "Dup");
            e.set_unprotected(fields::USERNAME, "second");
        });

        // A group whose name carries a precomposed accent ("Café").
        db.root_mut()
            .add_group()
            .edit(|g| g.name = "Caf\u{00e9}".to_string());

        db
    }

    #[test]
    fn root_resolves_to_root_group() {
        let db = build_db();
        let resolved = VaultPath::parse("/").unwrap().resolve(&db).unwrap();
        assert_eq!(resolved, Resolved::Group(db.root().id()));
    }

    #[test]
    fn nested_group_path_resolves() {
        let db = build_db();
        let resolved = VaultPath::parse("/Web/Banking/")
            .unwrap()
            .resolve(&db)
            .unwrap();
        match resolved {
            Resolved::Group(id) => {
                let g = db.group(id).expect("group exists");
                assert_eq!(g.name, "Banking");
            }
            other => panic!("expected a group, got {other:?}"),
        }
    }

    #[test]
    fn group_without_trailing_slash_still_resolves_via_resolve_group() {
        let db = build_db();
        // No trailing slash means resolve() tries an entry first and fails;
        // resolve_group is the explicit accessor for groups.
        let path = VaultPath::parse("/Web/Banking").unwrap();
        let err = path.resolve(&db).expect_err("no entry named Banking");
        assert_eq!(err.code_enum(), ErrorCode::EntryNotFound);
        let gid = VaultPath::parse("/Web/Banking/")
            .unwrap()
            .resolve_group(&db)
            .expect("group resolves");
        assert_eq!(db.group(gid).unwrap().name, "Banking");
    }

    #[test]
    fn entry_path_resolves() {
        let db = build_db();
        let resolved = VaultPath::parse("/Web/Banking/MyBank")
            .unwrap()
            .resolve(&db)
            .unwrap();
        match resolved {
            Resolved::Entry(id) => {
                let e = db.entry(id).expect("entry exists");
                assert_eq!(e.get_title(), Some("MyBank"));
            }
            other => panic!("expected an entry, got {other:?}"),
        }
    }

    #[test]
    fn resolve_entry_convenience_returns_entry_id() {
        let db = build_db();
        let eid = VaultPath::parse("/Web/Banking/MyBank")
            .unwrap()
            .resolve_entry(&db)
            .expect("entry resolves");
        assert_eq!(db.entry(eid).unwrap().get_title(), Some("MyBank"));
    }

    #[test]
    fn missing_group_segment_is_group_not_found() {
        let db = build_db();
        let err = VaultPath::parse("/Web/Nope/MyBank")
            .unwrap()
            .resolve(&db)
            .expect_err("intermediate group missing");
        assert_eq!(err.code_enum(), ErrorCode::GroupNotFound);
    }

    #[test]
    fn missing_entry_is_entry_not_found() {
        let db = build_db();
        let err = VaultPath::parse("/Web/Banking/Ghost")
            .unwrap()
            .resolve(&db)
            .expect_err("entry missing");
        assert_eq!(err.code_enum(), ErrorCode::EntryNotFound);
    }

    #[test]
    fn path_injection_simply_fails_to_resolve() {
        let db = build_db();
        // "/../../etc" is not a filesystem path here: ".." is just a group name
        // that does not exist, so it fails to resolve with GROUP_NOT_FOUND.
        let err = VaultPath::parse("/../../etc")
            .unwrap()
            .resolve(&db)
            .expect_err("injection does not resolve");
        assert_eq!(err.code_enum(), ErrorCode::GroupNotFound);
    }

    #[test]
    fn duplicate_sibling_ordinal_picks_a_distinct_entry() {
        let db = build_db();
        // The underlying keepass iteration order is a HashSet, so which of the
        // two "Dup" entries is :1 versus :2 is stable within a process but not
        // predictable across processes (see the uncertainty note on this in the
        // summary). The deterministic contract we assert: a bare name and ":1"
        // both pick the first sibling, ":2" picks a different sibling, and the
        // two together cover both usernames.
        let bare = VaultPath::parse("/Web/Dup")
            .unwrap()
            .resolve_entry(&db)
            .expect("bare dup resolves");
        let first = VaultPath::parse("/Web/Dup:1")
            .unwrap()
            .resolve_entry(&db)
            .expect("dup:1 resolves");
        let second = VaultPath::parse("/Web/Dup:2")
            .unwrap()
            .resolve_entry(&db)
            .expect("dup:2 resolves");

        // A bare name is the same as ":1".
        assert_eq!(bare, first, "bare name resolves like ordinal 1");
        // The two ordinals address different entries.
        assert_ne!(first, second, ":1 and :2 are distinct entries");

        // Together they cover both seeded usernames, in some order.
        let mut names = [
            db.entry(first)
                .unwrap()
                .get("UserName")
                .unwrap()
                .to_string(),
            db.entry(second)
                .unwrap()
                .get("UserName")
                .unwrap()
                .to_string(),
        ];
        names.sort();
        assert_eq!(names, ["first".to_string(), "second".to_string()]);
    }

    #[test]
    fn ordinal_past_the_end_is_not_found() {
        let db = build_db();
        let err = VaultPath::parse("/Web/Dup:3")
            .unwrap()
            .resolve_entry(&db)
            .expect_err("only two dups exist");
        assert_eq!(err.code_enum(), ErrorCode::EntryNotFound);
    }

    #[test]
    fn nfc_normalized_group_name_resolves() {
        let db = build_db();
        // The group is stored precomposed ("Café"); a path written with the
        // decomposed form ('e' + combining acute) must resolve to the same
        // group after NFC normalization.
        let decomposed = "/Caf\u{0065}\u{0301}/";
        let gid = VaultPath::parse(decomposed)
            .unwrap()
            .resolve_group(&db)
            .expect("decomposed name resolves to precomposed group");
        assert_eq!(db.group(gid).unwrap().name, "Caf\u{00e9}");
    }
}
