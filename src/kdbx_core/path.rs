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
//! - `/` separates segments. Inside a segment, `\/` is a literal slash,
//!   `\\` is a literal backslash, and `\:` is a literal colon that is not an
//!   ordinal separator.
//! - A trailing slash marks the path as a group path. The root path `/` is
//!   always a group path. Canonical formatted output carries no trailing slash.
//! - A segment may carry a `:N` suffix (1-based ordinal) to disambiguate
//!   siblings that share a name. Siblings with the same name are ordered by
//!   record UUID (not by KDBX hash-set iteration order), so a given ordinal
//!   resolves to the same record within a session, across sessions, and across
//!   the canonical and working clones of one database.
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
use unicode_normalization::UnicodeNormalization;

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
/// same as `Some(1)`. Siblings are ordered by record UUID, so a given ordinal
/// is stable and identical across clones of one database (see [`step_into_group`]
/// and [`match_entry`]).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Segment {
    /// The record name, with any `\/`, `\\`, and `\:` escapes already decoded
    /// and the `:N` ordinal suffix already stripped off.
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

        // Split into raw segments at unescaped `/`. A `\` makes the next
        // character literal for splitting purposes, so `\/` does not split and
        // `\\/` is a literal backslash followed by a separator. We keep the
        // escape sequences verbatim in the raw segment (we do not decode them
        // here): decoding happens later, in `Segment::parse`, so that the
        // ordinal scan can tell an escaped colon (`\:`, a literal colon) from
        // an ordinal-separator colon. A trailing unescaped `/` produces a final
        // empty raw segment, which we read as the group-path marker.
        let mut raw_segments: Vec<String> = Vec::new();
        let mut current = String::new();
        let mut chars = input.chars();
        // Drop the rooting slash. We know it is present from the check above.
        chars.next();

        let mut escaped = false;
        for ch in chars {
            if escaped {
                // Keep the backslash and the escaped character together so the
                // raw segment still carries the escape. `Segment::parse` decodes
                // `\/`, `\\`, and `\:`; any other escaped character is decoded to
                // the bare character there, matching the forgiving older behavior.
                current.push('\\');
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

    /// The path of the containing group: this path with its last segment
    /// dropped, always a group path. The parent of the root path is the root
    /// path. The stage diff uses this to report an entry's `group_path`
    /// alongside its full `path`.
    pub fn parent(&self) -> VaultPath {
        let mut segments = self.segments.clone();
        segments.pop();
        VaultPath {
            segments,
            is_group: true,
        }
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

    /// Resolve and require a group, forcing the final segment to resolve as a
    /// group regardless of a trailing slash.
    ///
    /// This does NOT go through [`resolve`](Self::resolve), because a caller
    /// asking for a group means it: `/Web` and `/Web/` are equivalent on input
    /// (spec section 1), so a group path need not carry a trailing slash. Every
    /// segment, including the last, is walked as a group step, so a missing
    /// group at any level is `GroupNotFound`.
    pub fn resolve_group(&self, db: &Database) -> CoreResult<GroupId> {
        let root_id = db.root().id();
        if self.segments.is_empty() {
            return Ok(root_id);
        }
        let mut current_group = root_id;
        let last = self.segments.len() - 1;
        for seg in &self.segments[..last] {
            current_group = self.step_into_group(db, current_group, seg)?;
        }
        self.step_into_group(db, current_group, &self.segments[last])
    }

    /// Resolve and require an entry.
    ///
    /// The intermediate segments are group steps (`GroupNotFound` if one is
    /// missing); only the last must be an entry (`EntryNotFound` if not).
    ///
    /// A group-shaped path (one that ends in `/`, including the root path `/`)
    /// is refused with `EntryNotFound`: a trailing slash always addresses a
    /// group, so it never names an entry. Before this rule, `/Email/` silently
    /// resolved to an entry titled "Email", so an untitled entry inside group
    /// "Email" (which once formatted as `/Email/`) aliased that other entry.
    /// Unlike [`resolve_group`](Self::resolve_group), which accepts `/Web` and
    /// `/Web/` alike, entry resolution is strict in this one direction.
    pub fn resolve_entry(&self, db: &Database) -> CoreResult<EntryId> {
        let root_id = db.root().id();
        // The root path is group-shaped too; the emptiness check is defensive.
        if self.is_group || self.segments.is_empty() {
            return Err(CoreError::new(ErrorCode::EntryNotFound)
                .with_message("a path ending in '/' addresses a group, not an entry")
                .with_details(serde_json::json!({ "path": self.format() })));
        }
        let mut current_group = root_id;
        let last = self.segments.len() - 1;
        for seg in &self.segments[..last] {
            current_group = self.step_into_group(db, current_group, seg)?;
        }
        self.match_entry(db, current_group, &self.segments[last])
    }

    /// Find the child group of `parent` named by `seg`, honoring the ordinal.
    /// Returns `GroupNotFound` when no matching child group exists.
    ///
    /// keepass 0.12 backs `group_ids()` onto a `HashSet` seeded by a per-process
    /// random hasher, so its iteration order is neither stable across processes
    /// nor identical between two clones of one database. We therefore collect all
    /// name matches and sort them by record UUID before applying the 1-based
    /// ordinal. `clone()` preserves UUIDs, so this makes a given ordinal resolve
    /// to the same group within a session, across sessions, and across the
    /// canonical and working clones.
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

        let mut matches: Vec<GroupId> = parent_ref
            .group_ids()
            .filter(|id| {
                db.group(*id)
                    .map(|child| nfc_normalize(&child.name) == target)
                    .unwrap_or(false)
            })
            .collect();
        // Stable order: sort by UUID so the ordinal is reproducible and clone
        // consistent.
        matches.sort_by_key(|id| id.uuid());

        if let Some(id) = matches.get(wanted - 1) {
            return Ok(*id);
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
    ///
    /// Same determinism concern as `step_into_group`: `entry_ids()` iterates a
    /// `HashSet`, so we collect all title matches and sort them by record UUID
    /// before applying the ordinal. This keeps ":N" reproducible and identical
    /// across the canonical and working clones.
    fn match_entry(&self, db: &Database, parent: GroupId, seg: &Segment) -> CoreResult<EntryId> {
        let parent_ref = db.group(parent).ok_or_else(|| {
            CoreError::new(ErrorCode::EntryNotFound)
                .with_message("containing group is missing")
                .with_details(serde_json::json!({ "path": self.format() }))
        })?;

        let target = nfc_normalize(&seg.name);
        let wanted = seg.ordinal.unwrap_or(1);

        let mut matches: Vec<EntryId> = parent_ref
            .entry_ids()
            .filter(|id| {
                db.entry(*id)
                    .map(|entry| nfc_normalize(entry.get_title().unwrap_or("")) == target)
                    .unwrap_or(false)
            })
            .collect();
        // Stable order: sort by UUID so the ordinal is reproducible and clone
        // consistent.
        matches.sort_by_key(|id| id.uuid());

        if let Some(id) = matches.get(wanted - 1) {
            return Ok(*id);
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
    /// Parse one raw segment string (escapes still present) into a name and
    /// ordinal.
    ///
    /// `raw` still carries the `\/`, `\\`, and `\:` escape sequences the splitter
    /// left in place. The `:N` ordinal suffix is recognized only on an unescaped
    /// trailing colon followed by ASCII digits forming a value of at least 1; an
    /// escaped colon (`\:`) is a literal colon and never an ordinal separator.
    /// The name portion is unescaped here. `full_path` is threaded through only
    /// for error context.
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
                name: unescape_segment(name),
                ordinal: Some(ordinal),
            })
        } else {
            Ok(Segment {
                name: unescape_segment(raw),
                ordinal: None,
            })
        }
    }

    /// Render this segment back to its escaped string form, including the `:N`
    /// suffix when present.
    fn format(&self) -> String {
        let mut out = escape_segment(&self.name);
        if self.ordinal.is_none() && name_reparses_with_ordinal(&self.name) {
            // The name (with no ordinal) ends in ":<digits>", so emitting it
            // verbatim would re-parse as carrying an ordinal. Escape the
            // disambiguator colon so the round-trip preserves the literal name.
            escape_last_unescaped_colon(&mut out);
        }
        if let Some(n) = self.ordinal {
            out.push(':');
            out.push_str(&n.to_string());
        }
        out
    }
}

/// Split a raw (still-escaped) segment into `(name, ordinal_digits)` when it ends
/// in `:N` with `N` a non-empty run of ASCII digits, a non-empty name, and an
/// unescaped colon. Returns `None` otherwise, so a bare name like `Banking`, a
/// name that simply contains a colon without a trailing digit run (`http:port`),
/// or a name whose colon is escaped (`Build\:2`) is left intact.
fn split_ordinal_suffix(raw: &str) -> Option<(&str, &str)> {
    let colon = raw.rfind(':')?;
    // Need a name before the colon and digits after it.
    if colon == 0 {
        return None;
    }
    // The colon must be unescaped: an escaped colon (`\:`) is a literal colon.
    if colon_is_escaped(raw, colon) {
        return None;
    }
    let digits = &raw[colon + 1..];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some((&raw[..colon], digits))
}

/// True when the colon byte at `colon` in `raw` is escaped, that is, preceded by
/// an odd run of backslashes. An even run (including zero) leaves the colon
/// unescaped.
fn colon_is_escaped(raw: &str, colon: usize) -> bool {
    let mut backslashes = 0usize;
    for b in raw[..colon].bytes().rev() {
        if b == b'\\' {
            backslashes += 1;
        } else {
            break;
        }
    }
    backslashes % 2 == 1
}

/// Decode a raw segment's escapes into the literal name. `\/`, `\\`, and `\:`
/// decode to `/`, `\`, and `:`; any other `\x` decodes to the bare `x`, matching
/// the forgiving pass-through the splitter used before.
fn unescape_segment(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            match chars.next() {
                // A trailing lone backslash cannot occur: the splitter rejects a
                // dangling escape. Keep it literal if it ever does.
                Some(next) => out.push(next),
                None => out.push('\\'),
            }
        } else {
            out.push(ch);
        }
    }
    out
}

/// True when `name`, formatted with no ordinal and then re-parsed, would be read
/// as carrying an ordinal: that is, the name ends in ":<one-or-more-digits>".
fn name_reparses_with_ordinal(name: &str) -> bool {
    let Some(colon) = name.rfind(':') else {
        return false;
    };
    if colon == 0 {
        return false;
    }
    let digits = &name[colon + 1..];
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// Escape the last unescaped colon in an already-escaped segment string, turning
/// it into `\:`. Used by formatting to protect a literal trailing ":<digits>"
/// from re-parsing as an ordinal.
fn escape_last_unescaped_colon(escaped: &mut String) {
    if let Some(colon) = escaped.rfind(':') {
        escaped.insert(colon, '\\');
    }
}

/// Escape a segment name for output: a literal `\` becomes `\\` and a literal
/// `/` becomes `\/`. Other characters pass through (the colon is handled
/// separately during formatting, only when needed to avoid an ordinal re-parse).
/// This is the inverse of the unescaping done during parse.
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
/// Backed by the `unicode-normalization` crate, so this is full NFC: canonical
/// reordering of combining marks and composition across the whole Unicode
/// repertoire, not just Latin. Two names that are canonically equivalent
/// normalize to the same string and compare equal, including non-Latin scripts
/// and multi-combining-mark sequences.
fn nfc_normalize(input: &str) -> String {
    input.nfc().collect::<String>()
}

/// Build the canonical [`VaultPath`] of the entry `target` in `db`, or `None`
/// when no entry with that id exists.
///
/// This is the inverse of [`VaultPath::resolve_entry`]: the path it returns
/// resolves back to `target` against the same database and against any clone of
/// it, because same-named siblings receive the same UUID-ordered `:N` ordinal
/// the resolver applies. The read tools and the stage diff use this to report
/// the path of a record they hold by id.
///
/// Returns `None` as well when the entry has no addressable path: its title is
/// empty or some ancestor group's name is empty (see [`addressable`]). Such a
/// record is still reachable by UUID ([`crate::kdbx_core::address`]).
pub fn vault_path_to_entry(db: &Database, target: EntryId) -> Option<VaultPath> {
    let root = db.root().id();
    let mut segments = Vec::new();
    if collect_entry_segments(db, root, target, &mut segments) {
        addressable(VaultPath {
            segments,
            is_group: false,
        })
    } else {
        None
    }
}

/// Build the canonical [`VaultPath`] of the group `target` in `db`, or `None`
/// when no group with that id exists. The root group maps to the bare root path
/// `/`. Inverse of [`VaultPath::resolve_group`]; see [`vault_path_to_entry`],
/// including its rule that a group with an empty name (or under one) has no
/// path.
pub fn vault_path_to_group(db: &Database, target: GroupId) -> Option<VaultPath> {
    let root = db.root().id();
    if target == root {
        return Some(VaultPath {
            segments: Vec::new(),
            is_group: true,
        });
    }
    let mut segments = Vec::new();
    if collect_group_segments(db, root, target, &mut segments) {
        addressable(VaultPath {
            segments,
            is_group: true,
        })
    } else {
        None
    }
}

/// Keep a built path only when it is addressable: every segment has a
/// non-empty name.
///
/// The path grammar has no spelling for an empty name. An empty final entry
/// segment would format as a trailing slash (a group path) and an empty group
/// segment as `//` (rejected by [`VaultPath::parse`]) or as the bare root `/`.
/// Emitting either would hand the agent a path that resolves to a different
/// record, or to nothing, so the rule is: a record whose path would contain an
/// empty segment has no path. Views report `path: null` for it and callers
/// address it by UUID instead. This is the one place that rule lives, so every
/// path the server emits round-trips through `parse` + `resolve_*` back to the
/// record it was built from.
fn addressable(path: VaultPath) -> Option<VaultPath> {
    if path.segments.iter().any(|seg| seg.name.is_empty()) {
        None
    } else {
        Some(path)
    }
}

/// Depth-first search from `group_id` for the entry `target`. Pushes the segment
/// for each group descended into, plus the entry's own segment when found.
/// Returns true with `segments` holding the path on success, or restores
/// `segments` and returns false.
fn collect_entry_segments(
    db: &Database,
    group_id: GroupId,
    target: EntryId,
    segments: &mut Vec<Segment>,
) -> bool {
    let group = match db.group(group_id) {
        Some(g) => g,
        None => return false,
    };

    let entry_ids: Vec<EntryId> = group.entry_ids().collect();
    if entry_ids.contains(&target)
        && let Some(entry) = db.entry(target)
    {
        let title = entry.get_title().unwrap_or("").to_string();
        let ordinal = entry_ordinal(db, &group, target, &title);
        segments.push(Segment {
            name: title,
            ordinal,
        });
        return true;
    }

    let child_ids: Vec<GroupId> = group.group_ids().collect();
    for cid in child_ids {
        let name = match db.group(cid) {
            Some(child) => child.name.clone(),
            None => continue,
        };
        let ordinal = group_ordinal(db, &group, cid, &name);
        segments.push(Segment { name, ordinal });
        if collect_entry_segments(db, cid, target, segments) {
            return true;
        }
        segments.pop();
    }
    false
}

/// Depth-first search from `group_id` for the group `target`, pushing a segment
/// per group descended into. Same success and backtrack contract as
/// [`collect_entry_segments`].
fn collect_group_segments(
    db: &Database,
    group_id: GroupId,
    target: GroupId,
    segments: &mut Vec<Segment>,
) -> bool {
    let group = match db.group(group_id) {
        Some(g) => g,
        None => return false,
    };

    let child_ids: Vec<GroupId> = group.group_ids().collect();
    for cid in child_ids {
        let name = match db.group(cid) {
            Some(child) => child.name.clone(),
            None => continue,
        };
        let ordinal = group_ordinal(db, &group, cid, &name);
        segments.push(Segment { name, ordinal });
        if cid == target || collect_group_segments(db, cid, target, segments) {
            return true;
        }
        segments.pop();
    }
    false
}

/// The 1-based ordinal of entry `target` among same-titled siblings of `group`,
/// ordered by record UUID (matching [`VaultPath::match_entry`]). `None` when
/// `target` is the only entry with its title, so the formatted path omits the
/// ordinal.
fn entry_ordinal(
    db: &Database,
    group: &keepass::db::GroupRef<'_>,
    target: EntryId,
    title: &str,
) -> Option<usize> {
    let wanted = nfc_normalize(title);
    let mut ids: Vec<EntryId> = group
        .entry_ids()
        .filter(|id| {
            db.entry(*id)
                .map(|e| nfc_normalize(e.get_title().unwrap_or("")) == wanted)
                .unwrap_or(false)
        })
        .collect();
    ids.sort_by_key(|id| id.uuid());
    if ids.len() <= 1 {
        return None;
    }
    ids.iter().position(|id| *id == target).map(|i| i + 1)
}

/// The 1-based ordinal of group `target` among same-named sibling groups of
/// `group`, ordered by record UUID (matching [`VaultPath::step_into_group`]).
/// `None` when `target` is the only group with its name.
fn group_ordinal(
    db: &Database,
    group: &keepass::db::GroupRef<'_>,
    target: GroupId,
    name: &str,
) -> Option<usize> {
    let wanted = nfc_normalize(name);
    let mut ids: Vec<GroupId> = group
        .group_ids()
        .filter(|id| {
            db.group(*id)
                .map(|g| nfc_normalize(&g.name) == wanted)
                .unwrap_or(false)
        })
        .collect();
    ids.sort_by_key(|id| id.uuid());
    if ids.len() <= 1 {
        return None;
    }
    ids.iter().position(|id| *id == target).map(|i| i + 1)
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
        // The generic resolve() respects the trailing-slash flag: a path without
        // one tries an entry first and fails for a group name.
        let path = VaultPath::parse("/Web/Banking").unwrap();
        let err = path.resolve(&db).expect_err("no entry named Banking");
        assert_eq!(err.code_enum(), ErrorCode::EntryNotFound);

        // But resolve_group forces a group regardless of the trailing slash:
        // `/Web`, `/Web/`, `/Web/Banking`, and `/Web/Banking/` all resolve. This
        // is the contract add_entry relies on (group_path has no trailing slash).
        for p in ["/Web", "/Web/", "/Web/Banking", "/Web/Banking/"] {
            let gid = VaultPath::parse(p)
                .unwrap()
                .resolve_group(&db)
                .unwrap_or_else(|_| panic!("{p} should resolve to a group"));
            let name = db.group(gid).unwrap().name.clone();
            assert!(name == "Web" || name == "Banking", "{p} resolved to {name}");
        }
        // The root path resolves to the root group.
        assert_eq!(
            VaultPath::parse("/").unwrap().resolve_group(&db).unwrap(),
            db.root().id()
        );
    }

    #[test]
    fn resolve_entry_forces_entry_kind_without_trailing_slash() {
        let db = build_db();
        // resolve_entry forces the final segment to an entry. A group name fails
        // as ENTRY_NOT_FOUND; the actual entry resolves.
        assert_eq!(
            VaultPath::parse("/Web")
                .unwrap()
                .resolve_entry(&db)
                .unwrap_err()
                .code_enum(),
            ErrorCode::EntryNotFound
        );
        assert!(
            VaultPath::parse("/Web/Banking/MyBank")
                .unwrap()
                .resolve_entry(&db)
                .is_ok()
        );
        // The root path has no entry.
        assert_eq!(
            VaultPath::parse("/")
                .unwrap()
                .resolve_entry(&db)
                .unwrap_err()
                .code_enum(),
            ErrorCode::EntryNotFound
        );
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
        // Siblings that share a name are ordered by record UUID, so which "Dup"
        // is :1 versus :2 is fixed (not subject to keepass HashSet iteration
        // order). The contract we assert here: a bare name and ":1" both pick the
        // first sibling, ":2" picks a different sibling, and the two together
        // cover both usernames. The clone-consistency and fixed-UUID guarantees
        // are asserted in `ordinals_are_uuid_ordered_and_clone_consistent`.
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

    #[test]
    fn ordinals_are_uuid_ordered_and_clone_consistent() {
        // Two same-named sibling entries: ":1" must map to the smaller UUID and
        // ":2" to the larger, and that mapping must be identical against a clone
        // of the database (clone preserves UUIDs). This is the property that
        // keeps "name:N" resolving to the same record in the canonical and
        // working clones of the stage/commit model.
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            root.add_entry()
                .edit(|e| e.set_unprotected(fields::TITLE, "Twin"));
            root.add_entry()
                .edit(|e| e.set_unprotected(fields::TITLE, "Twin"));
        }

        // The two UUIDs, sorted, give the fixed expected mapping.
        let mut uuids: Vec<uuid::Uuid> = db
            .iter_all_entries()
            .filter(|e| e.get_title() == Some("Twin"))
            .map(|e| e.id().uuid())
            .collect();
        assert_eq!(uuids.len(), 2, "two twins seeded");
        uuids.sort();
        let (smaller, larger) = (uuids[0], uuids[1]);

        let first = VaultPath::parse("/Twin:1")
            .unwrap()
            .resolve_entry(&db)
            .expect("Twin:1 resolves");
        let second = VaultPath::parse("/Twin:2")
            .unwrap()
            .resolve_entry(&db)
            .expect("Twin:2 resolves");
        assert_eq!(first.uuid(), smaller, ":1 maps to the smaller UUID");
        assert_eq!(second.uuid(), larger, ":2 maps to the larger UUID");

        // A clone has the same UUIDs, so the same ordinal maps to the same UUID.
        let clone = db.clone();
        let first_clone = VaultPath::parse("/Twin:1")
            .unwrap()
            .resolve_entry(&clone)
            .expect("Twin:1 resolves in clone");
        let second_clone = VaultPath::parse("/Twin:2")
            .unwrap()
            .resolve_entry(&clone)
            .expect("Twin:2 resolves in clone");
        assert_eq!(
            first_clone.uuid(),
            first.uuid(),
            ":1 is identical across the clone"
        );
        assert_eq!(
            second_clone.uuid(),
            second.uuid(),
            ":2 is identical across the clone"
        );
    }

    #[test]
    fn literal_colon_digit_title_round_trips() {
        // A title that literally ends in ":<digits>" must survive format/parse:
        // the disambiguator colon is escaped so it does not re-parse as an
        // ordinal. The literal is written with an escaped colon on input.
        for (input, want_name) in [
            ("/A/Build\\:2", "Build:2"),
            ("/Server\\:8080", "Server:8080"),
        ] {
            let once = VaultPath::parse(input).expect("parse");
            let last = once.segments.last().expect("a segment");
            assert_eq!(last.name, want_name);
            assert!(
                last.ordinal.is_none(),
                "a literal name is not read as an ordinal: {input}"
            );
            // format then re-parse is identity on the parsed value.
            let formatted = once.format();
            let twice = VaultPath::parse(&formatted).expect("re-parse formatted");
            assert_eq!(once, twice, "round-trips: {input} -> {formatted}");
        }
    }

    #[test]
    fn escaped_colon_is_a_literal_colon_not_an_ordinal() {
        // Explicit "\:" input is a literal colon, never an ordinal separator.
        let p = VaultPath::parse("/Build\\:2").expect("parse escaped colon");
        assert_eq!(p.segments.len(), 1);
        assert_eq!(p.segments[0].name, "Build:2");
        assert_eq!(p.segments[0].ordinal, None);
        // And it formats back to the escaped form.
        assert_eq!(p.format(), "/Build\\:2");
    }

    #[test]
    fn literal_colon_digit_title_resolves_to_that_entry_not_an_ordinal() {
        // A group "A" with an entry literally titled "Build:2" plus two "Build"
        // siblings. "/A/Build:2" must find the literal "Build:2" entry, while
        // "/A/Build\:2" written as the explicit ordinal path "/A/Build:2" is the
        // literal. The ordinal form is reachable by an unescaped colon.
        let mut db = Database::new();
        let a_id = db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "A".to_string())
            .id();
        db.group_mut(a_id).unwrap().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "Build:2");
            e.set_unprotected(fields::USERNAME, "literal");
        });
        db.group_mut(a_id).unwrap().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "Build");
            e.set_unprotected(fields::USERNAME, "first-build");
        });
        db.group_mut(a_id).unwrap().add_entry().edit(|e| {
            e.set_unprotected(fields::TITLE, "Build");
            e.set_unprotected(fields::USERNAME, "second-build");
        });

        // "/A/Build:2" parses with a trailing unescaped ":2", so it is the
        // ordinal path: it selects the second "Build" sibling, not the literal.
        let ordinal_hit = VaultPath::parse("/A/Build:2")
            .unwrap()
            .resolve_entry(&db)
            .expect("ordinal Build:2 resolves");
        assert_eq!(
            db.entry(ordinal_hit).unwrap().get_title(),
            Some("Build"),
            "unescaped :2 is the second Build sibling"
        );

        // The escaped form "/A/Build\:2" is the literal entry titled "Build:2".
        let literal_hit = VaultPath::parse("/A/Build\\:2")
            .unwrap()
            .resolve_entry(&db)
            .expect("literal Build:2 resolves");
        assert_eq!(
            db.entry(literal_hit).unwrap().get_title(),
            Some("Build:2"),
            "escaped :2 is the literal title"
        );
        assert_eq!(
            db.entry(literal_hit).unwrap().get("UserName"),
            Some("literal")
        );
    }

    #[test]
    fn nfc_handles_non_latin_and_multi_mark_cases() {
        // Cases the old hand-rolled Latin-only table missed.
        //
        // 1. Canonical ordering of two combining marks: "q" + dot-below (U+0323)
        //    + acute (U+0301) and the same marks in the other input order both
        //    normalize to the same NFC string. The old table only folded a single
        //    mark over an ASCII base, so it left these two unequal.
        let a = "q\u{0323}\u{0301}";
        let b = "q\u{0301}\u{0323}";
        assert_ne!(a, b, "inputs differ before normalization");
        assert_eq!(nfc_normalize(a), nfc_normalize(b));

        // 2. A non-Latin script: Greek alpha + combining acute (U+0301) composes
        //    to precomposed alpha-with-tonos (U+03AC). The old table had no Greek.
        let decomposed = "\u{03B1}\u{0301}";
        let precomposed = "\u{03AC}";
        assert_ne!(decomposed, precomposed, "differ before normalization");
        assert_eq!(nfc_normalize(decomposed), nfc_normalize(precomposed));
        assert_eq!(nfc_normalize(decomposed), precomposed);
    }

    // Inverse builders: vault_path_to_entry / vault_path_to_group.

    #[test]
    fn vault_path_to_entry_round_trips_and_resolves_back() {
        let db = build_db();
        // Resolve a known entry to its id, build its path, and confirm the path
        // both formats canonically and resolves back to the same id.
        let id = VaultPath::parse("/Web/Banking/MyBank")
            .unwrap()
            .resolve_entry(&db)
            .unwrap();
        let path = vault_path_to_entry(&db, id).expect("entry has a path");
        assert_eq!(path.format(), "/Web/Banking/MyBank");
        assert!(!path.is_group_path());
        assert_eq!(path.resolve_entry(&db).unwrap(), id);
    }

    #[test]
    fn vault_path_to_group_round_trips_and_root_is_slash() {
        let db = build_db();
        let banking = VaultPath::parse("/Web/Banking/")
            .unwrap()
            .resolve_group(&db)
            .unwrap();
        let path = vault_path_to_group(&db, banking).expect("group has a path");
        assert_eq!(path.format(), "/Web/Banking");
        assert!(path.is_group_path());
        assert_eq!(path.resolve_group(&db).unwrap(), banking);

        // The root group maps to the bare root path.
        let root_path = vault_path_to_group(&db, db.root().id()).expect("root path");
        assert!(root_path.is_root());
        assert_eq!(root_path.format(), "/");
    }

    #[test]
    fn vault_path_to_entry_disambiguates_duplicate_siblings() {
        let db = build_db();
        // The two "Dup" entries under /Web each get a distinct ordinal path that
        // resolves back to its own id, and the two paths differ.
        let first = VaultPath::parse("/Web/Dup:1")
            .unwrap()
            .resolve_entry(&db)
            .unwrap();
        let second = VaultPath::parse("/Web/Dup:2")
            .unwrap()
            .resolve_entry(&db)
            .unwrap();
        assert_ne!(first, second);

        let p1 = vault_path_to_entry(&db, first).unwrap();
        let p2 = vault_path_to_entry(&db, second).unwrap();
        assert_ne!(p1.format(), p2.format());
        assert_eq!(p1.resolve_entry(&db).unwrap(), first);
        assert_eq!(p2.resolve_entry(&db).unwrap(), second);
        // Each formatted path carries an ordinal (the siblings are ambiguous).
        assert!(p1.format().starts_with("/Web/Dup:"));
        assert!(p2.format().starts_with("/Web/Dup:"));
    }

    #[test]
    fn vault_path_is_clone_consistent() {
        let db = build_db();
        let clone = db.clone();
        // A path built against one database resolves to the same record in a
        // clone, because ordinals are UUID-ordered and clone preserves UUIDs.
        let id = VaultPath::parse("/Web/Dup:2")
            .unwrap()
            .resolve_entry(&db)
            .unwrap();
        let path = vault_path_to_entry(&db, id).unwrap();
        let id_in_clone = path.resolve_entry(&clone).unwrap();
        assert_eq!(id.uuid(), id_in_clone.uuid());
    }

    #[test]
    fn parent_drops_last_segment_as_group_path() {
        let entry = VaultPath::parse("/Web/Banking/MyBank").unwrap();
        let parent = entry.parent();
        assert!(parent.is_group_path());
        assert_eq!(parent.format(), "/Web/Banking");
        // Parent of a top-level entry is the root; parent of root is root.
        assert_eq!(VaultPath::parse("/MyBank").unwrap().parent().format(), "/");
        assert!(VaultPath::parse("/").unwrap().parent().is_root());
    }

    // Aliasing: a formatted path must never resolve to a different record.

    /// The review probe's shape: a root entry titled "Email" plus a group
    /// "Email" holding an entry with no title. Returns (db, root entry id,
    /// untitled entry id).
    fn db_with_untitled_entry_in_same_named_group() -> (Database, EntryId, EntryId) {
        let mut db = Database::new();
        let root_entry = db
            .root_mut()
            .add_entry()
            .edit(|e| {
                e.set_unprotected(fields::TITLE, "Email");
                e.set_protected(fields::PASSWORD, "root-email-secret");
            })
            .id();
        let gid = db
            .root_mut()
            .add_group()
            .edit(|g| g.name = "Email".to_string())
            .id();
        let untitled = db
            .group_mut(gid)
            .unwrap()
            .add_entry()
            .edit(|e| e.set_protected(fields::PASSWORD, "untitled-secret"))
            .id();
        (db, root_entry, untitled)
    }

    #[test]
    fn untitled_entry_has_no_path() {
        // An empty title would format as "/Email/", which parses as the group
        // path "/Email" and (before the fix) resolved to the root entry titled
        // "Email". The untitled entry must have no path at all.
        let (db, _root_entry, untitled) = db_with_untitled_entry_in_same_named_group();
        assert!(vault_path_to_entry(&db, untitled).is_none());
    }

    #[test]
    fn unnamed_group_has_no_path_and_neither_do_its_entries() {
        // A top-level group with an empty name would format as "/", aliasing
        // the root group; an entry inside it would format as "//Title", which
        // does not even parse. Neither gets a path.
        let mut db = Database::new();
        let gid = db.root_mut().add_group().id();
        let eid = db
            .group_mut(gid)
            .unwrap()
            .add_entry()
            .edit(|e| e.set_unprotected(fields::TITLE, "Inside"))
            .id();
        assert!(vault_path_to_group(&db, gid).is_none());
        assert!(vault_path_to_entry(&db, eid).is_none());
    }

    #[test]
    fn resolve_entry_rejects_a_group_shaped_path() {
        // "/Email/" addresses a group. resolve_entry used to ignore the trailing
        // slash and match the root entry titled "Email"; it must refuse instead.
        let (db, _root_entry, _untitled) = db_with_untitled_entry_in_same_named_group();
        let err = VaultPath::parse("/Email/")
            .unwrap()
            .resolve_entry(&db)
            .expect_err("a trailing slash never names an entry");
        assert_eq!(err.code_enum(), ErrorCode::EntryNotFound);
        // The entry-shaped path still reaches the root entry.
        assert!(
            VaultPath::parse("/Email")
                .unwrap()
                .resolve_entry(&db)
                .is_ok()
        );
    }

    #[test]
    fn every_emitted_entry_path_resolves_back_to_its_own_entry() {
        // The non-aliasing property over a database full of awkward names: for
        // every entry, a path is either absent or it parses and resolves to
        // exactly that entry (never to another node).
        let (mut db, _, _) = db_with_untitled_entry_in_same_named_group();
        let awkward = [
            "a/b",
            "back\\slash",
            "Build:2",
            ":3",
            "Email",
            "Email",
            "trailing ",
        ];
        for title in awkward {
            db.root_mut()
                .add_entry()
                .edit(|e| e.set_unprotected(fields::TITLE, title));
        }
        let unnamed = db.root_mut().add_group().id();
        db.group_mut(unnamed)
            .unwrap()
            .add_entry()
            .edit(|e| e.set_unprotected(fields::TITLE, "Lost"));

        let ids: Vec<EntryId> = db.iter_all_entries().map(|e| e.id()).collect();
        let mut with_path = 0;
        for id in ids {
            if let Some(p) = vault_path_to_entry(&db, id) {
                with_path += 1;
                let reparsed = VaultPath::parse(&p.format()).expect("emitted path parses");
                assert_eq!(
                    reparsed.resolve_entry(&db).expect("emitted path resolves"),
                    id,
                    "path {} aliases another entry",
                    p.format()
                );
            }
        }
        // Root "Email" plus the seven awkward titles; the untitled entry and the
        // entry under the unnamed group have none.
        assert_eq!(with_path, 8);
    }

    #[test]
    fn vault_path_to_entry_unknown_id_is_none() {
        let db = build_db();
        // A group id is not an entry id, so building an entry path from a group
        // id (or any id not present as an entry) yields None.
        let group = db.root().id();
        // Construct an entry-typed lookup that cannot match: the root group's id
        // reinterpreted is not in the entry store. We instead use a fresh db's
        // entry id to guarantee absence.
        let other = {
            let mut d = Database::new();
            d.root_mut()
                .add_entry()
                .edit(|e| e.set_unprotected(fields::TITLE, "Lonely"));
            d.iter_all_entries().next().unwrap().id()
        };
        assert!(vault_path_to_entry(&db, other).is_none());
        assert!(vault_path_to_group(&db, group).is_some());
    }
}
