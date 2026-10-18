# mcp-kdbx: MCP server for KDBX vaults

**Project:** mcp-kdbx (bridge member of the *-kdbx ecosystem)
**Date:** 2026-05-08
**Author:** Alexander Towell
**Status:** Implemented through Phase 3 of the v0.1 plan (`docs/superpowers/plans/2026-05-09-mcp-kdbx-v0.1.md`) on branch `feat/v0.1`; Phases 4-5 (tests, CI, docs) pending. The design below is the historical v0.1 record; see CLAUDE.md for the three deliberate deviations from its letter.
**Supersedes:** none (this is the v0.1 design)

## Goal

A local Model Context Protocol (MCP) server that exposes a KeePass `.kdbx` file to AI agents. v0.1 is a stdio MCP server: an LLM agent can list groups and entries, find by title or URL, reveal protected fields with per-secret consent gating, generate TOTP codes, list and download attachments, and (when explicitly enabled) add new entries and update fields. Writes are staged in memory and committed atomically on save, with the diff visible via diff-kdbx.

The server is a single Rust binary spawned by an MCP host (Claude Desktop, Claude Code, Cursor). It reads its configuration from environment variables, opens the vault at startup (encrypted bytes only), and unlocks on first request via env-var password or shell-out to a secret manager.

## Position in the *-kdbx ecosystem

mcp-kdbx is a **bridge** member: it exposes KDBX to AI agents. Relationship to other members:

| Member | Role | How mcp-kdbx relates |
|---|---|---|
| `keepass-rs` | Substrate | Direct dependency. Provides parsing, encryption, write API. |
| `diff-kdbx` | Sibling | Library dependency for `kdbx_diff_pending` (semantic-diff between canonical and working_db). |
| `web-kdbx` | Sibling | Independent. Both consume `keepass-rs`. Different consumer (browser users vs LLM agents). |
| `hugo-kdbx`, `arkiv-kdbx`, `longecho-kdbx` | Bridges, planned | Out of scope for v0.1. |

The shared substrate for the whole ecosystem is `keepass-rs`. mcp-kdbx contributes back by being the first agent-facing consumer at scale, surfacing API gaps that emerge from a tool-call-shaped surface.

## Motivation

Three problems converge to make this v0.1 worth building:

### 1. AI agents are credential-shaped consumers

A large class of agentic workflows needs credentials: signing into a service, fetching a TOTP, retrieving an API key from a saved vault entry, saving a new credential after a signup flow. Today the agent either (a) asks the human to paste the secret, breaking the agent's flow, (b) fetches from environment variables that pre-load every secret without granular consent, or (c) integrates with one specific cloud password manager via SDK. None of these compose well with a static, local, single-file vault format.

mcp-kdbx is the integration that lets LLM-host UIs gate per-secret access in a way the user can audit afterwards.

### 2. KDBX is the right substrate for AI-managed credentials

KDBX is encrypted at rest with the user's master password. It's portable (KeePassXC, OmniKee, web-kdbx all read it). It supports attachments (key files, recovery codes, certificate PEMs). It has a built-in TOTP convention that downstream tooling already understands. And it's not a SaaS lock-in.

Most importantly, KDBX supports the **per-field protected flag**, which directly maps to mcp-kdbx's consent-gating model: the lib's notion of "this field is protected" tells the MCP layer "this requires an explicit per-call reveal."

### 3. The agent-facing trust model is genuinely different

Browser-based vault UIs (web-kdbx, OmniKee PWA) optimize for human users who decide what to view at click-time. CLI vaults optimize for shell pipelines. AI agents are something new: an autonomous program with imperfect judgment that needs **graduated** access (bulk metadata is cheap; secrets are expensive) and **reviewable** writes (proposed changes shouldn't auto-commit). v0.1 is an opinionated take on what that gradient looks like.

## Architectural decisions

These decisions were settled during the 2026-05-06 brainstorm (sections 1-8 below detail them):

| Decision | Choice | Rationale |
|---|---|---|
| Scope of MCP exposure | Per-vault server (Q1) | One mcp-kdbx instance manages exactly one vault. Multi-vault aggregation is a higher-layer concern. |
| Value model | Single-vault (Q2) | Matches stdio MCP host lifecycle; user runs one mcp-kdbx per vault if multiple are needed. |
| Auth + lifecycle | Env var with secret-manager fallback, 15-min idle TTL (Q3 = A+C) | LLM-host-friendly default (env var); secret-manager users get `KDBX_UNLOCK_CMD`. Per-call password override via `kdbx_unlock`. |
| Write capability | Read + limited write, gated by `KDBX_ALLOW_WRITES=true` (Q4) | Read-only is too restrictive for the credential-lifecycle use case; full read+write opens too much blast radius. Limited writes (`add_entry`, `update_field`; no delete/move) behind a startup flag is the conservative-useful midpoint. |
| Implementation approach | Approach 1 + diff-kdbx slice | stdio MCP server, single Rust binary, direct `keepass-rs` for vault ops, `diff-kdbx` library dep for stage diffs. ~2000 LOC. |

The complete specification follows in eight sections.

---

# Section 1: MCP protocol surface

## Naming and namespace

All tools prefixed with `kdbx_`, snake_case. Matches Anthropic's first-party MCP servers and the broader plugin ecosystem.

## Tool inventory

| Tool | Category |
|---|---|
| `kdbx_unlock` | Lifecycle |
| `kdbx_lock` | Lifecycle |
| `kdbx_status` | Lifecycle |
| `kdbx_list_groups` | Read |
| `kdbx_list_entries` | Read |
| `kdbx_list_attachments` | Read |
| `kdbx_get_entry` | Read |
| `kdbx_find_entry` | Read |
| `kdbx_reveal_password` | Reveal (consent-gated) |
| `kdbx_reveal_protected` | Reveal (consent-gated) |
| `kdbx_download_attachment` | Reveal (consent-gated) |
| `kdbx_get_otp` | Reveal (consent-gated) |
| `kdbx_add_entry` | Write (gated by `KDBX_ALLOW_WRITES`) |
| `kdbx_update_field` | Write (gated by `KDBX_ALLOW_WRITES`) |
| `kdbx_diff_pending` | Stage/commit (gated) |
| `kdbx_save_pending` | Stage/commit (gated) |
| `kdbx_discard_pending` | Stage/commit (gated) |

17 tools total.

## Output format

Every tool returns a JSON object as a text-content block. Structure:

```json
{ "ok": true, "data": { /* tool-specific payload */ } }
```

Or on error:

```json
{
  "ok": false,
  "error": {
    "code": "VAULT_LOCKED",
    "message": "Vault is locked. Call kdbx_unlock first.",
    "details": { /* optional, error-specific */ }
  }
}
```

Rationale: the structured-result-with-`ok`-flag is consistently parseable from prompt text without the LLM needing to know about MCP-protocol-level error semantics. It is also amenable to an audit trail (one shape to log) and easier to extend (add fields without breaking parsers).

## Path conventions

Paths use forward slashes, rooted at `/`. Group separator is `/`. Entry titles are case-sensitive, NFC-normalized.

```
/                              root group
/Web                           group "Web" under root
/Web/Banking                   group "Banking" under "Web"
/Web/Banking/MyBank            entry "MyBank" in group "Web/Banking"
```

**Slashes in titles:** `\/` escapes a literal slash; `\\` escapes a literal backslash. Output paths emit the necessary escapes; LLMs pass them back verbatim.

**Disambiguation:** when two siblings have the same name, suffix with `:N` (1-based ordinal by KDBX iteration order):

```
/Web/MyBank        first MyBank
/Web/MyBank:2      second MyBank
```

Ordinals are stable within a session, can shift across sessions. UUIDs (returned in every response) are the cross-session-stable identifier.

**Trailing slash:** `/Web/Banking` and `/Web/Banking/` are equivalent on input. Output paths are canonical (no trailing slash).

## Tool schemas

### Lifecycle

```ts
// kdbx_unlock
input:  { password?: string, keyfile_bytes?: string /* base64 */ }
output: { ok: true, data: { vault_name: string, locked: false, has_pending_changes: boolean } }
errors: AUTH_FAILED, VAULT_NOT_FOUND, VAULT_ALREADY_UNLOCKED, UNLOCK_SOURCE_MISSING

// kdbx_lock
input:  {}
output: { ok: true, data: { locked: true, pending_discarded: number } }

// kdbx_status
input:  {}
output: {
  ok: true,
  data: {
    locked: boolean,
    vault_name: string | null,
    vault_path: string,                                  // absolute
    idle_timeout_remaining_seconds: number | null,        // null if locked
    has_pending_changes: boolean | null,                  // null if locked
    writes_allowed: boolean,
    server_version: string,
    keepass_rs_version: string
  }
}
```

### Reads

```ts
// kdbx_list_groups
input:  { parent_path?: string }                         // default "/"
output: {
  ok: true,
  data: {
    groups: [{
      name: string,
      path: string,
      uuid: string,
      num_entries: number,
      num_subgroups: number,
      notes: string | null
    }]
  }
}

// kdbx_list_entries
input:  { group_path: string }
output: {
  ok: true,
  data: {
    entries: [{
      title: string,
      path: string,
      uuid: string,
      username: string | null,                            // null if absent or protected
      url: string | null,                                 // null if absent or protected
      notes_preview: string | null,                       // first 200 chars; null if absent or protected
      standard_field_names: { name: string, protected: boolean }[],  // present standard fields, canonical order
      custom_field_names: { name: string, protected: boolean }[],
      has_attachments: boolean,
      has_otp: boolean,
      modified_at: string                                 // ISO 8601
    }]
  }
}

// kdbx_list_attachments
input:  { entry_path: string }
output: {
  ok: true,
  data: {
    attachments: [{ name: string, size_bytes: number, sha256: string /* hex */ }]
  }
}

// kdbx_get_entry
input:  { path: string }
output: {
  ok: true,
  data: {
    title, path, uuid, username, url, notes,              // notes full, not preview; null if absent or protected
    standard_field_names: { name: string, protected: boolean }[],
    custom_field_names: { name: string, protected: boolean }[],
    has_attachments: boolean,
    has_otp: boolean,
    created_at: string,
    modified_at: string,
    accessed_at: string
    // No password, no protected values, no attachment bytes.
  }
}

// kdbx_find_entry
input:  {
  query: string,
  fields?: ("title" | "username" | "url" | "notes")[]    // default ["title", "username", "url"]
}
output: {
  ok: true,
  data: {
    entries: [ /* same shape as kdbx_list_entries */ ],
    matched_count: number,
    truncated: boolean                                     // true if >100 matches
  }
}
```

### Reveals (consent-gated)

```ts
// kdbx_reveal_password
input:  { path: string }
output: { ok: true, data: { password: string } }

// kdbx_reveal_protected
input:  { path: string, field_name: string }
output: { ok: true, data: { value: string } }

// kdbx_download_attachment
input:  { entry_path: string, name: string }
output: { ok: true, data: { name, size_bytes, sha256, base64: string } }

// kdbx_get_otp
input:  { path: string, time_unix?: number }              // default now
output: { ok: true, data: { code: string, valid_for_seconds: number, period_seconds: number } }
```

### Writes (gated by KDBX_ALLOW_WRITES)

```ts
// kdbx_add_entry
input: {
  group_path: string,
  title: string,
  fields?: { [name: string]: { value: string, protected: boolean } },
  attachments?: { [name: string]: { base64: string } },
  created_at?: string,                                   // ISO 8601, optional, for fixtures
  modified_at?: string                                    // ISO 8601, optional, for fixtures
}
output: { ok: true, data: { staged: true, path: string, uuid: string } }

// kdbx_update_field
input: { path: string, field_name: string, value: string, protected?: boolean }
output: { ok: true, data: { staged: true, path: string, field_name: string } }
```

### Stage/commit (gated)

```ts
// kdbx_diff_pending
input:  {}
output: {
  ok: true,
  data: {
    added: [{ path, uuid, title, group_path, field_count, has_attachments, has_otp }],
    modified: [{
      path, uuid, title,
      field_changes: [
        { field_name, before, after, protected: false } |
        { field_name, changed: true, protected: true }    // protected fields redacted
      ],
      attachment_changes: [{ name, change: "added" | "removed" | "modified" }]
    }],
    removed: [],                                          // reserved for future
    summary: { num_added: number, num_modified: number, num_removed: number }
  }
}

// kdbx_save_pending
input:  {}
output: { ok: true, data: { saved: true, num_changes, vault_path, written_at } }

// kdbx_discard_pending
input:  {}
output: { ok: true, data: { discarded: true, num_dropped: number } }
```

## Error code enumeration

| Code | When |
|---|---|
| `VAULT_LOCKED` | Tool requires unlocked vault, vault is locked |
| `VAULT_ALREADY_UNLOCKED` | `kdbx_unlock` called when already unlocked |
| `VAULT_NOT_FOUND` | Vault file path doesn't resolve |
| `AUTH_FAILED` | Wrong password / keyfile |
| `UNLOCK_SOURCE_MISSING` | `kdbx_unlock` called with no password and no env source configured |
| `GROUP_NOT_FOUND` | Path doesn't resolve to a group |
| `ENTRY_NOT_FOUND` | Path doesn't resolve to an entry |
| `FIELD_NOT_FOUND` | Entry has no field by that name |
| `FIELD_NOT_PROTECTED` | Reveal called on a non-protected field |
| `ATTACHMENT_NOT_FOUND` | Entry has no attachment by that name |
| `NO_OTP_CONFIGURED` | Entry has no `otp` field or no valid TOTP URI |
| `WRITES_DISABLED` | Write tool called when `KDBX_ALLOW_WRITES != true` |
| `NO_PENDING_CHANGES` | `kdbx_save_pending` called with empty stage |
| `WRITE_FAILED` | Disk write failed |
| `VAULT_FILE_MODIFIED` | mtime changed since unlock |
| `ENTRY_TITLE_INVALID` | Title is empty or contains literal `/` |
| `FIELD_NAME_INVALID` | Field name is empty or has reserved characters |
| `INVALID_INPUT` | A supplied value is malformed in a way no other code names (see implementation notes) |
| `PATH_INVALID` | A path is malformed: no leading `/`, an empty `//` segment, a dangling `\` escape, or a `:0` ordinal (implementation notes, 2026-10-18) |
| `VAULT_UNREADABLE` | The vault file fails before any key check: `details.reason` is `not_kdbx`, `unsupported_version`, `truncated`, or `corrupt_header` (implementation notes, 2026-10-18) |

## Versioning

Server version surfaces via `kdbx_status.server_version`. Tool schemas follow semver: breaking input/output changes bump the major. The `keepass_rs_version` is reported separately because the MCP layer can be stable across keepass-rs upgrades.

---

# Section 2: Auth + lifecycle

## Configuration surface

Environment variables only in v0.1. No CLI flags, no config file.

| Env var | Purpose | Default |
|---|---|---|
| `KDBX_VAULT_PATH` | Absolute path to the .kdbx file | **Required** |
| `KDBX_KEYFILE_PATH` | Optional keyfile for two-factor unlock | unset |
| `KDBX_PASSWORD` | Master password (env-injected) | unset |
| `KDBX_UNLOCK_CMD` | Shell command whose stdout is the master password | unset |
| `KDBX_UNLOCK_CMD_TIMEOUT_SECONDS` | Timeout for the unlock command | 30 |
| `KDBX_ALLOW_WRITES` | Must be exactly `"true"` to enable any write tool | unset (read-only) |
| `KDBX_IDLE_TIMEOUT_SECONDS` | Auto-lock after N seconds of inactivity | 900 (15 min) |
| `KDBX_AUTO_CLEAN_ORPHANS` | Auto-clean orphan `*.tmp.*` files at startup | unset (off) |
| `KDBX_LOG_LEVEL` | `error`, `warn`, `info`, `debug`, `trace` | `info` |
| `KDBX_LOG_FILE` | Append-only audit log path. Empty means stderr only | unset |

## Startup sequence

```
1. Read env vars.
2. Validate KDBX_VAULT_PATH (resolve absolute, file must exist + be readable).
   On failure: exit(1) with stderr message.
3. Validate KDBX_ALLOW_WRITES (must be "" or "true"). Reject other values.
4. Validate KDBX_IDLE_TIMEOUT_SECONDS (parse 0..86400; 0 = no idle lock).
5. Open log destination if KDBX_LOG_FILE is set.
6. Read encrypted vault bytes into memory (no decryption yet).
7. Capture vault file mtime as file_mtime_at_unlock.
8. If KDBX_AUTO_CLEAN_ORPHANS=true: scan vault dir for *.tmp.<pid>.* files
   older than 1 hour, unlink.
9. Initialize state: Locked.
10. Start MCP server on stdio.
```

## State machine

```
                       [Locked]  ← initial
                          │
                  kdbx_unlock(...)
                          │
                          ▼
                       [Unlocked {
                         key,
                         canonical_db,
                         working_db,
                         last_activity,
                         file_mtime_at_unlock
                       }]
                          │
       ┌──────────────────┼──────────────────────┐
       │                  │                      │
   kdbx_lock         idle_timeout            shutdown
       │                  │                      │
       ▼                  ▼                      ▼
   [Locked]           [Locked]                 (drop)

  Tool calls in Unlocked state update last_activity.
  Lock transitions: zero key, drop both dbs, discard stage,
                    log lock_reason.
```

## Unlock sequence

```
1. Tool call: kdbx_unlock(password?, keyfile_bytes?).
2. Resolve unlock source, in priority order:
     a. password from tool input, if provided
     b. KDBX_PASSWORD env var, if set
     c. KDBX_UNLOCK_CMD env var: exec via /bin/sh -c, timeout
        KDBX_UNLOCK_CMD_TIMEOUT_SECONDS, capture trimmed stdout.
        Non-zero exit -> AUTH_FAILED.
     d. None set and no input password -> UNLOCK_SOURCE_MISSING.
3. Build keepass DatabaseKey from password + optional keyfile.
4. Attempt decryption.
     - Failure -> AUTH_FAILED, vault stays Locked.
     - Success -> transition to Unlocked, populate state, start idle timer.
5. Return success.
```

Windows is out of scope for v0.1. Detect and exit cleanly with a clear message.

## Lock sequence

```
1. Either kdbx_lock, idle timer, or SIGTERM/SIGINT.
2. Capture lock_reason and pending_discarded count.
3. Zero the master key.
4. Drop the parsed databases (Rust drop semantics).
5. Discard pending stage.
6. Stop the idle timer.
7. Transition to Locked.
8. Append audit log entry.
9. If kdbx_lock tool: return { locked: true, pending_discarded: N }.
```

## Pending changes on lock

**Discard on any lock transition.** The next tool call after an idle-lock returns a VAULT_LOCKED error including the discarded changes summary so the agent can re-stage if appropriate:

```json
{
  "error": {
    "code": "VAULT_LOCKED",
    "details": {
      "lock_reason": "idle_timeout",
      "pending_discarded_count": 2,
      "pending_discarded_summary": [
        { "kind": "add_entry", "title": "MyNewService" },
        { "kind": "update_field", "path": "/Web/Banking/MyBank", "field_name": "URL" }
      ]
    }
  }
}
```

## External-modification detection

```
At unlock:    capture vault_file.mtime as file_mtime_at_unlock
At save:      re-stat the file, compare to stored mtime
              If now > file_mtime_at_unlock + 1s:
                refuse with VAULT_FILE_MODIFIED
              Else:
                write atomically (temp + fsync + rename + fsync_dir)
                update file_mtime_at_unlock to new mtime
```

## Idle timer mechanics

Periodic check (interval = idle_timeout / 10, min 5s, max 60s) of `now - last_activity`. Any tool call in Unlocked state updates `last_activity`, including `kdbx_status` (legitimate keep-alive).

---

# Section 3: Tool semantics

## Path resolution algorithm

```
1. Reject if path doesn't start with "/".
2. Split on "/" (respecting backslash escapes).
3. Discard empty leading segment.
4. Walk segments left-to-right from root.
5. For each non-final segment: must resolve to a Group.
6. Final segment: resolves to a Group (if path ends with "/") or an Entry.
7. Match by exact name (case-sensitive, Unicode-NFC-normalized).
8. ":N" ordinal disambiguates collisions (1-based, KDBX iteration order).
9. Return handle, or NOT_FOUND error.
```

## Working-copy model

The stage exists as an in-memory shadow database, not as a list of operations.

```
At unlock:
  canonical_db = parse(decrypt(vault_bytes))
  working_db   = clone(canonical_db)

Read tools query against working_db.
Write tools mutate working_db in place; canonical_db is untouched.

kdbx_diff_pending: diff-kdbx semantic-diff(canonical_db, working_db).
kdbx_save_pending: serialize working_db, atomic-write,
                   canonical_db = clone(working_db).
kdbx_discard_pending: working_db = clone(canonical_db).

At lock: drop both databases.
```

Two pleasant properties:
1. No separate stage data structure. The stage is `diff(canonical, working)`. diff-kdbx already knows how to compute this.
2. Reads see writes immediately. After `kdbx_add_entry`, the next `kdbx_list_entries` includes the new entry.

Memory cost: 2x the parsed database. Negligible for typical KDBX vaults.

## Field semantics

**Standard fields** (KDBX-canonical): `Title`, `UserName`, `Password` (default protected), `URL`, `Notes`.
**Custom fields:** arbitrary user-defined with explicit `protected` flag.

Protection is a per-field flag on every field, standard or custom. Any standard field can be marked protected (KeePassXC's per-attribute "Protect" toggle; KeePass 2's "protect in memory" option for UserName, URL, Notes). Read views and search honor the stored flag, never the field name: a protected value is withheld from metadata and reachable only through a reveal tool. Title is the one exception (see the implementation notes).

`kdbx_update_field` rules:
- Standard or custom field names accepted.
- `value` required; empty string allowed (clears the field).
- `protected` optional; if omitted, preserves existing protection state.
- Updating Password to empty string is allowed (regenerate workflows).

Field name validation:
- Length 1..256
- No ASCII control characters (< 0x20)
- No leading/trailing whitespace
- Unicode and spaces in middle accepted

Returns `FIELD_NAME_INVALID` on rejection.

## Entry title validation

- Length 1..4096
- No ASCII control characters
- Unicode, spaces, and (escaped) slashes accepted

Returns `ENTRY_TITLE_INVALID` on rejection.

## Search semantics

`kdbx_find_entry`:
- Lowercase via Unicode case folding (not ASCII-only).
- Substring match against the configured field-list (default: title, username, url).
- A protected field is never compared (Title excepted, since it is visible metadata), so search is not an oracle on protected values.
- Stable sort by `(group_path, title)`.
- Cap at 100 results; set `truncated: true` if more match.
- Plain substring only. No regex, no boolean operators, no globs.

## TOTP semantics

`kdbx_get_otp`:
1. Resolve entry by path.
2. Look for OTP source: modern `otp` field with `otpauth://` URI, fallback to legacy `TOTP Seed` + `TOTP Settings`.
3. Compute TOTP at requested time (default: now).
4. Return `{ code, valid_for_seconds, period_seconds }`.

The TOTP secret never crosses the MCP boundary. Only the current code is exposed.

## Attachment semantics

KDBX deduplicates attachments at the database level. Entries reference attachments by ID; the same attachment can appear under multiple entries.

`kdbx_add_entry` with attachments: decode base64, compute SHA-256, insert into database (let keepass-rs handle dedup), link to entry under the input-provided name.

`kdbx_download_attachment`: resolve entry, find attachment by name, fetch bytes, return `{ name, size_bytes, sha256, base64 }`. No hard size cap (KDBX is unlimited; we accept what KDBX accepts). Sizes above 10MB get a `warn` log entry but are not rejected.

## Save atomicity

```
1. Stat vault file. mtime check; refuse if conflict.
2. Serialize working_db to encrypted bytes (in memory).
3. Write to temp file: $vault_path.tmp.$pid.$rand
4. fsync(temp)
5. Atomic rename: temp -> vault_path
6. fsync(parent dir)                              # POSIX durability
7. Re-stat; capture new mtime.
8. canonical_db = clone(working_db).
9. Update file_mtime_at_unlock.
10. Return { saved: true, num_changes, written_at }.
```

If steps 4-7 fail: temp file unlinked, no changes to vault, working_db preserved. Return `WRITE_FAILED`.

---

# Section 4: Stage/commit workflow

## kdbx_diff_pending output

```json
{
  "ok": true,
  "data": {
    "added": [{ "path", "uuid", "title", "group_path", "field_count", "has_attachments", "has_otp" }],
    "modified": [{
      "path", "uuid", "title",
      "field_changes": [
        { "field_name", "before", "after", "protected": false } |
        { "field_name", "changed": true, "protected": true }
      ],
      "attachment_changes": [{ "name", "change": "added" | "removed" | "modified" }]
    }],
    "removed": [],
    "summary": { "num_added", "num_modified", "num_removed" }
  }
}
```

**Protected-field redaction:** for `protected: true` fields, `before` and `after` are NOT included; only `{ field_name, changed: true, protected: true }`. Bulk diff queries don't reveal secrets even when secrets have changed.

**Stable ordering:** entries within each list sorted by `(group_path, title)`.

**No-op state:** empty arrays + zero summary; not an error.

## kdbx_save_pending flow

Pre-conditions: vault unlocked, `KDBX_ALLOW_WRITES=true`, at least one pending change.

Steps as in Section 3 (save atomicity). On any failure: stage preserved, specific error code surfaces failure mode.

## VAULT_FILE_MODIFIED recovery

```json
{
  "error": {
    "code": "VAULT_FILE_MODIFIED",
    "details": {
      "file_mtime_at_unlock": "2026-05-08T10:00:00Z",
      "file_mtime_now": "2026-05-08T10:15:30Z",
      "pending_changes": 3
    }
  }
}
```

Recovery options for the agent:
1. Discard pending and re-unlock (lose staged changes; re-read disk).
2. No `force: true` in v0.1 (locked decision).
3. Manual merge (out of scope; user exits to KeePassXC).

## kdbx_discard_pending flow

```
1. count = number of staged changes.
2. working_db = clone(canonical_db).
3. Append audit log entry.
4. Return { discarded: true, num_dropped: count }.
```

Discarding when there are no pending changes is a no-op success.

## Stage size

No explicit cap. Memory cost is 2x parsed database. Documented limitation for pathologically large vaults (1GB+ with attachments).

## Stage on lock

Per Section 2: idle-lock and manual lock both discard stage. The next tool call's VAULT_LOCKED error includes the discarded summary.

## Edge cases catalog

| Case | Behavior |
|---|---|
| Save with no changes | NO_PENDING_CHANGES |
| Discard with no changes | Success, num_dropped: 0 |
| Save with vault file deleted externally | WRITE_FAILED |
| Save with disk full | WRITE_FAILED (stage preserved) |
| Multiple writes to same field | Last value wins |
| Stage references nonexistent group | Error at tool-call time |
| Concurrent mcp-kdbx instances | First save wins; second VAULT_FILE_MODIFIED |
| Save then immediate diff_pending | Empty diff |
| Discard then immediate diff_pending | Empty diff |
| Process killed mid-save | Temp file orphan; cleaned on next startup if `KDBX_AUTO_CLEAN_ORPHANS=true` |

---

# Section 5: Configuration

## Source

Environment variables only in v0.1. No CLI flags, no config file. Reasons:

1. MCP host config friendliness (most hosts inject env vars per JSON config).
2. Avoid precedence ambiguity (single source = no precedence rules).
3. Future extensibility (config files can be added later via wrapper scripts).

## Validation rules

Stricter than typical env-var parsing. The full table is in Section 2's configuration surface; key rules:

- `KDBX_ALLOW_WRITES` MUST be exactly `"true"` (case-sensitive, no whitespace) or unset. Other values like `"yes"`, `"1"`, `"TRUE"` are rejected with exit(1). Strict matching prevents silent disabling of write enablement.
- `KDBX_AUTO_CLEAN_ORPHANS` follows the same strict rule.
- Integer values: parse as integer with explicit range; reject malformed.
- Required paths: resolved absolute, existence + readability checked at startup.

Validation failures: `exit(1)` with differentiated stderr messages (no different exit codes; differentiation is in the message).

## Defaults rationale

| Default | Why |
|---|---|
| `IDLE_TIMEOUT_SECONDS=900` (15 min) | Matches 1Password CLI session feel. |
| `ALLOW_WRITES` off | Conservative read-only by default. |
| `UNLOCK_CMD_TIMEOUT_SECONDS=30` | Generous for typical secret-manager round trips. |
| `AUTO_CLEAN_ORPHANS` off | Filesystem hygiene varies; opinionated. |
| `LOG_LEVEL=info` | Captures lifecycle and reveal events. |

## Introspection via kdbx_status

Returns operationally relevant config (vault_name, vault_path, locked, writes_allowed, idle_timeout, log_level, server_version, keepass_rs_version, has_pending_changes). **Excludes** `KDBX_PASSWORD`, `KDBX_UNLOCK_CMD`, `KDBX_KEYFILE_PATH` (server never echoes secrets or their sources).

## Mid-session change behavior

Most env vars read once at startup. Change config -> restart server.

| Variable | Reread? |
|---|---|
| `KDBX_VAULT_PATH`, `KDBX_ALLOW_WRITES`, `KDBX_IDLE_TIMEOUT_SECONDS`, `KDBX_LOG_LEVEL`, etc. | No |
| `KDBX_PASSWORD`, `KDBX_UNLOCK_CMD` | **Yes**, on each unlock attempt |

The split: operationally-fixed config is restart-only; password sources are cycle-able to support secret rotation.

## .env file support

Deferred for v0.1. Wrapper script suffices:

```bash
#!/bin/sh
set -a
. /path/to/.env
set +a
exec mcp-kdbx
```

This pattern composes with any existing dotenv tooling and keeps mcp-kdbx itself dotenv-agnostic.

---

# Section 6: Audit trail

## Format

JSON-lines (JSONL): one JSON object per line, UTF-8. No human-readable text mode for v0.1.

## Destinations

| Setting | Target |
|---|---|
| `KDBX_LOG_FILE` unset | stderr only |
| `KDBX_LOG_FILE=/path/to/log` | Append to file AND emit to stderr |

No log rotation in v0.1 (use `logrotate` or similar externally).

## Log levels

| Level | Used for |
|---|---|
| `error` | WRITE_FAILED, AUTH_FAILED with cmd-exit details, internal panics |
| `warn` | Idle-timer firing late, file mtime drift, KDBX_UNLOCK_CMD timeout, quota |
| `info` | Lifecycle and reveal events. **Default.** |
| `debug` | Tool-entry/exit logs with parameters and timing |
| `trace` | Protocol-level: full JSON-RPC payloads. **MAY contain sensitive data; explicit opt-in.** |

## Event envelope

```json
{
  "timestamp": "2026-05-08T10:00:00Z",   // ISO 8601 UTC
  "level": "info",
  "event": "vault_unlocked",
  "pid": 12345,
  "details": { /* event-specific */ }
}
```

## Logged events

| Event | Level | Details |
|---|---|---|
| `server_started` | info | server_version, vault_path, writes_allowed, idle_timeout_seconds |
| `vault_unlocked` | info | unlock_source ("input" \| "env" \| "cmd"), file_mtime |
| `vault_locked` | info | reason, pending_discarded_count |
| `auth_failed` | error | source, error_code |
| `write_staged` | info | tool, target_path, target_uuid, field_name (if applicable) |
| `stage_discarded` | info | reason, num_dropped, summary (paths only) |
| `save_committed` | info | num_changes, before_mtime, after_mtime |
| `save_refused` | warn | before_mtime, conflict_mtime, pending_changes |
| `save_failed` | error | failure_step, error_message, pending_changes |
| `reveal_password` | info | target_path, target_uuid, sha256 |
| `reveal_protected` | info | target_path, target_uuid, field_name, sha256 |
| `download_attachment` | info | target_path, target_uuid, attachment_name, size_bytes, sha256 |
| `get_otp` | info | target_path, target_uuid (no code logged) |
| `unlock_failed` | warn | unlock_source, reason (added 2026-10-18: `VAULT_UNREADABLE`) |
| `writer_lock_unavailable` | warn | reason (added 2026-10-18: save without the writer lock) |
| `tool_call` | debug | tool, params (sensitive fields redacted), duration_ms, error_code |
| `mcp_message` | trace | direction, full JSON-RPC payload |

## Privacy invariants

These are non-negotiable:

- **Never log plaintext values.** No password, no protected field, no OTP code, no attachment bytes ever appears in any log entry except at `trace` level.
- **Reveal events log SHA-256 hash, not value.** Hash computed as `sha256("kdbx-reveal-v1\0" || value)` for domain-separation against rainbow-table attacks.
- **Path segments and field names ARE logged.** They're metadata, not secrets. Users with paranoid threat models can disable info-level logging by setting `KDBX_LOG_LEVEL=warn`.
- **Master password and unlock-command output never appear anywhere.** Specifically scrubbed in `mcp_message` capture (`password` parameter replaced with `"<redacted>"`).
- **`KDBX_PASSWORD` env var is not logged.** `server_started` event captures vault_path and idle_timeout_seconds but no env-var-derived secrets.

## Operational uses

- Audit reveal events: `grep '"event":"reveal_' log`
- Forensics: hash-match log against known sensitive entries
- Debug VAULT_LOCKED reasons: combine `vault_locked` events with idle_timeout
- Compliance reports: trivially convert JSONL to whatever ingest format

---

# Section 7: Threat model

## Trust boundaries

mcp-kdbx **trusts**:
- Local OS (filesystem, process isolation, memory)
- The MCP host process (Claude Desktop, etc.)
- The keepass-rs library and dependencies
- The user's filesystem layout

mcp-kdbx **does NOT trust**:
- Tool-call inputs from the agent (paths, field names, UUIDs validated)
- The vault file's mtime across save (mtime check before write)
- `KDBX_UNLOCK_CMD` output (timeout-bounded; fails closed on non-zero exit)
- The network: there is no network surface in v0.1 (stdio only)

## Threats addressed by design

### Adversarial agent (primary threat)

A misbehaving or hostile LLM agent. Defenses:

- **Bulk reads metadata-only.** `kdbx_list_entries`, `kdbx_get_entry`, `kdbx_find_entry`, `kdbx_list_attachments` never include protected values, attachment bytes, or OTP codes.
- **Per-call consent-gated reveals.** Each `kdbx_reveal_*` and `kdbx_download_attachment` is a separate audited event. The MCP host can show a confirm UI per call.
- **Minimal write surface.** No delete or move tools. Writes require `KDBX_ALLOW_WRITES=true`. Stage-then-commit pattern allows review before disk write.
- **Audit log of every reveal and write.** sha256-hashed values let the user verify access without storing secrets.

### External vault modification

mtime check refuses save with VAULT_FILE_MODIFIED.

### Concurrent mcp-kdbx instances

First save wins; second's mtime check fires.

### Path injection

In-memory tree-walk, not filesystem traversal. `/../../../../etc/passwd` -> GROUP_NOT_FOUND.

### Idle exposure

15-minute default idle-lock zeroes the master key.

## Threats partially addressed

### Process memory dump

While unlocked, master key + decrypted vault live in Rust heap.

| Defense | Status |
|---|---|
| Zero key on lock | Yes (explicit overwrite) |
| Drop parsed DB on lock | Yes (Rust drop; freed memory not actively zeroed) |
| `mlock` to prevent swap | **No** (deferred; would require `cap_ipc_lock` or root) |
| Hardware enclave | No |

If your threat model includes "attacker can dump my process memory or read swap," mcp-kdbx is not the right tool.

### Audit log tampering

Plaintext file on disk; an attacker with write access can rewrite history.

| Defense | Status |
|---|---|
| File permissions guidance (0600) | Documented |
| Append-only signed chain | **No** (deferred) |
| Remote append-only sink | Document workaround (syslog, journald) |

### Configuration via env

`KDBX_PASSWORD` in process env is readable via `/proc/$pid/environ` on Linux. **Defense: prefer `KDBX_UNLOCK_CMD`.**

## Threats NOT addressed

- **Compromised MCP host.** If the host is compromised, attacker has same access as user.
- **Cryptographic side channels.** Delegated to keepass-rs.
- **Denial-of-service.** No rate limiting in v0.1.
- **Hardware attacks.** Out of scope for any software-only tool.
- **Browser-side threats.** Not applicable (mcp-kdbx is a server, not a browser app).

## Recommended posture for cautious users

1. Use `KDBX_UNLOCK_CMD` instead of `KDBX_PASSWORD` (avoid env-leak)
2. Set `KDBX_LOG_FILE` to a private path with 0600 permissions
3. Set `KDBX_IDLE_TIMEOUT_SECONDS=300` (5 min) for paranoid; default 900 for typical
4. Leave `KDBX_ALLOW_WRITES` unset unless writes are needed
5. Run mcp-kdbx in a per-vault MCP host config
6. Periodically grep the audit log for unexpected reveal events

---

# Section 8: Testing strategy

## Test layers

| Layer | What | Speed | Focus |
|---|---|---|---|
| Layer 1 | Rust unit tests (`cargo test --lib`) | < 5s | Pure functions: path resolution, validation, search, TOTP, error formatting |
| Layer 2 | Integration tests against KDBX fixtures | ~ 10s | State machine: open, mutate, save, lock, reopen |
| Layer 3 | MCP protocol conformance | ~ 30s | Spawn binary, communicate via stdio JSON-RPC, exercise tool surface |
| Layer 4 | Manual cross-MCP-host smoke | manual | Real Claude Desktop, Claude Code, Cursor |

## Layer 1 coverage

In `src/*.rs` `#[cfg(test)] mod test {}`:

- Path resolution: backslash escape, `:N` ordinal, error codes
- Field/title validation: empty, control-char, Unicode
- Search: case-insensitive, field filter, cap-and-truncate, sort
- TOTP: known-vector tests
- Error formatting: every error code maps to structured response

No real KDBX files needed.

## Layer 2 coverage

In `tests/integration/*.rs`:

1. Copy fixture KDBX to temp dir
2. Start in-process server
3. Exercise tool surface
4. Assert outcomes

Fixture set in `tests/fixtures/`:

| Fixture | Contents |
|---|---|
| `empty.kdbx` | Zero entries |
| `flat.kdbx` | 5 entries in root |
| `nested.kdbx` | 3 levels of group nesting |
| `with_attachments.kdbx` | 2 entries + 1 attachment each |
| `with_otp.kdbx` | 1 entry with TOTP URI |
| `duplicates.kdbx` | 2 entries with same title in same group |

Password for all fixtures: `test-password-do-not-use` (matches web-kdbx and diff-kdbx).

Coverage: every tool, success and error paths, idle-lock, audit-log appending, VAULT_FILE_MODIFIED conflict.

## Layer 3 coverage

Rust integration test using `tokio::process::Command`:

- Spawn `mcp-kdbx` binary
- Communicate via JSON-RPC over stdin/stdout
- Verify `tools/list` schemas match Section 1
- Exercise every tool's happy-path response shape
- Trigger every error code in the enumeration
- Round-trip serialization (non-ASCII strings, base64 binary, integer ranges)

This layer catches wire-format drift invisible to unit tests.

## Layer 4 manual smoke

Per-release checklist in `docs/manual-testing.md`:
- Claude Desktop: configure mcp-kdbx, exercise unlock/list/reveal/save/lock
- Claude Code: same
- Cursor: same (if available)
- mcp-cli or similar: same

## Test fixture management

Generate via `gen-fixtures` binary in `[[bin]]` table, gated by `cli` feature (matches diff-kdbx, web-kdbx convention). Fixed UUIDs and timestamps where keepass allows for byte-stability. `MANIFEST.md` documents each fixture's contents; Layer 2 tests assert against observed contents to catch manifest drift.

## CI gates

```yaml
jobs:
  rust-test:                                  # Layer 1 + Layer 2
    - cargo test --all-features
    - cargo clippy --all-targets -- -D warnings
    - cargo fmt --check
  protocol-conformance:                       # Layer 3
    - cargo test --test protocol_conformance
  audit:
    - bash scripts/ci-audit.sh                # path traversal, log redaction, env-var policy
```

## Property tests (deferred to v0.2)

`proptest` integrations for:
- Path round-trip: `parse(format(path)) == path`
- Save round-trip: `open(save_to_bytes(open(bytes))) == open(bytes)`
- Search relevance: matched entries contain query

Roughly 100 LOC of setup buys substantial coverage in v0.2.

## Coverage targets for v0.1

| Area | Target |
|---|---|
| Path resolution | Every branch |
| Tool handlers | Every tool: 1+ happy-path + 1+ error-path |
| Auth/lifecycle | Each unlock source, each lock cause |
| Stage/commit | Success and conflict paths |
| Audit log | Every event type emitted |
| Error codes | Every code in enumeration triggered |
| Cryptography | Out of scope (delegated) |

---

# Out of scope (v0.1)

These are explicitly NOT in v0.1. Each is a known and intentional gap; revisit per v0.2 demand.

| Out-of-scope item | Reason |
|---|---|
| HTTP/SSE transport | stdio is sufficient for the dominant deployment shape (MCP host as parent process). HTTP adds auth surface (bearer, mTLS) and lifecycle complexity. |
| Multi-vault support | One mcp-kdbx instance per vault. Aggregation is a higher-layer concern. |
| Delete/move/rename tools | Writes are read+limited (add_entry, update_field). Destructive ops require manual KeePassXC for v0.1. |
| Force-overwrite on save conflict | `kdbx_save_pending(force: true)` is dangerous without merge support. v0.1 says "discard your stage, re-read, redo." |
| Snapshot-based diff | `kdbx_diff_since(timestamp)` requires snapshot storage. v0.1 has only canonical-vs-working diff. |
| `mlock` memory pinning | Capability requirements; minimal user benefit relative to complexity. |
| Tamper-evident audit log | Append-only signed chain is its own design problem. |
| Rate limiting on save | Premature; no observed need. |
| `KDBX_PARANOID=true` shorthand | Document the recipe instead. |
| Property tests | Infrastructure for v0.2. |
| Built-in `.env` support | Wrapper script suffices. |
| Windows support | POSIX-shell `/bin/sh` assumed for `KDBX_UNLOCK_CMD`. |
| Cross-tool ecosystem integration with web-kdbx | Both projects need to mature first. |

# Future work (v0.2 directions)

| Direction | Trigger |
|---|---|
| HTTP/SSE transport | Demand for "MCP server runs on home server, accessed via Tailscale" |
| Snapshot-based diff | Demand for "show me what changed since yesterday" |
| `mlock` support | User with high-paranoid threat model |
| Tamper-evident audit log | Compliance requirements |
| Property tests | API stabilizes; ~100 LOC of setup for substantial coverage |
| Windows support | Demand from Windows users |
| Force-overwrite with merge | Concurrent-edit demand emerges |

# References

- 2026-04-29-web-kdbx-design.md: web-kdbx L0 spec (sibling project)
- 2026-05-06-web-kdbx-l1-storage-design.md: web-kdbx L1 spec (canonical mental-model document for the URL-as-vault story)
- diff-kdbx: github.com/queelius/diff-kdbx (library dependency for stage diffing)
- keepass-rs: github.com/sseemayer/keepass-rs (substrate library)
- OmniKee: github.com/OmniKee/OmniKee (sibling KeePass-compatible app; informed the consent-gating design)
- MCP specification: https://modelcontextprotocol.io

---

# Implementation notes (v0.1, 2026-06-15)

Deviations from the design above, settled during the security-review fix batch.
These are the authoritative wire contract for v0.1; the conformance tests assert
against them.

- **Error enumeration: added `INVALID_INPUT`.** A caller-supplied value that is
  malformed in a way the listed codes do not name (specifically, an attachment
  whose base64 fails to decode in `kdbx_add_entry`) returns `INVALID_INPUT`, not
  `FIELD_NAME_INVALID` (which is reserved for a bad field name). A malformed
  per-call `keyfile_bytes`, or an unreadable configured keyfile, stays
  `AUTH_FAILED` (it is an authentication credential) and emits `auth_failed`.

- **`kdbx_add_entry`: `created_at` / `modified_at` deferred.** The optional
  timestamp inputs in the section 1 schema are not implemented for v0.1. The
  `gen-fixtures` binary, their intended consumer, sets times through the keepass
  API directly, so the tool path does not need them yet. Revisit if a real
  caller needs to set entry times.

- **`tool_call` (debug) and `mcp_message` (trace) audit events deferred.** Those
  rows of the section 6 logged-events table are not emitted in v0.1, and the
  redaction helper they would have used was removed. Payload leakage at
  debug/trace is prevented instead by capping rmcp's tracing verbosity
  (`rmcp=warn`) in `main.rs`, so `KDBX_LOG_LEVEL=debug` no longer prints raw
  JSON-RPC payloads (which contain the master password and revealed secrets).
  A redaction layer must be restored if this capture is wired later (the HTTP
  adapter is the likely place).

- **`KDBX_KEYFILE_PATH` precedence.** When both a per-call `keyfile_bytes` and a
  configured `KDBX_KEYFILE_PATH` are present, the per-call value wins (mirroring
  the password source order). When only the configured path is set, it is read
  at unlock.

- **`kdbx_status.idle_timeout_remaining_seconds`** reports the live countdown
  when unlocked (status counts as activity, so it is the full window after a
  status call), and `null` when locked or when idle lock is disabled
  (`KDBX_IDLE_TIMEOUT_SECONDS=0`).

- **Protected standard fields (security fix, 2026-10-18).** v0.1 originally
  emitted `username`, `url`, `notes`, and `notes_preview` from the raw field
  value and searched them the same way, so a UserName, URL, or Notes the user
  had marked protected leaked in plaintext through `kdbx_list_entries`,
  `kdbx_get_entry`, and `kdbx_find_entry` (and repeated `kdbx_find_entry`
  substring queries recovered it), bypassing the reveal tools and the audit
  trail. The fix, all derived from the stored per-field flag through one rule
  (`kdbx_core::visibility::metadata_value`) shared by the views and search:
  - A protected `UserName`, `URL`, or `Notes` is emitted as JSON `null` under
    its usual key (`username`, `url`, `notes` / `notes_preview`).
  - Every read view now carries `standard_field_names: { name, protected }[]`,
    listing the standard fields present on the entry in canonical order
    (Title, UserName, Password, URL, Notes). It reuses the
    `custom_field_names` record shape rather than adding per-key flags, so the
    two lists together inventory every field with its protection. A
    `protected: true` record means the value is withheld and must be read with
    `kdbx_reveal_password` (Password) or `kdbx_reveal_protected` (any other
    field, standard names included, for example `field_name: "UserName"`),
    which audits a sha256 as usual. The key is additive: unprotected values
    appear exactly as before, and `custom_field_names` is unchanged. A `null`
    value with no matching record in `standard_field_names` means the field is
    absent.
  - `kdbx_find_entry` never compares against a protected value; unprotected
    fields match as before.
  - Example, an entry whose UserName is protected and whose URL is not:
    `"username": null, "url": "https://github.com", "standard_field_names":
    [{"name": "Title", "protected": false}, {"name": "UserName", "protected":
    true}, {"name": "Password", "protected": true}, {"name": "URL",
    "protected": false}]`.
  - **Known, deliberate exception: Title.** Entries are addressed by title in
    vault paths (`/Group/Title`), and every read tool returns `path`, so a
    protected Title is visible regardless. It is still emitted under `title`
    and is still searchable; `standard_field_names` reports its true
    `protected` flag. Hiding it would require an addressing scheme that does
    not embed titles (UUID-only paths), which is out of scope for v0.1.
  - Password is still never emitted by any view, protected or not.

# Implementation notes (review fix batch, 2026-10-18)

Deviations and clarifications from the second review fix batch. Like the notes
above, these are the authoritative wire contract; the conformance and
integration tests assert them.

- **Paths never alias another record.** An entry with an empty Title used to
  format as `/Group/`, which parses as the group path `/Group`, and entry
  resolution ignored the trailing slash, so `/Group/` resolved to a different
  entry (a sibling of the group titled `Group`) and reveal or update acted on
  the wrong record. Two rules close this:
  - A record has a vault path only when every segment of that path has a
    non-empty name. An entry with an empty (or missing) Title, and any record
    under a group with an empty name, has no path: read views, the stage diff
    (`path`, `group_path`), `kdbx_update_field`, and audit `target_path`
    report `null` for it. The path grammar has no spelling for an empty name,
    so the alternative (emitting a placeholder) would always alias something.
    Every path the server emits parses and resolves back to the record it was
    built from (a unit test asserts this over awkward titles).
  - Entry tools refuse a group-shaped path. A path ending in `/` (including
    the root `/`) always addresses a group, so entry resolution returns
    `ENTRY_NOT_FOUND` for it instead of matching an entry. Group tools still
    accept `/Web` and `/Web/` alike.
- **UUID addressing for entry tools.** `kdbx_get_entry`,
  `kdbx_list_attachments`, `kdbx_reveal_password`, `kdbx_reveal_protected`,
  `kdbx_download_attachment`, `kdbx_get_otp`, and `kdbx_update_field` accept an
  optional `uuid` (the record UUID every read view returns) alongside their
  path parameter (`path`, or `entry_path` for the two attachment tools), which
  is now optional too. Exactly one of the two must be given: both, or neither,
  or a malformed uuid is `INVALID_INPUT`; a well-formed uuid that names no
  entry is `ENTRY_NOT_FOUND`. This is how an agent reaches a record with no
  path, and it is the cross-session-stable way to name any entry.
  `kdbx_update_field` now also returns the entry's `uuid`, and its `path` is
  the canonical path of the entry written (re-derived after the write).
- **Discard summaries.** `pending_discarded_summary` (on `VAULT_LOCKED`) and the
  `stage_discarded` audit `summary` list each staged entry's vault path, or its
  UUID when it has no path. A path always starts with `/`; a UUID never does.
- **Save conflict detection is by content, under a writer lock.** The mtime
  heuristic in section 2 ("External-modification detection") and section 3
  ("Save atomicity", step 1) is replaced. It missed an external write that
  kept or backdated the mtime (restore and sync tools do this) and any write
  landing within its one-second slack, including a second mcp-kdbx saving in
  the same second; each was then silently clobbered. Now:
  - At unlock the vault is read through one handle; the server records the
    sha256 of exactly those bytes and the mtime from that handle's metadata.
  - `kdbx_save_pending` serializes first (the KDF runs before any lock), then
    takes an exclusive advisory lock on a sidecar `<vault>.lock` (flock via
    `std::fs::File::try_lock`, waiting up to 5 seconds), re-reads the vault,
    and refuses with `VAULT_FILE_MODIFIED` when the content hash differs from
    the baseline, whatever the mtimes say. A touch that changes only the mtime
    is not a conflict. The lock is held through the temp write and rename, so
    two mcp-kdbx instances cannot interleave. The sidecar is never deleted.
    A new sidecar takes the vault file's permission bits (filtered by the
    umask), and a sidecar this user cannot write is opened read-only (flock
    needs no write access), so a group-shared vault stays saveable by every
    member. Both opens use `O_NOFOLLOW | O_NONBLOCK` and the descriptor must
    be a regular file: a symlink or FIFO planted at the lock path (by anyone
    able to write the vault directory) fails the save at once with
    `WRITE_FAILED`, `details.step: "lock"`, instead of redirecting the lock
    or blocking past the wait deadline. A
    lock still held after the wait is `WRITE_FAILED` with `details.step:
    "lock"`.
  - After the rename the baseline becomes the sha256 of the bytes written and
    the mtime of the written file, so a second save in the same session works.
  - `VAULT_FILE_MODIFIED.details.pending_changes` is the real count of staged
    entries (it was a 0/1 flag), and the `save_committed` audit event's
    `after_mtime` is the new file's mtime (it was the wall-clock write time).
  - `WRITE_FAILED` from a save carries `details.step`: `lock`, `reread`,
    `serialize`, `write_temp`, or `rename`.
  - Residual risk: the lock coordinates mcp-kdbx instances only. A program
    that does not take it (KeePassXC) writing between the re-read and the
    rename is not detected; that window is one temp write plus one rename.
  - The unlock KDF and the save run under `tokio::task::block_in_place`, so
    they no longer stall the async worker the idle timer shares.
  - MSRV is now 1.89 (`File::try_lock`); no new dependency.
- **`kdbx_update_field` keeps KeePass edit semantics.** A real change now
  snapshots the pre-edit entry into the entry's history and updates its
  `LastModificationTime` (keepass `edit_tracking`), as KeePass and KeePassXC
  do; before, the old value vanished from history on save and `modified_at`
  never moved. Setting a field to the value and protection it already holds is
  a no-op (no history snapshot, no pending change). History is not surfaced by
  any tool, and the stage diff ignores history growth. `kdbx_add_entry` keeps
  a plain edit: keepass stamps the new entry's creation and modification
  times, and a snapshot of the blank entry would be noise.
- **Title and field-name validation has no bypass, and rejects invisible
  characters.** Section 3's "No ASCII control characters" becomes: no Unicode
  control characters (General_Category Cc: ASCII controls, DEL, the C1
  range) and no format characters (Cf) except an explicit allow-list: the
  zero-width non-joiner and joiner (U+200C, U+200D), which Persian, Hindi,
  Malayalam, and emoji sequences need. Everything else in Cf is refused,
  including the bidi controls, zero-width space, word joiner, byte-order
  mark, tag characters, soft hyphen, and any format character a future
  Unicode version adds (an allow-list, not a list of known-bad ranges). This
  applies to titles and field names; the
  error details carry the offending `code_point` (for example `"U+202E"`).
  Every write to `Title` is validated as a title: `kdbx_update_field` with
  `field_name: "Title"` (an empty or disallowed-character title is
  `ENTRY_TITLE_INVALID`), and a `Title` key in `kdbx_add_entry`'s `fields`
  map is refused with `FIELD_NAME_INVALID` (the `title` parameter is the one
  way to set it).
- **`kdbx_get_otp.time_unix` is clamped.** Section 1 let the caller pick any
  evaluation time, which contradicts section 3's "only the current code is
  exposed": an agent could harvest codes for any future step. The requested
  time is now clamped to now plus or minus one TOTP period (so the previous,
  current, or next code, for clock skew), the response gains `time_unix` (the
  time actually used), and the `get_otp` audit event records
  `requested_time_unix` (null when omitted) and the effective `time_unix`.
- **A symlinked vault stays a symlink.** The save resolves the configured
  `KDBX_VAULT_PATH` through any symlinks and writes the temp file, takes the
  writer lock, re-reads, and renames next to the real file. Before, the rename
  replaced the link itself with a regular file, detaching the vault from the
  file the link pointed at. `KDBX_AUTO_CLEAN_ORPHANS` scans the resolved
  file's directory for the same reason. `kdbx_status.vault_path` still reports
  the configured path.
- **Save temp files are owner-only from creation, and orphan cleanup is
  strict.** The temp file (`<vault>.tmp.<pid>.<nonce>`, both decimal) is
  created with mode 0600 (it was umask-default until a later chmod, briefly
  world-readable). One `TempName` type formats the name for the writer and
  parses it for `KDBX_AUTO_CLEAN_ORPHANS`, which now removes only names with
  two decimal parts, so a user file like `vault.kdbx.tmp.old.bak` is never
  deleted.
- **Secret hygiene.** Every secret-bearing field is a `Secret<T>`
  (`kdbx_core::secret`): `Debug` prints `<redacted>`, the value is zeroized on
  drop, and reading it takes an explicit `expose()`. This covers `Config`'s
  password and unlock command, `kdbx_unlock`'s inputs, `kdbx_add_entry` and
  `kdbx_update_field` values and attachment content, the staged
  `FieldInput`/`AttachmentInput`, and the TOTP secret and computed code. Tool
  input schemas are unchanged (the wrapper's schema is the inner type's). The
  CI audit's check D is structural: any struct deriving `Debug` with a
  secret-named field (`password`, `unlock_cmd`, `keyfile_bytes`, `secret`,
  `value`, `base64`, `bytes`, `code`) holding a raw `String` or `Vec<u8>`
  fails. The `KDBX_UNLOCK_CMD` stdout and stderr buffers are zeroized, and the
  output is decoded as strict UTF-8: non-UTF-8 output is `AUTH_FAILED` with
  `details.reason: "unlock_cmd_output_not_utf8"` (a lossy decode used to
  substitute U+FFFD and try a password the command never printed).
- **A lock's discard summary is never lost.** Section 2 attaches the summary
  to the first `VAULT_LOCKED` after a lock, but an agent's first call after an
  idle lock is often `kdbx_unlock`, which used to clear it silently. Now
  `kdbx_unlock`'s output gains `previous_lock` (the summary, consumed, or
  `null`), and `kdbx_status` gains `last_lock` (the same object, peeked and
  not consumed; `null` once reported). All three reports share one shape:
  `{ lock_reason, pending_discarded_count, pending_discarded_summary }`. A
  failed unlock leaves the summary in place.
- **Error codes: `PATH_INVALID` and `VAULT_UNREADABLE`.** A malformed path
  (no leading `/`, `//`, a dangling `\`, `:0`) returned `GROUP_NOT_FOUND`,
  even from entry tools; it is now `PATH_INVALID`, and the not-found codes
  mean a well-formed path matched nothing. Every `Database::open` failure was
  `AUTH_FAILED`; failures found before any key is derived or checked are now
  `VAULT_UNREADABLE` with `details.reason`: `not_kdbx` (no KeePass
  signature), `unsupported_version` (KeePass 2 pre-release or an unknown KDBX
  major version), `truncated` (shorter than the version header), or
  `corrupt_header` (the outer header does not parse or fails its sha256
  check). Naming these reveals nothing about the password. A wrong key, and
  every failure that can only arise after decryption with some key (a block
  HMAC or XML error), stays `AUTH_FAILED`. `VAULT_UNREADABLE` emits no
  `auth_failed` event; it emits a warn-level `unlock_failed` event with
  `unlock_source` and the `reason`.
- **`kdbx_find_entry.fields` is a closed enum.** Unknown names (and wrong
  case, such as `"Title"`) used to be dropped silently, so a typo quietly
  reverted to the default field set. The input is now typed: the schema lists
  `title`, `username`, `url`, `notes`, and any other value is refused at the
  protocol level as invalid params (JSON-RPC error -32602, "unknown variant"),
  before the tool runs. An omitted or empty list still means the default set.
- **TOTP sources.** One resolver, `totp::resolve_for_entry`, decides an
  entry's TOTP config for `kdbx_get_otp`, `has_otp` in the read views, and
  `has_otp` in the stage diff (three hand-copied lookups before). It tries, in
  order: the `otp` field (otpauth URI); KeePass 2's native `TimeOtp-*` fields
  (KeePass 2.47+, documented under "Placeholders", `{TIMEOTP}`): exactly one
  of `TimeOtp-Secret` (UTF-8), `-Hex`, `-Base32`, `-Base64`, plus optional
  `TimeOtp-Length` (default 6, at most 8), `TimeOtp-Period` (default 30), and
  `TimeOtp-Algorithm` (`HMAC-SHA-1` default, `HMAC-SHA-256`, `HMAC-SHA-512`);
  then the legacy `TOTP Seed` + `TOTP Settings` pair. A malformed source falls
  through to the next. Base32 secrets are normalized before decoding
  (whitespace removed, uppercased, `=` padding dropped), so lowercase, grouped,
  or padded secrets now work.
- **Agent guidance.** The server instructions (sent at initialize) now state
  the path grammar once: leading `/`, `\/` and `\\` escapes, `\:` before
  digits, `:N` ordinals, a trailing `/` naming a group, and uuid addressing
  for stable references or null paths. The `PATH_INVALID` message repeats the
  grammar for hosts that do not surface instructions. `kdbx_unlock`'s
  description no longer invites the agent to collect the master password: it
  says to call the tool with no arguments (the server reads `KDBX_PASSWORD` or
  `KDBX_UNLOCK_CMD`) and not to ask the user to type the password into the
  chat; the `password` argument is documented as for scripted use.
- **Typed audit fields (format unchanged).** One ordered `Level` enum serves
  both the audit envelope and `KDBX_LOG_LEVEL` (the derived order is the
  verbosity order, replacing a string-keyed rank with a silent `info`
  fallback). `unlock_source` and `source` are an `UnlockSource`, `reason` on
  `vault_locked` and in lock reports is a `LockReason`, `tool` a `WriteTool`,
  `stage_discarded.reason` a `StageDiscardReason`, `error_code` an
  `ErrorCode`, and `failure_step` a `SaveStep`, all serialized through serde
  to the same strings as before; a unit test pins the exact JSONL line of
  every event. The one value change: `save_failed.failure_step` now names the
  real step (`lock`, `reread`, `serialize`, `write_temp`, `rename`) instead of
  always `"write"`. Two value shapes widened earlier in this batch and are
  pinned too: `target_path` (on `write_staged`, the reveal events,
  `download_attachment`, and `get_otp`) is `null` for a record with no
  addressable path, and `stage_discarded.summary` (like
  `pending_discarded_summary`) lists a UUID instead of a path for such a
  record. `download_attachment` also carries `target_uuid`, and `get_otp`
  carries `requested_time_unix` and `time_unix`.
- **History is kept in KeePass order and within the vault's limits.**
  keepass 0.12's `History::add_entry` (used by `edit_tracking`) inserts each
  new snapshot at index 0, while its XML parse and write keep file order and
  KeePass writes history oldest first; it also never applies
  `HistoryMaxItems` / `HistoryMaxSize`. After every tracked edit the server
  moves the new snapshot to the end (oldest first) and applies KeePass's
  `MaintainBackups`: remove the oldest backup (smallest LastModificationTime,
  first on a tie) while there are more than `HistoryMaxItems`, then while
  their total size exceeds `HistoryMaxSize`. Negative means unlimited; unset
  means KeePass's defaults (10 items, 6 MiB). Size is field bytes plus
  attachment bytes, an approximation of KeePass's `PwEntry.GetSize`.
  Binaries used only by a removed backup stay in the binary pool until
  KeePass next saves.
- **A filesystem without locks degrades, audibly.** If the writer lock fails
  because the filesystem cannot lock at all (`ENOLCK`, for example NFS
  without a lock daemon, or an "unsupported" error from some FUSE and SMB
  mounts), the save proceeds without the inter-instance lock (the content
  check still runs) and a successful save emits a new warn-level audit event,
  `writer_lock_unavailable`, with `reason`: `no_locks` or `unsupported`. Any
  other lock error stays `WRITE_FAILED` (`details.step: "lock"`).
- **UUID addressing for group tools.** `kdbx_list_entries` (`group_path` or
  `uuid`), `kdbx_list_groups` (`parent_path` or `uuid`; with neither, the
  root), and `kdbx_add_entry` (`group_path` or `group_uuid`, named so it
  cannot be mistaken for the new entry's uuid) take a group by path or by
  record UUID under the same exactly-one rule as entry tools: both, neither
  (except `kdbx_list_groups`), or a malformed uuid is `INVALID_INPUT`; an
  unknown uuid is `GROUP_NOT_FOUND`. A group under an unnamed group, whose
  path is null, is reachable this way.
