# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`mcp-kdbx`: a Model Context Protocol server for KeePass KDBX vaults, written in Rust. Spawned by an MCP host (Claude Desktop, Claude Code, Cursor) as a child process; communicates over stdio JSON-RPC. Exposes 17 tools across four categories (lifecycle, read, reveal, write). Bridge member of the `*-kdbx` ecosystem.

User-facing summary: `README.md`. Full v0.1 design (motivation, threat model, protocol surface, auth, semantics, audit trail, threat model, testing): `docs/superpowers/specs/2026-05-08-mcp-kdbx-design.md`.

## Status

**Phases 1 and 2 complete (the whole `kdbx_core` layer), on branch `feat/v0.1`, not yet merged or pushed.**

The v0.1 implementation plan landed at `docs/superpowers/plans/2026-05-09-mcp-kdbx-v0.1.md` (26 tasks, 5 phases). 165 unit tests pass; `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` are clean.

Phase 1 (tasks 1 to 9), the foundation: `error`, `config`, `audit`, `totp`, `path`, `search`, `unlock`, `vault`, plus `Cargo.toml` and a binary version stub.

Phase 2 (tasks 10, 12, 13), stage-then-commit: `stage` (working-copy writes, the diff-kdbx stage diff with protected-field redaction, and the atomic save) and `orphan` (startup temp-file cleanup). `diff-kdbx` is wired in as a path dependency. `path` gained the inverse builders (`vault_path_to_entry`/`vault_path_to_group`/`VaultPath::parent`), and `vault` gained the save-support accessors and the idle predicate.

Task 11 (idle timer) is split deliberately: the decision logic is `Vault::should_lock(now, idle_timeout)`, a pure tested predicate. The tokio task that calls it on a timer, and cancels on lock or shutdown, is wired in Phase 3, where the server loop owns the `Vault`.

Two deviations from the plan's letter, both deliberate: the module is named `kdbx_core` (not `core`, which would shadow the std crate for unqualified paths), and the diff-kdbx dependency lands in Phase 2 (where `stage` first uses it) rather than Phase 1.

Pending:
- Phase 3 (MCP adapter and stdio transport, tasks 14 to 18): the 17 tools, the `{ ok, data } | { ok, error }` envelope, the idle-timer task, and the framework choice (`rmcp` vs hand-rolled stdio: current lean `rmcp`, since the `kdbx_core`/adapter split already isolates the coupling to `src/adapter/transport.rs`). This is where the consent-gating, KDBX_ALLOW_WRITES enforcement, and audit emission are wired to the core.
- Phase 4 (fixtures, integration and protocol-conformance tests, tasks 19 to 22).
- Phase 5 (CI gates and docs, tasks 23 to 26).

## Position in the ecosystem

| Member | Role | Relation to mcp-kdbx |
|---|---|---|
| `keepass-rs` | Substrate library | Direct dependency. Provides parsing, encryption, write API. |
| `diff-kdbx` | Sibling CLI | Library dependency for `kdbx_diff_pending` (semantic-diff between canonical and working_db). |
| `web-kdbx` | Sibling browser UI | Independent. Both consume `keepass-rs`. Different consumer (browser users vs LLM agents). |
| `hugo-kdbx`, `arkiv-kdbx`, `longecho-kdbx` | Bridges, planned | Out of scope for v0.1. |

## Key cross-repo references

- `~/github/kdbx/CLAUDE.md`: ecosystem-level conventions for all `*-kdbx` repos.
- `~/github/kdbx/web-kdbx/`: the most mature sibling. Its spec/plan pair (`2026-04-29-web-kdbx-design.md` + `2026-04-29-web-kdbx.md`, plus `2026-05-06-web-kdbx-l1-storage-design.md` + `2026-05-06-web-kdbx-l1.md`) is the canonical example of the workflow.
- `~/github/kdbx/diff-kdbx/`: the dependency that mcp-kdbx will pull in for stage diffing. Read its CLAUDE.md and spec to understand its public Rust API.
- `~/github/bugfixes/track1-issues/keepass-rs/`: local fork used for upstream contributions.

## Architectural decisions (settled in the v0.1 spec)

| Decision | Choice |
|---|---|
| Scope | Per-vault server (one mcp-kdbx instance per vault) |
| Transport | stdio JSON-RPC only (no HTTP/SSE in v0.1) |
| Auth | env-var password + optional shell-out to secret manager (`KDBX_PASSWORD` and `KDBX_UNLOCK_CMD`) |
| Idle lock TTL | 900 seconds (15 minutes) default; configurable |
| Write capability | Read + limited write (add_entry, update_field; no delete, no move). Gated by `KDBX_ALLOW_WRITES=true` at startup. |
| Stage model | In-memory shadow database; diff-kdbx-as-library computes the diff; atomic temp+rename on save |
| Audit trail | JSONL via `KDBX_LOG_FILE`; sha256 of revealed values with `kdbx-reveal-v1\0` domain separation |

## Workflow for any new feature

1. Brainstorm against the relevant existing spec, or `/brainstorm` from scratch (superpowers:brainstorming).
2. Spec lands in `docs/superpowers/specs/YYYY-MM-DD-<name>.md`.
3. Implementation plan lands in `docs/superpowers/plans/YYYY-MM-DD-<name>.md` (use checkbox `- [ ]` syntax for tracking).
4. Execute via subagent-driven development (one subagent per task; two-stage review).
5. Finish via the superpowers:finishing-a-development-branch skill.

## Invariants to preserve once code lands

These are non-negotiable from the spec; flag any change that violates them as a design-level concern, not just a code change.

- **Bulk reads never expose protected values.** `kdbx_list_entries`, `kdbx_get_entry`, `kdbx_find_entry`, `kdbx_list_attachments` return metadata only (including the `protected: bool` flag per field). Reveal requires a separate per-call event.
- **Reveal events log a sha256 of the value, never the value.** Domain prefix: `kdbx-reveal-v1\0`. Plaintext values appear in logs only at `trace` level (explicit opt-in, documented warning).
- **Master password and `KDBX_UNLOCK_CMD` output never appear in any log.** `mcp_message` capture redacts the `password` parameter on `kdbx_unlock`.
- **Writes default off.** `KDBX_ALLOW_WRITES` MUST be exactly `"true"` to enable; other values rejected at startup.
- **Stage-then-commit.** Writes mutate `working_db`; nothing hits disk until `kdbx_save_pending`. Lock (any reason) discards the stage; the next tool call returns VAULT_LOCKED with the discarded summary.
- **Save atomicity via temp+fsync+rename+fsync(parent).** No partial-file window on power loss.
- **mtime conflict refusal.** External vault modification (KeePassXC, another mcp-kdbx) refuses save with VAULT_FILE_MODIFIED.

## Voice rules for any prose written here

- Follow the soul skill (canonical list: `~/github/repos/soul/skills/soul/SKILL.md`). Key rules: no em-dashes (use commas, periods, colons, parentheses); no corporate hype phrases; direct, plain, humble.
- Conventional commits with lowercase scope: `feat(vault):`, `docs(spec):`, `ci:`, `test(integration):`, etc.
- Include `Co-Authored-By: Claude Opus 4.7 (1M context) <noreply@anthropic.com>` on AI-assisted commits.

## Test fixture convention (when fixtures land)

Fixtures use the password `test-password-do-not-use` (matches `web-kdbx` and `diff-kdbx`). Generated by a `gen-fixtures` binary in the `[[bin]]` table, gated by the `cli` feature. `tests/fixtures/MANIFEST.md` documents each fixture's contents; tests assert against observed contents to catch manifest drift.
