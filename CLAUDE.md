# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`mcp-kdbx`: a Model Context Protocol server for KeePass KDBX vaults, written in Rust. Spawned by an MCP host (Claude Desktop, Claude Code, Cursor) as a child process; communicates over stdio JSON-RPC. Exposes 17 tools across four categories (lifecycle, read, reveal, write). Bridge member of the `*-kdbx` ecosystem.

User-facing summary: `README.md`. Full v0.1 design (motivation, protocol surface, auth, semantics, audit trail, threat model, testing): `docs/superpowers/specs/2026-05-08-mcp-kdbx-design.md`.

## Status

**Phases 1, 2, and 3 complete (the full server), on branch `feat/v0.1`, not yet merged or pushed.**

The v0.1 implementation plan landed at `docs/superpowers/plans/2026-05-09-mcp-kdbx-v0.1.md` (26 tasks, 5 phases). 179 unit tests pass; `cargo fmt --check` and `cargo clippy --all-targets -- -D warnings` are clean. The server runs: all 17 tools register and respond over real stdio MCP.

Phase 1 (tasks 1 to 9), the `kdbx_core` foundation: `error`, `config`, `audit`, `totp`, `path`, `search`, `unlock`, `vault`.

Phase 2 (tasks 10, 12, 13), stage-then-commit: `stage` (working-copy writes, the diff-kdbx stage diff with protected-field redaction, the atomic save) and `orphan` (startup temp-file cleanup). `diff-kdbx` is a path dependency.

Phase 3 (tasks 14 to 18), the MCP adapter over `rmcp` 1.7.0, all in `src/adapter/`: `responses` (the `{ ok, data } | { ok, error }` text envelope), `mod` (the `KdbxServer` handler, shared state, level-filtered audit emission, the writes gate, and the idle-timer task), `views` (read-shape builders), and the four tool groups `lifecycle` / `reads` / `reveals` / `writes`. `main.rs` reads config, opens the audit file, cleans orphans, announces start, spawns the idle timer, and serves stdio. Consent-gating, `KDBX_ALLOW_WRITES` enforcement, and sha256-not-plaintext audit are all wired and validated end to end (zero plaintext leak confirmed by smoke test).

Framework decision (settled): `rmcp` 1.7.0, the official Rust MCP SDK. It owns the protocol plumbing; the `kdbx_core`/adapter split keeps all rmcp coupling inside `src/adapter/`. Tools return the `{ ok, data }` string as a text content block, so the spec's envelope is preserved.

Three deliberate deviations from the plan's letter: the module is `kdbx_core` (not `core`, which would shadow the std crate); diff-kdbx lands in Phase 2 (where `stage` first uses it); and the tool surface is split across `src/adapter/{lifecycle,reads,reveals,writes}.rs` as combined `#[tool_router]` blocks rather than one `tools.rs`.

Minor deferred item: explicit SIGTERM/SIGINT lock-on-shutdown (Task 18 step 4) is not wired, but `keepass::DatabaseKey` is `ZeroizeOnDrop`, so normal shutdown (stdin close) zeroizes the key on drop; abrupt signals rely on OS memory reclaim.

Pending:
- Phase 4 (fixtures, integration and protocol-conformance tests, tasks 19 to 22). The live smoke tests done so far are manual; this phase makes them an automated suite (a `gen-fixtures` binary under the `cli` feature, per-tool integration tests, and a protocol-conformance harness that spawns the binary).
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
- `~/github/kdbx/diff-kdbx/`: path dependency (see Cargo.toml) used by `kdbx_core::stage` for the `kdbx_diff_pending` semantic diff. Read its CLAUDE.md and spec to understand its public Rust API.
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
- Include a `Co-Authored-By: Claude <model name> <noreply@anthropic.com>` trailer on AI-assisted commits, naming whatever model actually did the work. Do not hardcode a specific model name in this file; models change between sessions.

## Test fixture convention (when fixtures land)

Fixtures use the password `test-password-do-not-use` (matches `web-kdbx` and `diff-kdbx`). Generated by a `gen-fixtures` binary in the `[[bin]]` table, gated by the `cli` feature. `tests/fixtures/MANIFEST.md` documents each fixture's contents; tests assert against observed contents to catch manifest drift.
