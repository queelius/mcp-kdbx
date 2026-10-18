# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`mcp-kdbx`: a Model Context Protocol server for KeePass KDBX vaults, written in Rust. Spawned by an MCP host (Claude Desktop, Claude Code, Cursor) as a child process; communicates over stdio JSON-RPC. Exposes 17 tools across four categories (lifecycle, read, reveal, write). Bridge member of the `*-kdbx` ecosystem.

User-facing summary: `README.md`. Full v0.1 design (motivation, protocol surface, auth, semantics, audit trail, threat model, testing): `docs/superpowers/specs/2026-05-08-mcp-kdbx-design.md`.

## Status

**All five v0.1 phases complete (the full server, its automated test suite, CI gates, and docs). Merged to `main` locally (merge commit, `feat/v0.1` deleted); `main` is ahead of `origin/main` and not yet pushed. v0.1 is feature-complete, pending a crates.io release.**

The v0.1 implementation plan landed at `docs/superpowers/plans/2026-05-09-mcp-kdbx-v0.1.md` (26 tasks, 5 phases). 240 tests pass (207 library unit tests, 27 protocol-conformance, 6 integration); `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and the source security audit (`bash scripts/ci-audit.sh`) are clean. The server runs: all 17 tools register and respond over real stdio MCP.

Phase 1 (tasks 1 to 9), the `kdbx_core` foundation: `error`, `config`, `audit`, `totp`, `path`, `search`, `unlock`, `vault`.

Phase 2 (tasks 10, 12, 13), stage-then-commit: `stage` (working-copy writes, the diff-kdbx stage diff with protected-field redaction, the atomic save) and `orphan` (startup temp-file cleanup). `diff-kdbx` is a path dependency.

Phase 3 (tasks 14 to 18), the MCP adapter over `rmcp` 1.7.0, all in `src/adapter/`: `responses` (the `{ ok, data } | { ok, error }` text envelope), `mod` (the `KdbxServer` handler, shared state, level-filtered audit emission, the writes gate, and the idle-timer task), `views` (read-shape builders), and the four tool groups `lifecycle` / `reads` / `reveals` / `writes`. `main.rs` reads config, opens the audit file, cleans orphans, announces start, spawns the idle timer, and serves stdio. Consent-gating, `KDBX_ALLOW_WRITES` enforcement, and sha256-not-plaintext audit are all wired and validated end to end (zero plaintext leak confirmed by smoke test).

Framework decision (settled): `rmcp` 1.7.0, the official Rust MCP SDK. It owns the protocol plumbing; the `kdbx_core`/adapter split keeps all rmcp coupling inside `src/adapter/`. Tools return the `{ ok, data }` string as a text content block, so the spec's envelope is preserved.

Deliberate deviations from the plan's letter: the module is `kdbx_core` (not `core`, which would shadow the std crate); diff-kdbx lands in Phase 2 (where `stage` first uses it); the tool surface is split across `src/adapter/{lifecycle,reads,reveals,writes}.rs` as combined `#[tool_router]` blocks rather than one `tools.rs`; and in Phase 4 the plan's two test layers were unified onto a single binary-spawning harness (`tests/common/mod.rs`) with the work grouped into `tests/protocol_conformance.rs` (Layer 3: tools/list surface, per-tool happy path, every error code, round-trips) and `tests/integration.rs` (Layer 2 stateful flows: audit-file inspection, stage/save/reopen, manual-lock recovery, idle lock, external-modification conflict), rather than seven per-category files under `tests/integration/`. The adapter's tool methods are private, so driving the real binary over stdio is both more faithful and the only black-box option.

Phase 4 also fixed a latent server-identity bug found while writing the conformance test: `get_info` used `Implementation::from_build_env()`, whose `env!` expands inside the rmcp crate, so the server announced itself as `rmcp` v1.7.0. It now builds the identity from this crate's own `CARGO_PKG_NAME`/`CARGO_PKG_VERSION`, and the conformance test pins `mcp-kdbx`.

Minor deferred item: explicit SIGTERM/SIGINT lock-on-shutdown (Task 18 step 4) is not wired, but `keepass::DatabaseKey` is `ZeroizeOnDrop`, so normal shutdown (stdin close) zeroizes the key on drop; abrupt signals rely on OS memory reclaim.

Two error codes are not reachable from a black-box protocol test and stay covered by `kdbx_core` unit tests: `VAULT_NOT_FOUND` (the config layer refuses to start without a readable vault path) and `WRITE_FAILED` (needs a mid-save filesystem failure).

Phase 5 (tasks 23 to 26): `.github/workflows/ci.yml` (rust-test, protocol-conformance, and source-audit jobs; checks out the sibling `diff-kdbx` so the path dep resolves), `scripts/ci-audit.sh` (seven source-invariant grep checks), `docs/operations.md` (config, secret managers, audit log, posture), and the README polish (status, quick start, CI badge). The CI gate runs `cargo fmt --check`, `cargo test --all-features`, and `cargo clippy --all-targets --all-features -- -D warnings` (the `--all-features` is needed to lint the `cli`-gated `gen-fixtures` helper).

Remaining for release (not v0.1 plan tasks): push `main` to `origin`, run the `docs/manual-testing.md` smoke against a real host, then migrate the `diff-kdbx` path dependency to a crates.io (or git) version and publish. The CI currently checks out `diff-kdbx`'s default branch as a sibling, so it depends on that branch carrying the API mcp-kdbx builds against (the local `diff-kdbx` HEAD with the needed API may be ahead of its pushed `main`; pushing diff-kdbx or pinning the CI checkout removes the risk before the first CI run).

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
- **Master password and `KDBX_UNLOCK_CMD` output never appear in any log.** v0.1 ensures this by capping rmcp's tracing verbosity (`rmcp=warn` in `main.rs`) so the SDK never debug-logs raw JSON-RPC payloads (which carry the password and revealed secrets), and by wrapping every secret-bearing field (the password and unlock command in `Config`, unlock and write tool inputs, field values, attachment bytes, the TOTP secret and code) in `kdbx_core::secret::Secret<T>`, whose `Debug` prints `<redacted>` and whose value is zeroized on drop. `scripts/ci-audit.sh` check D enforces this structurally for every struct that derives `Debug`. The spec's `mcp_message` trace capture is deferred (see the spec's implementation notes); if it lands later, it must redact before logging.
- **Writes default off.** `KDBX_ALLOW_WRITES` MUST be exactly `"true"` to enable; other values rejected at startup.
- **Stage-then-commit.** Writes mutate `working_db`; nothing hits disk until `kdbx_save_pending`. Lock (any reason) discards the stage; the next tool call returns VAULT_LOCKED with the discarded summary.
- **Save atomicity via temp+fsync+rename+fsync(parent).** No partial-file window on power loss.
- **Content conflict refusal.** External vault modification (KeePassXC, another mcp-kdbx) refuses save with VAULT_FILE_MODIFIED. Identity is the sha256 of the bytes parsed at unlock (or written by the last save), re-checked under a sidecar `<vault>.lock` advisory lock held across check, write, and rename; mtimes are reported, never trusted.

## Voice rules for any prose written here

- Follow the soul skill (canonical list: `~/github/repos/soul/skills/soul/SKILL.md`). Key rules: no em-dashes (use commas, periods, colons, parentheses); no corporate hype phrases; direct, plain, humble.
- Conventional commits with lowercase scope: `feat(vault):`, `docs(spec):`, `ci:`, `test(integration):`, etc.
- Include a `Co-Authored-By: Claude <model name> <noreply@anthropic.com>` trailer on AI-assisted commits, naming whatever model actually did the work. Do not hardcode a specific model name in this file; models change between sessions.

## Test fixture convention

Fixtures use the password `test-password-do-not-use` (matches `web-kdbx` and `diff-kdbx`). They are committed under `tests/fixtures/` and regenerated by the `gen-fixtures` binary (`[[bin]]` in Cargo.toml, gated by the `cli` feature):

```sh
cargo run --features cli --bin gen-fixtures
```

`tests/fixtures/MANIFEST.md` documents each fixture's contents (empty, flat, nested, with_attachments, with_otp, duplicates); tests assert against observed contents to catch manifest drift. The generator is not byte-stable (keepass assigns random UUIDs, KDBX4 uses a fresh nonce per save), so tests resolve entries by path and title, not UUID. Manual cross-MCP-host smoke steps live in `docs/manual-testing.md`.
