# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`mcp-kdbx`: a Model Context Protocol server for KeePass KDBX vaults, written in Rust. Spawned by an MCP host (Claude Desktop, Claude Code, Cursor) as a child process; communicates over stdio JSON-RPC. Exposes 17 tools across four categories (lifecycle, read, reveal, write). Bridge member of the `*-kdbx` ecosystem.

User-facing summary: `README.md`. Full v0.1 design (motivation, protocol surface, auth, semantics, audit trail, threat model, testing): `docs/superpowers/specs/2026-05-08-mcp-kdbx-design.md`.

## Status

**All five v0.1 phases complete (the full server, its automated test suite, CI gates, and docs). Merged to `main` locally (merge commit, `feat/v0.1` deleted); `main` is ahead of `origin/main` and not yet pushed. v0.1 is feature-complete, pending a crates.io release.**

The v0.1 implementation plan landed at `docs/superpowers/plans/2026-05-09-mcp-kdbx-v0.1.md` (26 tasks, 5 phases). After the kdbx-core adoption (below), 270 tests pass (213 library unit tests, 41 protocol-conformance, 16 integration); `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and the source security audit (`bash scripts/ci-audit.sh`, checks A to G) are clean. The server runs: all 17 tools register and respond over real stdio MCP.

**kdbx-core adoption (2026-10-18, branch `adopt/kdbx-core`, plan `docs/superpowers/plans/2026-10-18-mcp-kdbx-kdbx-core-adoption.md`).** mcp-kdbx no longer carries its own copies of the ecosystem rules. Architecture now: `src/engine/` (renamed from `kdbx_core`, so `kdbx_core::` always means the shared crate) holds `view` (a `View` is a fingerprint-sealed kdbx-core snapshot of a keepass db plus its `PathIndex` and OTP availability; the vault caches one per working-db generation), `address` (path or uuid, resolved against a view: `resolve_in` to the snapshot record for reads, `resolve` to the live keepass id for reveals and writes), `otp` (kdbx-core's `otp` over the live entry's `otp_fields`, typed `OTP_INVALID`), `search` (over the snapshot), `stage` (diff via `diff_kdbx::compute` on two snapshots), `audit`, `vault`, and the rest unchanged. Paths, visibility (`is_secret`), field names, TOTP and fingerprints all come from kdbx-core; `engine::path`, `engine::visibility` and `engine::totp` are deleted. The read views are built from the cached snapshot alone; reveals and writes use the live db. Two fingerprint keys: a random per-session key for every fingerprint in a tool response, and the Argon2-derived stable audit key (only when an audit file is configured and the log level records reveals; single-threaded argon2 0.5, so up to lanes times the vault's KDF time) for audit-file fingerprints, whose fields never reach stderr. User-visible changes: group paths keep their trailing `/`, escapes are strict, an unprotected Password is a secret, `OTP_INVALID`, Steam TOTP, attachment `fingerprint` instead of `sha256`, and the audit JSONL fields. Details: the spec's "Implementation notes (kdbx-core adoption, 2026-10-18)".

Phase 1 (tasks 1 to 9), the `engine` foundation: `error`, `config`, `audit`, `totp`, `path`, `search`, `unlock`, `vault`.

Phase 2 (tasks 10, 12, 13), stage-then-commit: `stage` (working-copy writes, the diff-kdbx stage diff with protected-field redaction, the atomic save) and `orphan` (startup temp-file cleanup). `diff-kdbx` is a path dependency.

Phase 3 (tasks 14 to 18), the MCP adapter over `rmcp` 1.7.0, all in `src/adapter/`: `responses` (the `{ ok, data } | { ok, error }` text envelope), `mod` (the `KdbxServer` handler, shared state, level-filtered audit emission, the writes gate, and the idle-timer task), `views` (read-shape builders), and the four tool groups `lifecycle` / `reads` / `reveals` / `writes`. `main.rs` reads config, opens the audit file, cleans orphans, announces start, spawns the idle timer, and serves stdio. Consent-gating, `KDBX_ALLOW_WRITES` enforcement, and sha256-not-plaintext audit are all wired and validated end to end (zero plaintext leak confirmed by smoke test).

Framework decision (settled): `rmcp` 1.7.0, the official Rust MCP SDK. It owns the protocol plumbing; the `engine`/adapter split keeps all rmcp coupling inside `src/adapter/`. Tools return the `{ ok, data }` string as a text content block, so the spec's envelope is preserved.

Deliberate deviations from the plan's letter: the module was `kdbx_core` (not `core`, which would shadow the std crate), renamed to `engine` when the external `kdbx-core` crate was adopted, so `use kdbx_core::...` always means the shared crate; diff-kdbx lands in Phase 2 (where `stage` first uses it); the tool surface is split across `src/adapter/{lifecycle,reads,reveals,writes}.rs` as combined `#[tool_router]` blocks rather than one `tools.rs`; and in Phase 4 the plan's two test layers were unified onto a single binary-spawning harness (`tests/common/mod.rs`) with the work grouped into `tests/protocol_conformance.rs` (Layer 3: tools/list surface, per-tool happy path, every error code, round-trips) and `tests/integration.rs` (Layer 2 stateful flows: audit-file inspection, stage/save/reopen, manual-lock recovery, idle lock, external-modification conflict), rather than seven per-category files under `tests/integration/`. The adapter's tool methods are private, so driving the real binary over stdio is both more faithful and the only black-box option.

Phase 4 also fixed a latent server-identity bug found while writing the conformance test: `get_info` used `Implementation::from_build_env()`, whose `env!` expands inside the rmcp crate, so the server announced itself as `rmcp` v1.7.0. It now builds the identity from this crate's own `CARGO_PKG_NAME`/`CARGO_PKG_VERSION`, and the conformance test pins `mcp-kdbx`.

Minor deferred item: explicit SIGTERM/SIGINT lock-on-shutdown (Task 18 step 4) is not wired, but `keepass::DatabaseKey` is `ZeroizeOnDrop`, so normal shutdown (stdin close) zeroizes the key on drop; abrupt signals rely on OS memory reclaim.

Review fix batch (2026-10-18, branch `fix/review-batch`): paths can no longer alias another entry (empty-title records have `path: null`, entry tools refuse trailing-slash paths, and every entry and group tool accepts a uuid instead of a path); save conflicts are detected by content sha256 under a sidecar `<vault>.lock` flock (MSRV 1.89 for `File::try_lock`; the lock file takes the vault mode, opens read-only if unwritable, refuses symlinks and FIFOs, and degrades with a warn event on filesystems without locks); `update_field` records history and modification time, with history kept oldest first and trimmed per the vault HistoryMaxItems/HistoryMaxSize; every Title write is validated (Unicode Cc and all Cf except ZWNJ/ZWJ rejected, via `unicode-properties`); `kdbx_get_otp` clamps `time_unix` to now plus or minus one period; symlinked vaults stay symlinks; temp files are 0600 from creation and orphan cleanup parses names strictly (`vault_file::TempName`); secret-bearing fields are `Secret<T>` (redacting, zeroizing) with a structural CI check; the last lock's discard is reported by `kdbx_unlock` (`previous_lock`) and `kdbx_status` (`last_lock`); new codes `PATH_INVALID` and `VAULT_UNREADABLE` (audited as `unlock_failed`); `find_entry.fields` is a closed enum; KeePass 2 native `TimeOtp-*` TOTP fields are supported; audit levels and reasons are serde enums with the JSONL format pinned. Details: the spec's "Implementation notes (review fix batch, 2026-10-18)".

Two error codes are not reachable from a black-box protocol test and stay covered by `engine` unit tests: `VAULT_NOT_FOUND` (the config layer refuses to start without a readable vault path) and `WRITE_FAILED` (needs a mid-save filesystem failure).

Phase 5 (tasks 23 to 26): `.github/workflows/ci.yml` (rust-test, protocol-conformance, and source-audit jobs; checks out the sibling `kdbx-core` and `diff-kdbx` so the path deps resolve), `scripts/ci-audit.sh` (source-invariant grep checks, A to G since the kdbx-core adoption), `docs/operations.md` (config, secret managers, audit log, posture), and the README polish (status, quick start, CI badge). The CI gate runs `cargo fmt --check`, `cargo test --all-features`, and `cargo clippy --all-targets --all-features -- -D warnings` (the `--all-features` is needed to lint the `cli`-gated `gen-fixtures` helper).

Remaining for release (not plan tasks): create `queelius/kdbx-core` on GitHub and push diff-kdbx's snapshot API, then pin both sibling checkouts in `.github/workflows/ci.yml` to commit SHAs (the TODOs there); push; run the `docs/manual-testing.md` smoke against a real host; then switch the `kdbx-core` and `diff-kdbx` path dependencies to crates.io versions and publish.

## Position in the ecosystem

| Member | Role | Relation to mcp-kdbx |
|---|---|---|
| `keepass-rs` | Substrate library | Direct dependency (0.12). Provides parsing, encryption, write API. |
| `kdbx-core` | Shared crate | Direct dependency (`keepass-0_12` capture, `kdf`). Owns the snapshot model, path grammar, visibility rule, field schema, keyed fingerprints, text escaping and TOTP. Bumping keepass means switching its capture feature. |
| `diff-kdbx` | Sibling CLI | Library dependency for `kdbx_diff_pending`: `compute` over two kdbx-core snapshots, independent of mcp-kdbx's keepass version. Its `fingerprint` subcommand verifies audit fingerprints. |
| `web-kdbx` | Sibling browser UI | Independent. Shares kdbx-core. Different consumer (browser users vs LLM agents). |
| `hugo-kdbx`, `arkiv-kdbx`, `longecho-kdbx` | Bridges, planned | Out of scope for v0.1. |

## Key cross-repo references

- `~/github/kdbx/CLAUDE.md`: ecosystem-level conventions for all `*-kdbx` repos.
- `~/github/kdbx/web-kdbx/`: the most mature sibling. Its spec/plan pair (`2026-04-29-web-kdbx-design.md` + `2026-04-29-web-kdbx.md`, plus `2026-05-06-web-kdbx-l1-storage-design.md` + `2026-05-06-web-kdbx-l1.md`) is the canonical example of the workflow.
- `~/github/kdbx/kdbx-core/`: path dependency; its spec (`docs/superpowers/specs/2026-10-18-kdbx-core-design.md`, section 9 wins) and CLAUDE.md define the shared rules. Do not re-implement any of them here; report gaps upstream.
- `~/github/kdbx/diff-kdbx/`: path dependency (see Cargo.toml) used by `engine::stage` for the `kdbx_diff_pending` semantic diff. Read its CLAUDE.md to understand its public Rust API (`compute`, `ChangeSet`; `#[non_exhaustive]` everywhere, so match with wildcard arms).
- `~/github/bugfixes/track1-issues/keepass-rs/`: local fork used for upstream contributions.

## Architectural decisions (settled in the v0.1 spec)

| Decision | Choice |
|---|---|
| Scope | Per-vault server (one mcp-kdbx instance per vault) |
| Transport | stdio JSON-RPC only (no HTTP/SSE in v0.1) |
| Auth | env-var password + optional shell-out to secret manager (`KDBX_PASSWORD` and `KDBX_UNLOCK_CMD`) |
| Idle lock TTL | 900 seconds (15 minutes) default; configurable |
| Write capability | Read + limited write (add_entry, update_field; no delete, no move). Gated by `KDBX_ALLOW_WRITES=true` at startup. |
| Stage model | In-memory shadow database; diff-kdbx-as-library computes the diff over two kdbx-core snapshots; atomic temp+rename on save |
| Audit trail | JSONL via `KDBX_LOG_FILE`; keyed fingerprints (kdbx-core, HMAC-SHA256 under an Argon2id key derived per unlock) of revealed values, in the file only; tool-response fingerprints are session-keyed |

## Workflow for any new feature

1. Brainstorm against the relevant existing spec, or `/brainstorm` from scratch (superpowers:brainstorming).
2. Spec lands in `docs/superpowers/specs/YYYY-MM-DD-<name>.md`.
3. Implementation plan lands in `docs/superpowers/plans/YYYY-MM-DD-<name>.md` (use checkbox `- [ ]` syntax for tracking).
4. Execute via subagent-driven development (one subagent per task; two-stage review).
5. Finish via the superpowers:finishing-a-development-branch skill.

## Invariants to preserve once code lands

These are non-negotiable from the spec; flag any change that violates them as a design-level concern, not just a code change.

- **Bulk reads never expose protected values.** `kdbx_list_entries`, `kdbx_get_entry`, `kdbx_find_entry`, `kdbx_list_attachments` return metadata only (including the `protected: bool` flag per field). Reveal requires a separate per-call event.
- **Reveal events log a keyed fingerprint of the value, never the value.** kdbx-core's `Fingerprint` under the stable audit key (derived at unlock, only when an audit file is configured, from the master key material, root group UUID salt, `DeriveParams::for_header`; its params and salt recorded in the file's `vault_unlocked` so `diff-kdbx fingerprint` can verify). Never an unkeyed hash of a secret. Everything derived from that key goes to the audit file only, never stderr or a tool response: the file is as sensitive as the vault. Fingerprints in tool responses use a random per-session key. Plaintext values appear in logs only at `trace` level (explicit opt-in, documented warning).
- **Master password and `KDBX_UNLOCK_CMD` output never appear in any log.** v0.1 ensures this by capping rmcp's tracing verbosity (`rmcp=warn` in `main.rs`) so the SDK never debug-logs raw JSON-RPC payloads (which carry the password and revealed secrets), and by wrapping every secret-bearing field (the password and unlock command in `Config`, unlock and write tool inputs, field values, attachment bytes, the TOTP secret and code) in `engine::secret::Secret<T>`, whose `Debug` prints `<redacted>` and whose value is zeroized on drop. `scripts/ci-audit.sh` check D enforces this structurally for every struct that derives `Debug`. The spec's `mcp_message` trace capture is deferred (see the spec's implementation notes); if it lands later, it must redact before logging.
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
