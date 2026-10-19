# mcp-kdbx

[![CI](https://github.com/queelius/mcp-kdbx/actions/workflows/ci.yml/badge.svg)](https://github.com/queelius/mcp-kdbx/actions/workflows/ci.yml)

**Model Context Protocol server for KeePass KDBX vaults.** Lets LLM agents
list, search, reveal, and (when explicitly enabled) edit entries in your
encrypted KeePass vault, with per-secret consent gating and a full audit
trail.

A bridge member of the [`*-kdbx` ecosystem](https://github.com/queelius?tab=repositories&q=kdbx).
The sibling members are `diff-kdbx` (semantic-diff CLI and library) and
`web-kdbx` (browser-side UI); all of them share
[`kdbx-core`](https://github.com/queelius/kdbx-core) (the vault model, path
grammar, visibility rule, keyed fingerprints and TOTP) and build on
[`keepass-rs`](https://github.com/sseemayer/keepass-rs), the substrate library.

## Status

**v0.1 feature-complete, not yet pushed; pending release.** The 17-tool
server (built on `rmcp` 1.7.0), the stage-then-commit write path, and the
full test suite are done, and the server now adopts the shared `kdbx-core`
crate: paths, visibility, field names and TOTP come from it, the stage diff
uses diff-kdbx's snapshot API, the read views are built from a sealed
snapshot, and the audit trail logs keyed fingerprints instead of unkeyed
hashes. 264 tests pass (209 library, 40 protocol-conformance against the
real binary over stdio, 15 integration); `cargo fmt --check` and `cargo
clippy --all-targets --all-features -- -D warnings` are clean, and the
source security audit (`scripts/ci-audit.sh`) passes. Not yet published to
crates.io.

The v0.1 design lives at `docs/superpowers/specs/2026-05-08-mcp-kdbx-design.md`
(its implementation notes record the kdbx-core adoption); the plans at
`docs/superpowers/plans/`. For deployment and observability, see
[`docs/operations.md`](docs/operations.md); for host setup and the
per-release smoke checklist, see
[`docs/manual-testing.md`](docs/manual-testing.md).

## Known limitations

- **Secret titles are out of scope.** The Title is an entry's address in a
  vault path, so it is shown even when its protection flag is set (the
  ecosystem rule in kdbx-core).
- **KDBX 4.1 vaults from KeePassXC may fail to open.** The substrate
  library `keepass-rs` (0.12.x) rejects the KDBX 4.1 `PreviousParentGroup`
  element ([keepass-rs #303](https://github.com/sseemayer/keepass-rs/issues/303))
  and group `<Tags>`, and KeePassXC saves KDBX 4.1 by default. A vault whose
  XML carries either (e.g. after moving entries or groups, or tagging a
  group) will fail to parse. Moving to keepass 0.15 needs KDBX 4.0 save
  support upstream (keepass-rs #373). Workaround until the upstream fix lands: have
  KeePassXC write the vault as KDBX 4.0 (Database > Database Settings >
  Security > Encryption Settings > Database format).

## Quick start

Build from source (Rust 1.89+, edition 2024). `kdbx-core` and `diff-kdbx`
are currently path dependencies, so check out the sibling repos first:

```sh
git clone https://github.com/queelius/kdbx-core ../kdbx-core
git clone https://github.com/queelius/diff-kdbx ../diff-kdbx
cargo build --release   # produces target/release/mcp-kdbx
```

Register with an MCP host, for example Claude Code:

```sh
claude mcp add kdbx \
  --env KDBX_VAULT_PATH=/path/to/vault.kdbx \
  --env KDBX_PASSWORD=correct-horse-battery-staple \
  -- /path/to/mcp-kdbx/target/release/mcp-kdbx
```

Configuration is environment-variable only. `KDBX_VAULT_PATH` is the one
required variable. Common options: `KDBX_PASSWORD` or `KDBX_UNLOCK_CMD`
(master password source; omit both to pass the password per-session via
`kdbx_unlock`), `KDBX_KEYFILE_PATH`, `KDBX_ALLOW_WRITES=true` (writes are
off by default), `KDBX_IDLE_TIMEOUT_SECONDS` (default 900), `KDBX_LOG_FILE`
(JSONL audit trail; stderr when unset), `KDBX_LOG_LEVEL` (default `info`).

The audit file records keyed fingerprints of revealed values, verifiable by
whoever holds the vault (`diff-kdbx fingerprint`), and is as sensitive as the
vault file itself: see [`docs/operations.md`](docs/operations.md).

## Design summary

The server is a single Rust binary. An MCP host (Claude Desktop, Claude
Code, Cursor) spawns it as a child process and communicates over stdio
JSON-RPC. The server reads its configuration from environment variables,
opens the vault file on disk (encrypted bytes only), and unlocks on first
request via env-var password or by shelling out to a secret manager.

The 17-tool surface is structured as four categories:

| Category | Tools | Notes |
|---|---|---|
| Lifecycle | `kdbx_unlock`, `kdbx_lock`, `kdbx_status` | |
| Read (metadata-only) | `kdbx_list_groups`, `kdbx_list_entries`, `kdbx_list_attachments`, `kdbx_get_entry`, `kdbx_find_entry` | Bulk reads never expose protected values |
| Reveal (consent-gated) | `kdbx_reveal_password`, `kdbx_reveal_protected`, `kdbx_download_attachment`, `kdbx_get_otp` | Each call is a separate audited event; TOTP includes Steam codes |
| Write (gated by `KDBX_ALLOW_WRITES=true`) | `kdbx_add_entry`, `kdbx_update_field`, `kdbx_diff_pending`, `kdbx_save_pending`, `kdbx_discard_pending` | Stage-then-commit; no delete or move tools |

Defaults are conservative: read-only, 15-minute idle lock, no writes
without explicit opt-in.

## Comparison to other tools

- **KeePassXC**: a desktop app for humans. mcp-kdbx is for LLM agents.
- **OmniKee**: a Tauri+PWA standalone vault. mcp-kdbx is a server, not an app.
- **`keepass` Python libraries**: in-process libraries. mcp-kdbx is a separate process spawned by the MCP host, with explicit consent gating per secret.

## Reading order for new contributors

1. `docs/superpowers/specs/2026-05-08-mcp-kdbx-design.md` (the v0.1 design)
2. `docs/superpowers/plans/2026-05-09-mcp-kdbx-v0.1.md` (the 26-task
   implementation plan; all five phases complete)
3. `docs/operations.md` (deployment, secret managers, audit log) and
   `docs/manual-testing.md` (host config and the smoke checklist)
4. `~/github/kdbx/CLAUDE.md` (ecosystem-level conventions) and
   `~/github/kdbx/kdbx-core/` (the shared rules mcp-kdbx adopts)
5. The sibling repo specs at `~/github/kdbx/web-kdbx/docs/superpowers/specs/`
   for reference on the spec/plan/execute flow

## License

MIT.
