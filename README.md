# mcp-kdbx

**Model Context Protocol server for KeePass KDBX vaults.** Lets LLM agents
list, search, reveal, and (when explicitly enabled) edit entries in your
encrypted KeePass vault, with per-secret consent gating and a full audit
trail.

A bridge member of the [`*-kdbx` ecosystem](https://github.com/queelius?tab=repositories&q=kdbx).
The sibling members are `diff-kdbx` (semantic-diff CLI and library) and
`web-kdbx` (browser-side UI); all of them build on
[`keepass-rs`](https://github.com/sseemayer/keepass-rs), the substrate library.

## Status

**Working server, pre-release.** Phases 1-3 of the v0.1 plan are complete
on branch `feat/v0.1`: all 17 tools register and respond over real stdio
MCP (built on `rmcp` 1.7.0), 179 library tests pass, `cargo fmt` and
`cargo clippy -D warnings` are clean, and consent gating, the
`KDBX_ALLOW_WRITES` gate, and the sha256-not-plaintext audit trail were
validated end to end against a live MCP host with zero plaintext leakage.
Remaining before release: Phase 4 (fixtures, integration tests,
protocol-conformance harness) and Phase 5 (CI gates and docs).

The v0.1 design lives at `docs/superpowers/specs/2026-05-08-mcp-kdbx-design.md`;
the implementation plan at `docs/superpowers/plans/2026-05-09-mcp-kdbx-v0.1.md`.

## Known limitations

- **KDBX 4.1 vaults from KeePassXC may fail to open.** The substrate
  library `keepass-rs` (0.12.x) rejects the KDBX 4.1 `PreviousParentGroup`
  element ([keepass-rs #303](https://github.com/sseemayer/keepass-rs/issues/303),
  open upstream), and KeePassXC saves KDBX 4.1 by default. A vault whose
  XML carries `PreviousParentGroup` (e.g. after moving entries or groups)
  will fail to parse. Workaround until the upstream fix lands: have
  KeePassXC write the vault as KDBX 4.0 (Database > Database Settings >
  Security > Encryption Settings > Database format).

## Quick start

Build from source (Rust 1.85+, edition 2024). `diff-kdbx` is currently a
path dependency, so check out the sibling repo at `../diff-kdbx` first:

```sh
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
| Reveal (consent-gated) | `kdbx_reveal_password`, `kdbx_reveal_protected`, `kdbx_download_attachment`, `kdbx_get_otp` | Each call is a separate audited event |
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
   implementation plan; Phases 1-3 done, 4-5 pending)
3. `~/github/kdbx/CLAUDE.md` (ecosystem-level conventions)
4. The sibling repo specs at `~/github/kdbx/web-kdbx/docs/superpowers/specs/`
   for reference on the spec/plan/execute flow

## License

MIT.
