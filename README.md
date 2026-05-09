# mcp-kdbx

**Model Context Protocol server for KeePass KDBX vaults.** Lets LLM agents
list, search, reveal, and (when explicitly enabled) edit entries in your
encrypted KeePass vault, with per-secret consent gating and a full audit
trail.

A bridge member of the [`*-kdbx` ecosystem](https://github.com/queelius?tab=repositories&q=kdbx).
The other members are `keepass-rs` (substrate library), `diff-kdbx`
(semantic-diff CLI), and `web-kdbx` (browser-side UI).

## Status

**Pre-implementation.** v0.1 design is settled and lives at
`docs/superpowers/specs/2026-05-08-mcp-kdbx-design.md`. The spec covers
the MCP protocol surface, auth and lifecycle, tool semantics, the
stage-then-commit write flow, configuration, audit trail, threat model,
and testing strategy.

The implementation plan is the next document, followed by subagent-driven
development. The flow mirrors the one used for `web-kdbx` and `diff-kdbx`.

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
2. `~/github/kdbx/CLAUDE.md` (ecosystem-level conventions)
3. The sibling repo specs at `~/github/kdbx/web-kdbx/docs/superpowers/specs/`
   for reference on the spec/plan/execute flow

## License

MIT.
