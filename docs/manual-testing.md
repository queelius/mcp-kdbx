# Manual cross-host smoke testing

The automated suites (`cargo test`) drive the server over stdio in-process. This
document covers the part they cannot: confirming `mcp-kdbx` works inside a real
MCP host (Claude Desktop, Claude Code, Cursor) before tagging a release.

Run this checklist once per release, against at least one host.

## Prerequisites

Build and install the binary so the host can launch it by name:

```sh
cargo install --path .        # installs `mcp-kdbx` into ~/.cargo/bin
# or build in place and use the absolute target path in the config below:
cargo build --release         # target/release/mcp-kdbx
```

Have a throwaway vault to point at. The committed test fixture works:
`tests/fixtures/flat.kdbx`, password `test-password-do-not-use`. Copy it
somewhere writable if you want to exercise the write tools (they refuse to touch
the file unless `KDBX_ALLOW_WRITES=true`, and even then only on save).

`mcp-kdbx` is one server per vault. To expose more than one vault, add more
entries under `mcpServers`, each with its own `KDBX_VAULT_PATH`.

## Configuration

The server reads everything from `KDBX_*` environment variables (see the spec
section 5 for the full surface). The host passes them through its `env` block.

| Variable | Meaning |
|---|---|
| `KDBX_VAULT_PATH` | Absolute path to the `.kdbx` vault. Required. |
| `KDBX_PASSWORD` | Master password injected directly. Optional; prefer per-call unlock or `KDBX_UNLOCK_CMD`. |
| `KDBX_UNLOCK_CMD` | Shell command whose stdout is the master password (the secret-manager path, for example `pass show vault`). |
| `KDBX_KEYFILE_PATH` | Optional keyfile for two-factor unlock. |
| `KDBX_ALLOW_WRITES` | Exactly `"true"` to enable the write tools. Off by default. |
| `KDBX_IDLE_TIMEOUT_SECONDS` | Idle auto-lock window. Default `900` (15 minutes); `0` disables it. |
| `KDBX_LOG_FILE` | Append-only JSONL audit log path. Optional. |
| `KDBX_LOG_LEVEL` | `error`, `warn`, `info` (default), `debug`, `trace`. |

### Password handling

There are three ways the master password reaches the server, tried in this order:

1. The `password` argument to `kdbx_unlock` (the agent supplies it per session).
2. `KDBX_PASSWORD` from the env block.
3. `KDBX_UNLOCK_CMD` stdout.

Prefer option 1 or 3. Putting a plaintext password in a host config file
(`KDBX_PASSWORD`) is the least safe option and is meant for throwaway or
automated setups only. The password and the unlock-command output never appear
in any log.

### Claude Desktop

Edit `claude_desktop_config.json` (macOS:
`~/Library/Application Support/Claude/claude_desktop_config.json`; the location
differs per platform). A ready-to-edit example is in
[`examples/claude-desktop-config.json`](../examples/claude-desktop-config.json):

```json
{
  "mcpServers": {
    "kdbx": {
      "command": "mcp-kdbx",
      "env": {
        "KDBX_VAULT_PATH": "/absolute/path/to/your/vault.kdbx",
        "KDBX_IDLE_TIMEOUT_SECONDS": "900"
      }
    }
  }
}
```

If `mcp-kdbx` is not on the host's `PATH`, use the absolute path to the binary as
`command` (for example `/home/you/.cargo/bin/mcp-kdbx`). Restart Claude Desktop
after editing. To enable writes, add `"KDBX_ALLOW_WRITES": "true"` to `env`.

### Claude Code

Register the server with the CLI (this writes the same kind of config):

```sh
claude mcp add kdbx --env KDBX_VAULT_PATH=/absolute/path/to/your/vault.kdbx -- mcp-kdbx
```

Add more `--env KEY=value` flags for the other variables (for example
`--env KDBX_ALLOW_WRITES=true`). Confirm the server is listed with
`claude mcp list`.

### Cursor

Edit `~/.cursor/mcp.json` (or the project-local `.cursor/mcp.json`). The shape
matches Claude Desktop:

```json
{
  "mcpServers": {
    "kdbx": {
      "command": "mcp-kdbx",
      "env": { "KDBX_VAULT_PATH": "/absolute/path/to/your/vault.kdbx" }
    }
  }
}
```

Reload Cursor's MCP settings after editing.

## Per-release smoke checklist

Pick a host, point it at a throwaway vault (the `flat.kdbx` fixture is ideal),
and walk through the path an agent would take. Each step lists the tool and the
expected result.

- [ ] **Server starts.** The host shows `kdbx` as connected and lists 17 tools.
- [ ] **Status while locked.** `kdbx_status` reports `locked: true`,
      `writes_allowed` matching your config, and the vault path.
- [ ] **Unlock.** `kdbx_unlock` with the password returns `locked: false`. A
      wrong password returns `AUTH_FAILED`.
- [ ] **List.** `kdbx_list_groups` and `kdbx_list_entries` (group `/`) return the
      entries (GitHub, Bank, Email, Server, Wifi for the fixture) with no
      password values in the output.
- [ ] **Get and find.** `kdbx_get_entry` (`/Bank`) returns metadata and
      timestamps; `kdbx_find_entry` (query `Bank`) finds it.
- [ ] **Reveal.** `kdbx_reveal_password` (`/Bank`) returns the plaintext.
      `kdbx_reveal_protected` (`/Bank`, `PIN`) returns `4321`. Revealing an
      unprotected field (`/Server`, `Port`) returns `FIELD_NOT_PROTECTED`.
- [ ] **Audit (if `KDBX_LOG_FILE` set).** The log records `vault_unlocked` and
      `reveal_password`, and the revealed value does not appear in plaintext
      (only a keyed `fingerprint`, which `diff-kdbx fingerprint` reproduces
      from the `vault_unlocked` event's `fingerprint_params` and
      `fingerprint_salt`; see `docs/operations.md`).
- [ ] **Writes disabled path.** With writes off, `kdbx_add_entry` returns
      `WRITES_DISABLED`.
- [ ] **Writes enabled path (separate run with `KDBX_ALLOW_WRITES=true`, on a
      copy).** `kdbx_add_entry` and `kdbx_update_field` stage changes;
      `kdbx_diff_pending` shows them; `kdbx_save_pending` commits; reopening the
      vault shows the changes persisted.
- [ ] **Lock.** `kdbx_lock` returns `locked: true`. A read afterward returns
      `VAULT_LOCKED`, and if a stage was pending, the first such error reports
      what was discarded.
- [ ] **Idle lock.** With a short `KDBX_IDLE_TIMEOUT_SECONDS`, leaving the vault
      untouched past the window locks it; the next call returns `VAULT_LOCKED`
      with `lock_reason: idle_timeout`.

Record the host, its version, and the date in the release notes when the
checklist passes.
