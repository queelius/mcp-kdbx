# Operations

How to deploy, configure, and observe `mcp-kdbx` in practice. For host-specific
config (Claude Desktop, Claude Code, Cursor) and the per-release smoke checklist,
see [`manual-testing.md`](manual-testing.md). For the full design rationale and
threat model, see the spec at
`docs/superpowers/specs/2026-05-08-mcp-kdbx-design.md`.

## Configuration surface

All configuration is environment variables. There are no CLI flags and no config
file, so there is one source and no precedence to reason about. The host passes
these through its `env` block.

| Variable | Default | Meaning |
|---|---|---|
| `KDBX_VAULT_PATH` | (required) | Absolute path to the `.kdbx` vault. Validated to be a readable regular file at startup. |
| `KDBX_PASSWORD` | unset | Master password injected directly. The least safe source; prefer per-call unlock or `KDBX_UNLOCK_CMD`. |
| `KDBX_UNLOCK_CMD` | unset | Shell command whose stdout is the master password. The secret-manager path. |
| `KDBX_UNLOCK_CMD_TIMEOUT_SECONDS` | `30` | Timeout for the unlock command. |
| `KDBX_KEYFILE_PATH` | unset | Optional keyfile for two-factor unlock. |
| `KDBX_ALLOW_WRITES` | off | Exactly `"true"` enables the write tools. Any other value is a startup error. |
| `KDBX_IDLE_TIMEOUT_SECONDS` | `900` | Idle auto-lock window. `0` disables idle lock. |
| `KDBX_AUTO_CLEAN_ORPHANS` | off | Exactly `"true"` cleans stale `*.tmp.*` save temp files at startup. |
| `KDBX_LOG_FILE` | unset | Append-only JSONL audit log path. Stderr only when unset. |
| `KDBX_LOG_LEVEL` | `info` | One of `error`, `warn`, `info`, `debug`, `trace`. Case-sensitive. |

Strict booleans (`KDBX_ALLOW_WRITES`, `KDBX_AUTO_CLEAN_ORPHANS`) must be exactly
`"true"` or unset. `"yes"`, `"1"`, `"TRUE"` are rejected at startup, on purpose:
a typo must not silently leave a flag in the wrong state.

### Typical read-only deployment

```sh
KDBX_VAULT_PATH=/home/you/vaults/personal.kdbx
KDBX_UNLOCK_CMD='pass show kdbx/personal'
KDBX_LOG_FILE=/home/you/.local/state/mcp-kdbx/audit.jsonl
```

### Writes enabled (on a vault you back up)

```sh
KDBX_VAULT_PATH=/home/you/vaults/work.kdbx
KDBX_UNLOCK_CMD='op read op://Private/work-kdbx/password'
KDBX_ALLOW_WRITES=true
KDBX_LOG_FILE=/home/you/.local/state/mcp-kdbx/work-audit.jsonl
```

## Password sources

The master password reaches the server from the first available of three
sources, in this order:

1. The `password` argument to `kdbx_unlock` (the agent supplies it per session).
2. `KDBX_PASSWORD` from the environment.
3. The stdout of `KDBX_UNLOCK_CMD`.

The password and the unlock-command output never appear in any log. Prefer
option 1 or 3: a plaintext password in a host config file (`KDBX_PASSWORD`) sits
in that file and in the process environment, where other tooling can read it.

### Secret-manager integration

`KDBX_UNLOCK_CMD` runs via `/bin/sh -c` and its trimmed stdout becomes the
password. Any command works. Common ones:

```sh
# pass (the standard unix password store)
KDBX_UNLOCK_CMD='pass show kdbx/personal'

# 1Password CLI
KDBX_UNLOCK_CMD='op read op://Private/personal-kdbx/password'

# gpg-encrypted file decrypted through gpg-agent (no passphrase re-entry while
# the agent has it cached)
KDBX_UNLOCK_CMD='gpg --quiet --decrypt /home/you/.secrets/kdbx-personal.gpg'

# macOS Keychain
KDBX_UNLOCK_CMD='security find-generic-password -s kdbx-personal -w'

# secret-tool (libsecret / GNOME Keyring)
KDBX_UNLOCK_CMD='secret-tool lookup service kdbx vault personal'
```

The command runs once per unlock, bounded by `KDBX_UNLOCK_CMD_TIMEOUT_SECONDS`. A
non-zero exit or a timeout is reported as `AUTH_FAILED`; the error details carry
the exit code or a timeout reason, never the command text or its output.

### Keyfile

For a vault protected by password plus keyfile, set `KDBX_KEYFILE_PATH`. A
per-call `keyfile_bytes` (base64) on `kdbx_unlock` overrides it. A missing or
unreadable keyfile is `AUTH_FAILED`.

## Audit log

When `KDBX_LOG_FILE` is set, every audited action is appended as one JSON object
per line (JSONL). The same lines also go to stderr.

### Format

```json
{"timestamp":"2026-10-19T00:21:24Z","level":"info","event":"vault_unlocked","pid":239659,"details":{"file_mtime":"2026-06-18T08:10:42Z","fingerprint_params":"argon2id$v=19$m=65536,t=3,p=1","fingerprint_salt":"133fb32a-2e9c-4281-b9fc-f462745668bc","unlock_source":"input"}}
{"timestamp":"2026-10-19T00:21:24Z","level":"info","event":"reveal_protected","pid":239659,"details":{"field_name":"PIN","fingerprint":"3671f5b92f3621151eed445763cdbac02cf6cfc40d36704a294036b6d9807f39","fingerprint_domain":"kdbx-core/field/v1","target_path":"/Bank","target_uuid":"2278f0b7-ecbd-4e10-ba9a-9f6b53ba7f92"}}
```

| Field | Meaning |
|---|---|
| `timestamp` | UTC, `YYYY-MM-DDTHH:MM:SSZ`. |
| `level` | `info`, `warn`, or `error`. |
| `event` | The event type (table below). |
| `pid` | The server process id. |
| `details` | Event-specific fields. |

Event types: `server_started`, `vault_unlocked`, `vault_locked`, `auth_failed`,
`unlock_failed`, `reveal_password`, `reveal_protected`, `download_attachment`,
`get_otp`, `write_staged`, `save_committed`, `save_refused`, `save_failed`,
`stage_discarded`, `writer_lock_unavailable`.

### Privacy invariant

Reveal events record a keyed fingerprint of the value, never the value:
`fingerprint` is HMAC-SHA256 under a key derived from the vault's master key
material (64 hex), and `fingerprint_domain` names what was fingerprinted
(`kdbx-core/field/v1` for `reveal_password` and `reveal_protected`,
`kdbx-core/attachment/v1` for `download_attachment`, whose fingerprint is also
what `kdbx_list_attachments` reports). The master password and
`KDBX_UNLOCK_CMD` output never appear at any level. Plaintext values appear
only at `trace` level, an explicit opt-in for local debugging; do not run
`trace` against a real vault.

An unkeyed hash would be a lookup oracle: whoever reads the log could hash
every 4-digit PIN and find the one revealed. The key closes that. It is
derived once per unlock with Argon2id over the master password and key file,
salted with the vault's root group UUID, with the vault's own Argon2
parameters when they cost at least 64 MiB x 3 passes and those floor
parameters otherwise, so guessing the key is never cheaper than attacking the
vault. `vault_unlocked` records the parameters (`fingerprint_params`) and the
salt (`fingerprint_salt`), and the key is dropped (and wiped) on lock. An
unlock therefore costs one extra Argon2 run.

The format changed with the kdbx-core adoption: earlier logs carry `sha256`
(`sha256("kdbx-reveal-v1\0" || value)` for string reveals, a plain content
sha256 for attachments) and no `fingerprint_*` keys.

### Verifying a logged fingerprint

Whoever holds the vault can check which value a reveal event names, with
diff-kdbx's `fingerprint` subcommand and the `vault_unlocked` event of the
same session:

```sh
# fingerprint_params and fingerprint_salt from the session's vault_unlocked
KDBX_DIFF_PASSWORD=... diff-kdbx fingerprint \
    --params 'argon2id$v=19$m=65536,t=3,p=1' \
    --salt 133fb32a-2e9c-4281-b9fc-f462745668bc \
    --field PIN --entry /Bank vault.kdbx
# prints 3671f5b9...; equal to the event's fingerprint when the field still
# holds the value that was revealed
```

`--entry` takes the event's `target_uuid` too (stable across renames), and
`--key-file` adds a key file. Without `--params` and `--salt`, diff-kdbx uses
the vault's own, which is what mcp-kdbx used unless the vault's KDF or root
group changed since. The subcommand covers fields; there is no attachment
counterpart yet. One mismatch to know: mcp-kdbx always includes the password
in the key material (an empty password is the empty string), while diff-kdbx
treats an empty password next to a key file as "no password", so a session
unlocked with an empty password and a key file cannot be verified this way.

### Log levels and what they capture

`info` (the default) captures lifecycle, reveal, and write events: the security-
relevant trail. `warn` and `error` capture only failures. `debug` adds internal
diagnostics; `trace` additionally allows plaintext and must stay off in normal
use.

### Querying with jq

```sh
# Every reveal (password, protected field, attachment, otp)
jq 'select(.event | startswith("reveal") or . == "download_attachment" or . == "get_otp")' audit.jsonl

# Count events by type
jq -r .event audit.jsonl | sort | uniq -c | sort -rn

# Failed unlock attempts
jq 'select(.event == "auth_failed")' audit.jsonl

# Everything that touched a specific entry
jq 'select(.details.target_path == "/Bank")' audit.jsonl

# Saves that were refused due to an external modification
jq 'select(.event == "save_refused")' audit.jsonl
```

### Rotation

The server opens the log file in append mode and holds the descriptor for its
lifetime. A spawned-per-session server is short-lived, so rotation rarely
matters, but for a long-running host use `logrotate` in `copytruncate` mode so
the open descriptor keeps writing to the same inode:

```
/home/you/.local/state/mcp-kdbx/*.jsonl {
    weekly
    rotate 8
    compress
    missingok
    notifempty
    copytruncate
}
```

Plain `create` mode (rename then recreate) would leave the running server
writing to the rotated-away file. The log file is created with `0600`
permissions; keep it on a private path.

## Save temp files and orphan cleanup

Saves are atomic: the new vault is written to a temp file in the vault's
directory, fsynced, then renamed over the original. A crash mid-save can leave a
`*.tmp.<pid>.*` file beside the vault. Set `KDBX_AUTO_CLEAN_ORPHANS=true` to have
the server remove stale ones (older than one hour) at startup, or delete them by
hand. The cleanup is off by default so the server never removes a file it did not
create without being asked.

## Recommended posture for cautious users

From the spec's threat model:

1. Use `KDBX_UNLOCK_CMD` rather than `KDBX_PASSWORD`, so the master password is
   never sitting in a config file or the process environment.
2. Set `KDBX_LOG_FILE` to a private path (the file is created `0600`).
3. Set `KDBX_IDLE_TIMEOUT_SECONDS=300` (5 minutes) if you want a tighter window;
   the default 900 suits typical use.
4. Leave `KDBX_ALLOW_WRITES` unset unless an agent genuinely needs to write, and
   keep a backup of any vault you do enable writes on.
5. Run one `mcp-kdbx` per vault, in a per-vault host config entry.
6. Periodically grep the audit log for reveal events you did not expect:
   `jq 'select(.event | startswith("reveal"))' audit.jsonl`.

What this does not defend against: a host or agent you have already unlocked for
can read any entry while the vault is unlocked, and an attacker who can run
arbitrary code as your user can read process memory. mcp-kdbx narrows the blast
radius (consent per reveal, an audit trail, idle lock, writes off by default); it
does not replace OS-level isolation.
