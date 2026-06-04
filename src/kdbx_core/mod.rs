//! kdbx_core: vault logic with no MCP-protocol types.
//!
//! Audit invariant (from the v0.1 spec): nothing under this module imports
//! MCP-specific types, so the core stays reusable by a future serv-kdbx HTTP
//! adapter. The MCP adapter (Phase 3) lives in a sibling module and depends on
//! this one, never the reverse.
//!
//! Module map:
//! - `error`: the typed error set and protocol-facing carrier (`CoreError`).
//! - `config`: environment-variable configuration and validation.
//! - `path`: `VaultPath` parsing, formatting, and resolution against a database.
//! - `vault`: the locked/unlocked state machine over canonical and working dbs.
//! - `unlock`: master-password source resolution (input, env, command).
//! - `audit`: the JSONL audit-log events and sha256 reveal hashing.
//! - `totp`: otpauth URI parsing and TOTP code computation.
//! - `search`: substring entry search across configurable fields.
//! - `stage`: working-copy write operations, the diff-kdbx stage diff, and the
//!   atomic save (Phase 2).
//! - `orphan`: startup cleanup of leftover `*.tmp.*` save files (Phase 2).

pub mod audit;
pub mod config;
pub mod error;
pub mod orphan;
pub mod path;
pub mod search;
pub mod stage;
pub mod totp;
pub mod unlock;
pub mod vault;
