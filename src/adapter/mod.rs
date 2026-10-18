//! The MCP adapter: wraps `kdbx_core` and speaks MCP over stdio via rmcp.
//!
//! This is the only layer that knows about MCP. It owns the shared vault state
//! and the audit log, defines the tool surface, converts tool inputs into core
//! calls, and wraps core results in the `{ ok, data } | { ok, error }` envelope
//! (see [`responses`]). The dependency direction is one way: the adapter
//! depends on `kdbx_core`, never the reverse, so a future HTTP adapter could
//! reuse the core unchanged.
//!
//! The 17 tools are split by category across submodules, each a
//! `#[tool_router(router = ...)]` block over [`KdbxServer`]; [`KdbxServer::new`]
//! combines them into one router. The submodules share the helpers defined here
//! (locking, audit emission, the writes gate) and the view builders in
//! [`views`].

pub mod lifecycle;
pub mod reads;
pub mod responses;
pub mod reveals;
pub mod views;
pub mod writes;

use crate::kdbx_core::address::EntryAddress;
use crate::kdbx_core::audit::{AuditEvent, AuditLog};
use crate::kdbx_core::config::Config;
use crate::kdbx_core::error::{CoreError, ErrorCode};
use crate::kdbx_core::vault::Vault;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::{ServerHandler, tool_handler};
use std::sync::Arc;
use tokio::sync::{Mutex, MutexGuard};

/// The keepass-rs version mcp-kdbx is built against, reported in `kdbx_status`.
/// Tracks the version floor in Cargo.toml.
pub(crate) const KEEPASS_RS_VERSION: &str = "0.12";

/// The MCP server: shared vault state, config, and the audit log, plus the rmcp
/// tool router.
///
/// The handler is cloned by rmcp per connection, so the mutable vault lives
/// behind an `Arc<Mutex<...>>` and the immutable config and the audit log behind
/// `Arc`. The tokio mutex is held only across a single tool call.
#[derive(Clone)]
pub struct KdbxServer {
    tool_router: ToolRouter<Self>,
    state: Arc<Mutex<Vault>>,
    config: Arc<Config>,
    audit: Arc<AuditLog>,
}

impl KdbxServer {
    /// Build a server for the vault described by `config`, logging through
    /// `audit`. The vault starts locked; no file is read until the first
    /// `kdbx_unlock`.
    pub fn new(config: Config, audit: AuditLog) -> Self {
        let vault = Vault::new(config.vault_path.clone());
        Self {
            // Combine the per-category routers into one. Each submodule's
            // `#[tool_router(router = ..._router)]` block contributes its tools.
            tool_router: Self::lifecycle_router()
                + Self::reads_router()
                + Self::reveals_router()
                + Self::writes_router(),
            state: Arc::new(Mutex::new(vault)),
            config: Arc::new(config),
            audit: Arc::new(audit),
        }
    }

    /// The shared vault handle, for the idle-timer task in `main`.
    pub fn state(&self) -> Arc<Mutex<Vault>> {
        Arc::clone(&self.state)
    }

    /// The shared config, for the idle-timer task in `main`.
    pub fn config(&self) -> Arc<Config> {
        Arc::clone(&self.config)
    }

    /// The shared audit log, for the idle-timer task in `main`.
    pub fn audit(&self) -> Arc<AuditLog> {
        Arc::clone(&self.audit)
    }

    /// Lock the vault mutex and mark activity. Every tool call goes through here
    /// so the idle timer measures from the last real interaction (spec section
    /// 2: any tool call, including status, is a keep-alive).
    pub(crate) async fn vault(&self) -> MutexGuard<'_, Vault> {
        let mut guard = self.state.lock().await;
        guard.touch();
        guard
    }

    /// Emit an audit event, subject to the configured log level. An event whose
    /// level is more verbose than `KDBX_LOG_LEVEL` is suppressed, which is the
    /// mechanism the spec points cautious users at ("disable info-level logging
    /// by setting KDBX_LOG_LEVEL=warn"). Reveal and write events are info level,
    /// so they appear by default and can be silenced only deliberately.
    pub(crate) fn emit(&self, event: AuditEvent) {
        if verbosity(event.level().as_str()) <= verbosity(self.config.log_level.as_str()) {
            self.audit.write(&event);
        }
    }

    /// Whether write tools are enabled (`KDBX_ALLOW_WRITES=true`). The write
    /// tools call this first and return `WRITES_DISABLED` when it is false.
    pub(crate) fn writes_allowed(&self) -> bool {
        self.config.allow_writes
    }

    /// Emit the `server_started` audit event. Called once by `main` after the
    /// server is built, so the audit trail records the policy the process runs
    /// under (vault path, writes-allowed, idle timeout), never any secret.
    pub fn announce_start(&self) {
        self.emit(AuditEvent::ServerStarted {
            server_version: env!("CARGO_PKG_VERSION").to_string(),
            vault_path: self.config.vault_path.display().to_string(),
            writes_allowed: self.config.allow_writes,
            idle_timeout_seconds: self.config.idle_timeout_seconds,
        });
    }

    /// Run the idle-lock timer until the process ends. Periodically checks
    /// whether the vault has been idle past `KDBX_IDLE_TIMEOUT_SECONDS` and locks
    /// it if so, emitting `vault_locked`. A zero timeout disables idle locking
    /// (the task returns at once). `main` spawns this on a clone of the server.
    ///
    /// This locks the vault directly rather than through [`vault`](Self::vault),
    /// because checking for idleness must not itself count as activity.
    pub async fn run_idle_timer(self) {
        use std::time::{Duration, Instant};
        let timeout = Duration::from_secs(self.config.idle_timeout_seconds);
        if timeout.is_zero() {
            return;
        }
        // Check roughly ten times per timeout window, clamped to a sane range.
        let interval = (timeout / 10).clamp(Duration::from_secs(5), Duration::from_secs(60));
        loop {
            tokio::time::sleep(interval).await;
            let mut vault = self.state.lock().await;
            if vault.should_lock(Instant::now(), timeout) {
                let dropped = vault.lock(crate::kdbx_core::vault::LockReason::IdleTimeout);
                // Drop the guard before emitting so the audit write is off the
                // lock.
                drop(vault);
                self.emit(AuditEvent::VaultLocked {
                    reason: "idle_timeout".to_string(),
                    pending_discarded_count: dropped as u64,
                });
            }
        }
    }
}

/// Locate the entry an entry-targeting tool names, by vault path or by UUID
/// (exactly one; see [`EntryAddress::from_parts`]). `path_param` is the tool's
/// path parameter name (`path` or `entry_path`), echoed in the error message.
///
/// Every entry tool resolves its target through here, so path and UUID
/// addressing behave identically across reads, reveals, and writes.
pub(crate) fn locate_entry<'a>(
    db: &'a keepass::Database,
    path: Option<&str>,
    uuid: Option<&str>,
    path_param: &str,
) -> Result<keepass::db::EntryRef<'a>, CoreError> {
    let id = EntryAddress::from_parts(path, uuid, path_param)?.resolve(db)?;
    db.entry(id)
        .ok_or_else(|| CoreError::new(ErrorCode::EntryNotFound))
}

/// The canonical vault path of `entry`, or `None` when it has no addressable
/// path. Audit events and responses report this rather than echoing the
/// caller's input, so they name the record actually touched.
pub(crate) fn canonical_entry_path(
    db: &keepass::Database,
    entry: &keepass::db::EntryRef<'_>,
) -> Option<String> {
    crate::kdbx_core::path::vault_path_to_entry(db, entry.id()).map(|p| p.format())
}

/// Map a level name (`error`/`warn`/`info`/`debug`/`trace`) to a verbosity rank,
/// least verbose first. An event emits when its rank is at most the configured
/// level's rank. Both `audit::Level` and `config::LogLevel` render to these
/// names, so this one ranking covers the comparison without a second table.
fn verbosity(level: &str) -> u8 {
    match level {
        "error" => 0,
        "warn" => 1,
        "info" => 2,
        "debug" => 3,
        "trace" => 4,
        _ => 2,
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for KdbxServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(
                "mcp-kdbx exposes a single KeePass KDBX vault. Read groups and entries and find \
                 by title or url with the list and find tools; protected fields and attachments \
                 require a separate consent-gated reveal. Writes (when enabled) are staged in \
                 memory and committed atomically with kdbx_save_pending.",
            );
        // Report mcp-kdbx as the server, not rmcp's default implementation name.
        // Implementation::from_build_env expands env!("CARGO_CRATE_NAME") inside
        // the rmcp crate, so it would report "rmcp" and rmcp's version, not ours.
        // Build the identity explicitly from this crate's own build env instead.
        // ServerInfo is non-exhaustive, so set the field after construction.
        info.server_info = Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        info
    }
}
