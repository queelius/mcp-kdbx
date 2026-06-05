//! The MCP adapter: wraps `kdbx_core` and speaks MCP over stdio via rmcp.
//!
//! This is the only layer that knows about MCP. It owns the shared vault state,
//! defines the tool surface, converts tool inputs into core calls, and wraps
//! core results in the `{ ok, data } | { ok, error }` envelope (see
//! [`responses`]). The dependency direction is one way: the adapter depends on
//! `kdbx_core`, never the reverse, so a future HTTP adapter could reuse the core
//! unchanged.
//!
//! Phase 3 is in progress. This currently wires the rmcp server and the
//! `kdbx_status` lifecycle tool; the remaining tools land as the phase
//! continues.

pub mod responses;

use crate::kdbx_core::config::Config;
use crate::kdbx_core::vault::Vault;
use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::model::{Implementation, ServerCapabilities, ServerInfo};
use rmcp::{ServerHandler, tool, tool_handler, tool_router};
use std::sync::Arc;
use tokio::sync::Mutex;

/// The keepass-rs version mcp-kdbx is built against, reported in `kdbx_status`.
/// Sourced from the dependency tree at build time would be ideal; for now it
/// tracks the version floor in Cargo.toml.
const KEEPASS_RS_VERSION: &str = "0.12";

/// The MCP server: shared vault state plus the rmcp tool router.
///
/// The handler is cloned by rmcp per connection, so the mutable vault lives
/// behind an `Arc<Mutex<...>>` and the immutable config behind an `Arc`. The
/// tokio mutex is held only across a single tool call.
#[derive(Clone)]
pub struct KdbxServer {
    tool_router: ToolRouter<Self>,
    state: Arc<Mutex<Vault>>,
    config: Arc<Config>,
}

impl KdbxServer {
    /// Build a server for the vault described by `config`. The vault starts
    /// locked; no file is read until the first `kdbx_unlock`.
    pub fn new(config: Config) -> Self {
        let vault = Vault::new(config.vault_path.clone());
        Self {
            tool_router: Self::tool_router(),
            state: Arc::new(Mutex::new(vault)),
            config: Arc::new(config),
        }
    }
}

#[tool_router]
impl KdbxServer {
    /// Lifecycle: report vault and server status. Always available, locked or
    /// not. Reading status counts as activity, so it doubles as an idle-timer
    /// keep-alive (spec section 2).
    #[tool(
        description = "Report vault and server status: locked state, vault name and path, idle-timeout remaining, pending changes, whether writes are allowed, and version info."
    )]
    async fn kdbx_status(&self) -> String {
        let mut vault = self.state.lock().await;
        vault.touch();

        let locked = !vault.is_unlocked();
        let vault_name = if locked {
            None
        } else {
            vault
                .working_db()
                .ok()
                .and_then(|db| db.meta.database_name.clone())
        };
        let has_pending = if locked {
            None
        } else {
            Some(vault.has_pending_changes())
        };
        // Idle remaining is computed by the Phase 3 timer wiring; report null
        // for now when unlocked, matching the "null if locked" contract while
        // the timer task is not yet attached.
        let idle_remaining: Option<u64> = None;

        responses::ok(serde_json::json!({
            "locked": locked,
            "vault_name": vault_name,
            "vault_path": self.config.vault_path.display().to_string(),
            "idle_timeout_remaining_seconds": idle_remaining,
            "has_pending_changes": has_pending,
            "writes_allowed": self.config.allow_writes,
            "server_version": env!("CARGO_PKG_VERSION"),
            "keepass_rs_version": KEEPASS_RS_VERSION,
        }))
    }
}

// Point the handler at the cached `tool_router` field (built once in `new`)
// rather than the default `Self::tool_router()`, which would rebuild the router
// on every call.
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
        // from_build_env reads CARGO_PKG_NAME and CARGO_PKG_VERSION. ServerInfo
        // is non-exhaustive, so set the field after construction.
        info.server_info = Implementation::from_build_env();
        info
    }
}
