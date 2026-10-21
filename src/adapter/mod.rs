//! The MCP adapter: wraps `engine` and speaks MCP over stdio via rmcp.
//!
//! This is the only layer that knows about MCP. It owns the shared vault state
//! and the audit log, defines the tool surface, converts tool inputs into core
//! calls, and wraps core results in the `{ ok, data } | { ok, error }` envelope
//! (see [`responses`]). The dependency direction is one way: the adapter
//! depends on `engine`, never the reverse, so a future HTTP adapter could
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

use crate::engine::address::EntryAddress;
use crate::engine::audit::{AuditEvent, AuditLog, fingerprints_recorded};
use crate::engine::config::Config;
use crate::engine::error::{CoreError, CoreResult, ErrorCode};
use crate::engine::secret::Secret;
use crate::engine::vault::{AuditFingerprints, Vault};
use crate::engine::view::View;
use keepass::Database;
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
        // The stable audit key exists only for audit-file fingerprints, so it
        // is derived (one Argon2 run per unlock) exactly when an audit file is
        // configured and the log level records the events that carry them.
        let audit_fingerprints = if fingerprints_recorded(&audit, config.log_level) {
            AuditFingerprints::Keyed
        } else {
            AuditFingerprints::Off
        };
        let vault =
            Vault::new(config.vault_path.clone()).with_audit_fingerprints(audit_fingerprints);
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
    /// 2: any tool call, including status, is a keep-alive). The idle deadline
    /// is applied first: the timer only ticks every few seconds, and a call past
    /// the deadline must find the vault locked rather than reset the clock.
    pub(crate) async fn vault(&self) -> MutexGuard<'_, Vault> {
        let mut guard = self.state.lock().await;
        let timeout = std::time::Duration::from_secs(self.config.idle_timeout_seconds);
        if let Some(dropped) = guard.lock_if_idle(std::time::Instant::now(), timeout) {
            self.emit_idle_lock(dropped);
        }
        guard.touch();
        guard
    }

    fn emit_idle_lock(&self, dropped: usize) {
        self.emit(AuditEvent::VaultLocked {
            reason: crate::engine::vault::LockReason::IdleTimeout,
            pending_discarded_count: dropped as u64,
        });
    }

    /// Emit an audit event, subject to the configured log level. An event whose
    /// level is more verbose than `KDBX_LOG_LEVEL` is suppressed, which is the
    /// mechanism the spec points cautious users at ("disable info-level logging
    /// by setting KDBX_LOG_LEVEL=warn"). Reveal and write events are info level,
    /// so they appear by default and can be silenced only deliberately.
    pub(crate) fn emit(&self, event: AuditEvent) {
        // Level's derived order is verbosity order (least verbose first).
        if event.level() <= self.config.log_level {
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
            let dropped = self
                .state
                .lock()
                .await
                .lock_if_idle(Instant::now(), timeout);
            // The guard is a temporary, so the audit write is off the lock.
            if let Some(dropped) = dropped {
                self.emit_idle_lock(dropped);
            }
        }
    }
}

/// The server instructions sent at initialize: what the server is, the path
/// grammar every path parameter uses, and how to unlock without putting the
/// master password in the conversation. The grammar lives here once rather than
/// in every tool description.
const SERVER_INSTRUCTIONS: &str = "mcp-kdbx exposes a single KeePass KDBX vault. \
Read groups and entries and find by title, username, or url with the list and find tools; \
protected fields and attachments require a separate consent-gated reveal. Writes (when \
enabled) are staged in memory and committed atomically with kdbx_save_pending.\n\n\
Paths: every path has a leading '/' (the root group is '/'), and '/' separates group names \
from the entry title, as in /Web/Banking/MyBank. Inside a name, write a literal '/' as \\/, \
a literal backslash as \\\\, and a literal ':' before digits as \\:; a control character \
appears as \\n, \\t, \\r or \\u{XXXX}, and any other backslash escape is invalid. When \
siblings share a name, ':N' picks the Nth (1-based), as in /Web/MyBank:2. A trailing '/' \
names a group, never an entry, and group paths in tool output always end in '/'. Copy paths verbatim from tool output; ordinals can shift between sessions, so \
for a stable reference pass the entry's or group's uuid (every read returns it) instead of \
its path. A record whose path is null has no addressable path: use its uuid.\n\n\
Unlocking: call kdbx_unlock with no arguments; the server reads the master password from \
its configured KDBX_PASSWORD or KDBX_UNLOCK_CMD. Do not ask the user to type the master \
password into the chat.";

/// The vault's cached [`View`] of the working db. When it must be captured
/// first, the capture runs in `block_in_place`: it fingerprints every
/// attachment, which takes a while for large ones, and must not stall the
/// async worker. A cached view returns directly.
pub(crate) fn view_of(vault: &Vault) -> CoreResult<&View> {
    if vault.has_cached_view() {
        vault.view()
    } else {
        tokio::task::block_in_place(|| vault.view())
    }
}

/// The working db and its [`View`] (see [`view_of`]), for tools that resolve
/// an address against the view and then read the live record.
pub(crate) fn working_db_and_view_of(vault: &Vault) -> CoreResult<(&Database, &View)> {
    let view = view_of(vault)?;
    Ok((vault.working_db()?, view))
}

/// Locate the entry an entry-targeting tool names, by vault path or by UUID
/// (exactly one; see [`EntryAddress::from_parts`]). `path_param` is the tool's
/// path parameter name (`path` or `entry_path`), echoed in the error message.
///
/// Every entry tool resolves its target through here, so path and UUID
/// addressing behave identically across reads, reveals, and writes.
pub(crate) fn locate_entry<'a>(
    db: &'a keepass::Database,
    view: &View,
    path: Option<&str>,
    uuid: Option<&str>,
    path_param: &str,
) -> Result<keepass::db::EntryRef<'a>, CoreError> {
    let id = EntryAddress::from_parts(path, uuid, path_param)?.resolve(db, view)?;
    db.entry(id)
        .ok_or_else(|| CoreError::new(ErrorCode::EntryNotFound))
}

/// The canonical vault path of `entry`, or `None` when it has no addressable
/// path. Audit events and responses report this rather than echoing the
/// caller's input, so they name the record actually touched.
pub(crate) fn canonical_entry_path(
    view: &View,
    entry: &keepass::db::EntryRef<'_>,
) -> Option<String> {
    view.path_string(entry.id().uuid())
}

/// Tool inputs wrap secret values in [`Secret`]; their JSON Schema is the inner
/// type's, unchanged, so the wire contract an MCP host sees does not move.
/// (Implemented here, not in `engine`, which stays free of the rmcp/schemars
/// dependency.)
impl<T> rmcp::schemars::JsonSchema for Secret<T>
where
    T: zeroize::Zeroize + rmcp::schemars::JsonSchema,
{
    fn inline_schema() -> bool {
        T::inline_schema()
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        T::schema_name()
    }

    fn schema_id() -> std::borrow::Cow<'static, str> {
        T::schema_id()
    }

    fn json_schema(generator: &mut rmcp::schemars::SchemaGenerator) -> rmcp::schemars::Schema {
        T::json_schema(generator)
    }
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for KdbxServer {
    fn get_info(&self) -> ServerInfo {
        let mut info = ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_instructions(SERVER_INSTRUCTIONS);
        // Report mcp-kdbx as the server, not rmcp's default implementation name.
        // Implementation::from_build_env expands env!("CARGO_CRATE_NAME") inside
        // the rmcp crate, so it would report "rmcp" and rmcp's version, not ours.
        // Build the identity explicitly from this crate's own build env instead.
        // ServerInfo is non-exhaustive, so set the field after construction.
        info.server_info = Implementation::new(env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
        info
    }
}

#[cfg(test)]
mod tests {
    use crate::engine::{config::Config, stage};
    use kdbx_core::otp::TotpConfig;

    /// A value that must never appear in any Debug rendering below.
    const MARK: &str = "SECRET-MARK-7f3a";

    fn assert_redacted(what: &str, rendered: String) {
        assert!(
            !rendered.contains(MARK),
            "{what} Debug leaked the secret: {rendered}"
        );
    }

    #[test]
    fn every_secret_bearing_type_redacts_debug() {
        // Tool inputs, built from the JSON an agent would send.
        let add: super::writes::AddEntryParams = serde_json::from_value(serde_json::json!({
            "group_path": "/",
            "title": "T",
            "fields": { "Password": { "value": MARK, "protected": true } },
            "attachments": { "a.bin": { "base64": MARK } },
        }))
        .unwrap();
        assert_redacted("AddEntryParams", format!("{add:?}"));
        let update: super::writes::UpdateFieldParams = serde_json::from_value(serde_json::json!({
            "path": "/T", "field_name": "Password", "value": MARK,
        }))
        .unwrap();
        assert_redacted("UpdateFieldParams", format!("{update:?}"));
        let unlock: super::lifecycle::UnlockParams = serde_json::from_value(serde_json::json!({
            "password": MARK, "keyfile_bytes": MARK,
        }))
        .unwrap();
        assert_redacted("UnlockParams", format!("{unlock:?}"));

        // Core types that carry the same values onward.
        let entry = stage::EntryInput {
            title: "T".to_string(),
            fields: vec![stage::FieldInput {
                name: "Password".to_string(),
                value: MARK.to_string().into(),
                protected: true,
            }],
            attachments: vec![stage::AttachmentInput {
                name: "a.bin".to_string(),
                bytes: MARK.as_bytes().to_vec().into(),
            }],
        };
        assert_redacted("EntryInput", format!("{entry:?}"));
        let totp = TotpConfig::from_uri("otpauth://totp/X?secret=JBSWY3DPEHPK3PXP").unwrap();
        let rendered = format!("{totp:?}");
        assert!(rendered.contains("<redacted>"), "TotpConfig: {rendered}");
        let code = totp.code_at(59);
        assert!(!format!("{code:?}").contains(code.code()));
        let config = Config {
            password: Some(MARK.to_string().into()),
            unlock_cmd: Some(MARK.to_string().into()),
            ..Config::default()
        };
        assert_redacted("Config", format!("{config:?}"));
    }

    #[test]
    fn the_audit_key_is_derived_only_with_an_audit_file_that_records_reveals() {
        use crate::adapter::KdbxServer;
        use crate::engine::audit::{AuditLog, Level};
        use crate::engine::vault::AuditFingerprints;
        let keyed = |file: bool, log_level: Level| {
            let config = Config {
                log_level,
                ..Config::default()
            };
            let audit = AuditLog::new(file.then(|| tempfile::tempfile().unwrap()));
            let server = KdbxServer::new(config, audit);
            let vault = server.state.try_lock().unwrap();
            vault.audit_fingerprints()
        };
        assert_eq!(keyed(true, Level::Info), AuditFingerprints::Keyed);
        assert_eq!(keyed(true, Level::Debug), AuditFingerprints::Keyed);
        // KDBX_LOG_LEVEL=warn records no reveal event, so no Argon2 run.
        assert_eq!(keyed(true, Level::Warn), AuditFingerprints::Off);
        assert_eq!(keyed(false, Level::Info), AuditFingerprints::Off);
    }
}
