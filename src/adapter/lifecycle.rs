//! Lifecycle tools: `kdbx_status`, `kdbx_unlock`, `kdbx_lock`.
//!
//! These manage the locked/unlocked transition and report status. `kdbx_unlock`
//! is the only tool that handles the master password; it resolves the password
//! through `kdbx_core::unlock` (tool input, then `KDBX_PASSWORD`, then
//! `KDBX_UNLOCK_CMD`), never logs it, and emits `vault_unlocked` or
//! `auth_failed` to the audit trail.

use crate::adapter::{KEEPASS_RS_VERSION, KdbxServer, responses};
use crate::kdbx_core::audit::AuditEvent;
use crate::kdbx_core::config::Config;
use crate::kdbx_core::error::{CoreError, ErrorCode};
use crate::kdbx_core::unlock::resolve_unlock_source;
use crate::kdbx_core::vault::LockReason;
use base64::Engine;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{schemars, tool, tool_router};
use std::time::SystemTime;

/// Input for `kdbx_unlock`: an optional password and an optional base64 keyfile.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct UnlockParams {
    /// The master password. When omitted, the server resolves it from
    /// `KDBX_PASSWORD` or `KDBX_UNLOCK_CMD`.
    #[serde(default)]
    pub password: Option<String>,
    /// An optional keyfile for two-factor unlock, base64-encoded.
    #[serde(default)]
    pub keyfile_bytes: Option<String>,
}

#[tool_router(router = lifecycle_router, vis = "pub(crate)")]
impl KdbxServer {
    /// Lifecycle: report vault and server status. Available locked or not, and
    /// it counts as activity, so it doubles as an idle-timer keep-alive.
    #[tool(
        description = "Report vault and server status: locked state, vault name and path, idle-timeout remaining, pending changes, whether writes are allowed, and version info."
    )]
    async fn kdbx_status(&self) -> String {
        let vault = self.vault().await;
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
        // The idle-timer task in main owns the countdown; report null here while
        // honoring the "null when locked" contract.
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

    /// Lifecycle: unlock the vault. Resolves the password from the tool input,
    /// `KDBX_PASSWORD`, or `KDBX_UNLOCK_CMD`, in that order.
    #[tool(
        description = "Unlock the vault so its contents can be read. Provide the master password, or rely on the server's configured password source. An optional base64 keyfile is accepted for two-factor unlock."
    )]
    async fn kdbx_unlock(&self, Parameters(params): Parameters<UnlockParams>) -> String {
        let mut vault = self.vault().await;
        if vault.is_unlocked() {
            return responses::err(&CoreError::new(ErrorCode::VaultAlreadyUnlocked));
        }

        // Resolve the password (tool input wins, then env, then command). The
        // result is zeroized on drop and never logged.
        let source = unlock_source_label(params.password.as_deref(), &self.config);
        let password = match resolve_unlock_source(params.password.as_deref(), &self.config).await {
            Ok(pw) => pw,
            Err(e) => {
                if e.code_enum() == ErrorCode::AuthFailed {
                    self.emit(AuditEvent::AuthFailed {
                        source: source.to_string(),
                        error_code: e.code().to_string(),
                    });
                }
                return responses::err(&e);
            }
        };

        // Decode the optional keyfile.
        let keyfile = match decode_keyfile(params.keyfile_bytes.as_deref()) {
            Ok(bytes) => bytes,
            Err(e) => return responses::err(&e),
        };

        match vault.unlock(&password, keyfile.as_deref()) {
            Ok(()) => {
                let file_mtime = vault
                    .mtime_at_unlock()
                    .ok()
                    .map(format_system_time)
                    .unwrap_or_default();
                self.emit(AuditEvent::VaultUnlocked {
                    unlock_source: source.to_string(),
                    file_mtime,
                });
                let vault_name = vault
                    .working_db()
                    .ok()
                    .and_then(|db| db.meta.database_name.clone());
                responses::ok(serde_json::json!({
                    "vault_name": vault_name,
                    "locked": false,
                    "has_pending_changes": false,
                }))
            }
            Err(e) => {
                if e.code_enum() == ErrorCode::AuthFailed {
                    self.emit(AuditEvent::AuthFailed {
                        source: source.to_string(),
                        error_code: e.code().to_string(),
                    });
                }
                responses::err(&e)
            }
        }
    }

    /// Lifecycle: lock the vault. Zeroes the key, drops the databases, and
    /// discards any staged changes.
    #[tool(
        description = "Lock the vault: zero the key in memory, drop the decrypted database, and discard any unsaved staged changes. The reported count is how many pending changes were dropped."
    )]
    async fn kdbx_lock(&self) -> String {
        let mut vault = self.vault().await;
        let pending_discarded = vault.lock(LockReason::Manual);
        self.emit(AuditEvent::VaultLocked {
            reason: "manual".to_string(),
            pending_discarded_count: pending_discarded as u64,
        });
        responses::ok(serde_json::json!({
            "locked": true,
            "pending_discarded": pending_discarded,
        }))
    }
}

/// Which password source `resolve_unlock_source` will use, for the audit event.
/// Mirrors that function's priority order (input, then env, then command).
fn unlock_source_label(input: Option<&str>, config: &Config) -> &'static str {
    if input.is_some() {
        "input"
    } else if config.password.is_some() {
        "env"
    } else if config.unlock_cmd.is_some() {
        "cmd"
    } else {
        // Unreachable when resolution succeeded; resolution returns
        // UNLOCK_SOURCE_MISSING before any unlock is attempted.
        "input"
    }
}

/// Decode the optional base64 keyfile. A malformed value is an AUTH_FAILED with
/// a clear reason rather than a generic decode error.
fn decode_keyfile(encoded: Option<&str>) -> Result<Option<Vec<u8>>, CoreError> {
    match encoded {
        None => Ok(None),
        Some(s) => base64::engine::general_purpose::STANDARD
            .decode(s)
            .map(Some)
            .map_err(|_| {
                CoreError::new(ErrorCode::AuthFailed)
                    .with_message("keyfile_bytes is not valid base64")
            }),
    }
}

/// Format a `SystemTime` as `YYYY-MM-DDTHH:MM:SSZ` (UTC).
fn format_system_time(time: SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Utc> = time.into();
    dt.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}
