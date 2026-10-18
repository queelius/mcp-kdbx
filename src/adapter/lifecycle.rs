//! Lifecycle tools: `kdbx_status`, `kdbx_unlock`, `kdbx_lock`.
//!
//! These manage the locked/unlocked transition and report status. `kdbx_unlock`
//! is the only tool that handles the master password; it resolves the password
//! through `kdbx_core::unlock` (tool input, then `KDBX_PASSWORD`, then
//! `KDBX_UNLOCK_CMD`), never logs it, and emits `vault_unlocked` or
//! `auth_failed` to the audit trail.

use crate::adapter::views::format_system_time;
use crate::adapter::{KEEPASS_RS_VERSION, KdbxServer, responses};
use crate::kdbx_core::audit::AuditEvent;
use crate::kdbx_core::error::{CoreError, ErrorCode};
use crate::kdbx_core::secret::Secret;
use crate::kdbx_core::unlock::resolve_unlock_source;
use crate::kdbx_core::vault::LockReason;
use base64::Engine;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::{schemars, tool, tool_router};
use std::time::{Duration, Instant};

/// Input for `kdbx_unlock`: an optional password and an optional base64 keyfile.
/// Both are [`Secret`]s, so the derived `Debug` shows only whether each was
/// supplied, never the value.
#[derive(Debug, serde::Deserialize, schemars::JsonSchema)]
pub struct UnlockParams {
    /// The master password. When omitted, the server resolves it from
    /// `KDBX_PASSWORD` or `KDBX_UNLOCK_CMD`.
    #[serde(default)]
    pub password: Option<Secret<String>>,
    /// An optional keyfile for two-factor unlock, base64-encoded.
    #[serde(default)]
    pub keyfile_bytes: Option<Secret<String>>,
}

#[tool_router(router = lifecycle_router, vis = "pub(crate)")]
impl KdbxServer {
    /// Lifecycle: report vault and server status. Available locked or not, and
    /// it counts as activity, so it doubles as an idle-timer keep-alive.
    #[tool(
        description = "Report vault and server status: locked state, vault name and path, idle-timeout remaining, pending changes, whether writes are allowed, last_lock (what the most recent lock discarded, until reported), and version info."
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
        // Seconds until the idle timer would lock the vault if no further tool
        // call arrives. None when locked or when idle lock is disabled
        // (KDBX_IDLE_TIMEOUT_SECONDS=0), both of which serialize to null per the
        // spec. self.vault() above touched last_activity (status is a keep-alive),
        // so this reports the full window from now.
        let idle_remaining = vault.idle_remaining(
            Instant::now(),
            Duration::from_secs(self.config.idle_timeout_seconds),
        );

        responses::ok(serde_json::json!({
            "locked": locked,
            "vault_name": vault_name,
            "vault_path": self.config.vault_path.display().to_string(),
            "idle_timeout_remaining_seconds": idle_remaining,
            "has_pending_changes": has_pending,
            "writes_allowed": self.config.allow_writes,
            // What the most recent lock discarded, until an unlock or a
            // VAULT_LOCKED error reports it. Peeked, not consumed.
            "last_lock": vault.last_lock(),
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
        // result is zeroized on drop and never logged. resolve_unlock_source
        // returns the source it actually used, so the audit label cannot drift
        // from the resolution order.
        let (password, source) = match resolve_unlock_source(
            params.password.as_ref().map(|p| p.expose().as_str()),
            &self.config,
        )
        .await
        {
            Ok(resolved) => resolved,
            Err(e) => {
                if e.code_enum() == ErrorCode::AuthFailed {
                    // The source the command path tried; resolution failed
                    // before returning one, so label it "cmd" (the only
                    // source that can fail with AUTH_FAILED here).
                    self.emit(AuditEvent::AuthFailed {
                        source: "cmd".to_string(),
                        error_code: e.code().to_string(),
                    });
                }
                return responses::err(&e);
            }
        };
        let source_label = source.as_str().to_string();

        // Resolve the keyfile: the per-call keyfile_bytes wins; otherwise fall
        // back to the configured KDBX_KEYFILE_PATH (mirrors the password source
        // precedence). A malformed or unreadable keyfile is AUTH_FAILED and is
        // audited like the other failed-unlock paths.
        let keyfile = match resolve_keyfile_bytes(&params, &self.config) {
            Ok(bytes) => bytes,
            Err(e) => {
                if e.code_enum() == ErrorCode::AuthFailed {
                    self.emit(AuditEvent::AuthFailed {
                        source: source_label.clone(),
                        error_code: e.code().to_string(),
                    });
                }
                return responses::err(&e);
            }
        };

        // The KDF in Database::open is deliberately slow; run it off the async
        // worker (see kdbx_save_pending for the same pattern).
        let unlocked = tokio::task::block_in_place(|| vault.unlock(&password, keyfile.as_deref()));
        match unlocked {
            Ok(previous_lock) => {
                let file_mtime = vault
                    .mtime_at_unlock()
                    .ok()
                    .map(format_system_time)
                    .unwrap_or_default();
                self.emit(AuditEvent::VaultUnlocked {
                    unlock_source: source_label.clone(),
                    file_mtime,
                });
                let vault_name = vault
                    .working_db()
                    .ok()
                    .and_then(|db| db.meta.database_name.clone());
                // previous_lock: what the lock before this unlock discarded,
                // when no earlier call reported it (null otherwise).
                responses::ok(serde_json::json!({
                    "vault_name": vault_name,
                    "locked": false,
                    "has_pending_changes": false,
                    "previous_lock": previous_lock,
                }))
            }
            Err(e) => {
                if e.code_enum() == ErrorCode::AuthFailed {
                    self.emit(AuditEvent::AuthFailed {
                        source: source_label.clone(),
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

/// Resolve the keyfile bytes for an unlock, honoring source precedence: the
/// per-call `keyfile_bytes` (base64) wins, otherwise the configured
/// `KDBX_KEYFILE_PATH` is read from disk, otherwise there is no keyfile.
///
/// Either source failing (malformed base64, or an unreadable configured path)
/// is `AUTH_FAILED` with a clear message, which the caller audits like the other
/// failed-unlock paths. Returning a typed error here, rather than emitting,
/// keeps the audit emission in the tool body next to the password path.
fn resolve_keyfile_bytes(
    params: &UnlockParams,
    config: &crate::kdbx_core::config::Config,
) -> Result<Option<Vec<u8>>, CoreError> {
    if let Some(encoded) = params.keyfile_bytes.as_ref().map(|k| k.expose()) {
        return base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .map(Some)
            .map_err(|_| {
                CoreError::new(ErrorCode::AuthFailed)
                    .with_message("keyfile_bytes is not valid base64")
            });
    }
    match &config.keyfile_path {
        Some(path) => std::fs::read(path).map(Some).map_err(|io| {
            CoreError::new(ErrorCode::AuthFailed).with_message(format!(
                "could not read configured keyfile at {}: {io}",
                path.display()
            ))
        }),
        None => Ok(None),
    }
}
