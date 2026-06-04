//! Master-password source resolution (input, env, command).
//!
//! `kdbx_unlock` needs a master password before it can build a keepass
//! `DatabaseKey` and attempt decryption. There are three places that password
//! can come from, tried in a fixed priority order (spec section 2, "Unlock
//! sequence"):
//!
//! 1. The `password` argument passed to the tool call. A caller may override
//!    the configured source for a single unlock.
//! 2. `KDBX_PASSWORD` from the environment, surfaced here as `config.password`.
//! 3. `KDBX_UNLOCK_CMD` from the environment (`config.unlock_cmd`): a shell
//!    command whose trimmed stdout is the password. This is the secret-manager
//!    path (for example `pass show vault` or a cloud secret fetch). It runs via
//!    `/bin/sh -c`, bounded by `config.unlock_cmd_timeout_seconds`.
//!
//! If none of the three is available, there is nothing to unlock with, and the
//! caller gets [`ErrorCode::UnlockSourceMissing`].
//!
//! The resolved password is wrapped in [`zeroize::Zeroizing`] so its memory is
//! scrubbed when the value drops. The password is never logged here, and the
//! `KDBX_UNLOCK_CMD` text and its output are treated as secret (spec "Logging"
//! invariant: master password and unlock-command output never appear in any
//! log).
//!
//! Windows is out of scope for v0.1; the shell-out assumes a POSIX `/bin/sh`.

use std::process::Stdio;
use std::time::Duration;

use serde_json::json;
use zeroize::Zeroizing;

use crate::kdbx_core::config::Config;
use crate::kdbx_core::error::{CoreError, CoreResult, ErrorCode};

/// Resolve the master password from the first available source, in priority
/// order: the `input_password` argument, then `config.password`
/// (`KDBX_PASSWORD`), then the stdout of `config.unlock_cmd` (`KDBX_UNLOCK_CMD`).
///
/// Returns the password wrapped in [`Zeroizing`] so it is scrubbed on drop.
///
/// Errors:
/// - [`ErrorCode::AuthFailed`] when the unlock command exits non-zero (details
///   carry `{ source: "cmd", exit_code }`) or times out (details carry
///   `{ reason: "unlock_cmd_timeout" }`).
/// - [`ErrorCode::UnlockSourceMissing`] when no source is configured.
pub async fn resolve_unlock_source(
    input_password: Option<&str>,
    config: &Config,
) -> CoreResult<Zeroizing<String>> {
    // (a) An explicit per-call password wins over any configured source.
    if let Some(pw) = input_password {
        return Ok(Zeroizing::new(pw.to_string()));
    }

    // (b) KDBX_PASSWORD, injected directly into the environment.
    if let Some(pw) = config.password.as_deref() {
        return Ok(Zeroizing::new(pw.to_string()));
    }

    // (c) KDBX_UNLOCK_CMD: shell out to a secret manager and read its stdout.
    if let Some(cmd) = config.unlock_cmd.as_deref() {
        return run_unlock_cmd(cmd, config.unlock_cmd_timeout_seconds).await;
    }

    // (d) Nothing to unlock with.
    Err(CoreError::new(ErrorCode::UnlockSourceMissing))
}

/// Run the unlock command via `/bin/sh -c`, bounded by `timeout_seconds`, and
/// return its trimmed stdout as the password.
///
/// The command text and its output are secret: neither is included in any error
/// message or details payload. On a non-zero exit, the details carry only the
/// numeric exit code (or null when the process was killed by a signal and has
/// no code). On a timeout, the details name the reason without echoing the
/// command.
async fn run_unlock_cmd(cmd: &str, timeout_seconds: u64) -> CoreResult<Zeroizing<String>> {
    let mut command = tokio::process::Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let run = command.output();
    let timeout = Duration::from_secs(timeout_seconds);

    let output = match tokio::time::timeout(timeout, run).await {
        // The command finished within the window.
        Ok(Ok(output)) => output,
        // The command failed to spawn or to be waited on (for example, no
        // /bin/sh). Report AUTH_FAILED without leaking the command string.
        Ok(Err(e)) => {
            return Err(CoreError::new(ErrorCode::AuthFailed)
                .with_message("Unlock command failed to run.")
                .with_details(json!({
                    "source": "cmd",
                    "reason": "unlock_cmd_spawn_failed",
                    "io_error": e.kind().to_string(),
                })));
        }
        // The window elapsed before the command finished.
        Err(_elapsed) => {
            return Err(CoreError::new(ErrorCode::AuthFailed)
                .with_message("Unlock command timed out.")
                .with_details(json!({
                    "source": "cmd",
                    "reason": "unlock_cmd_timeout",
                    "timeout_seconds": timeout_seconds,
                })));
        }
    };

    if !output.status.success() {
        return Err(CoreError::new(ErrorCode::AuthFailed)
            .with_message("Unlock command exited non-zero.")
            .with_details(json!({
                "source": "cmd",
                // None when killed by a signal: serializes to JSON null.
                "exit_code": output.status.code(),
            })));
    }

    // Trim trailing whitespace and newline. A secret manager that prints the
    // password followed by a newline is the common case; trimming the end keeps
    // any internal characters intact while dropping the line terminator.
    let raw = String::from_utf8_lossy(&output.stdout);
    let trimmed = raw.trim_end();
    Ok(Zeroizing::new(trimmed.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `Config` whose secret sources are all unset, so each test can set just
    /// the field it exercises. Uses a 1-second command timeout so the timeout
    /// test does not stall the suite.
    fn base_config() -> Config {
        Config {
            password: None,
            unlock_cmd: None,
            unlock_cmd_timeout_seconds: 1,
            ..Config::default()
        }
    }

    #[tokio::test]
    async fn input_password_wins_over_env_and_cmd() {
        let mut cfg = base_config();
        // Both lower-priority sources are present, but the input must win.
        cfg.password = Some("from-env".to_string());
        cfg.unlock_cmd = Some("printf should-not-run".to_string());

        let pw = resolve_unlock_source(Some("from-input"), &cfg)
            .await
            .expect("input password resolves");
        assert_eq!(&*pw, "from-input");
    }

    #[tokio::test]
    async fn env_password_used_when_no_input() {
        let mut cfg = base_config();
        cfg.password = Some("env-secret".to_string());
        // A command is also configured, but the env password outranks it.
        cfg.unlock_cmd = Some("printf should-not-run".to_string());

        let pw = resolve_unlock_source(None, &cfg)
            .await
            .expect("env password resolves");
        assert_eq!(&*pw, "env-secret");
    }

    #[tokio::test]
    async fn unlock_cmd_stdout_is_trimmed() {
        let mut cfg = base_config();
        // printf emits no trailing newline, but the resolver trims either way.
        // Use echo to confirm the trailing newline is stripped.
        cfg.unlock_cmd = Some("echo secretpw".to_string());

        let pw = resolve_unlock_source(None, &cfg)
            .await
            .expect("command password resolves");
        assert_eq!(&*pw, "secretpw");
    }

    #[tokio::test]
    async fn unlock_cmd_printf_has_no_newline_to_trim() {
        let mut cfg = base_config();
        cfg.unlock_cmd = Some("printf secretpw".to_string());

        let pw = resolve_unlock_source(None, &cfg)
            .await
            .expect("command password resolves");
        assert_eq!(&*pw, "secretpw");
    }

    #[tokio::test]
    async fn nonzero_exit_is_auth_failed_with_exit_code() {
        let mut cfg = base_config();
        cfg.unlock_cmd = Some("exit 3".to_string());

        let err = resolve_unlock_source(None, &cfg)
            .await
            .expect_err("non-zero exit should fail");
        assert_eq!(err.code_enum(), ErrorCode::AuthFailed);

        let details = err.details().expect("details present");
        assert_eq!(details["source"], json!("cmd"));
        assert_eq!(details["exit_code"], json!(3));
    }

    #[tokio::test]
    async fn timeout_is_auth_failed_with_reason() {
        let mut cfg = base_config();
        // The command sleeps well past the 1-second timeout from base_config.
        cfg.unlock_cmd = Some("sleep 5".to_string());
        cfg.unlock_cmd_timeout_seconds = 1;

        let err = resolve_unlock_source(None, &cfg)
            .await
            .expect_err("slow command should time out");
        assert_eq!(err.code_enum(), ErrorCode::AuthFailed);

        let details = err.details().expect("details present");
        assert_eq!(details["reason"], json!("unlock_cmd_timeout"));
    }

    #[tokio::test]
    async fn no_source_is_unlock_source_missing() {
        let cfg = base_config();
        let err = resolve_unlock_source(None, &cfg)
            .await
            .expect_err("no source should fail");
        assert_eq!(err.code_enum(), ErrorCode::UnlockSourceMissing);
    }

    #[tokio::test]
    async fn empty_input_password_is_still_used() {
        // An explicitly empty string is a present source: it short-circuits
        // before the env and command paths. Whether it decrypts is the unlock
        // step's concern, not this resolver's.
        let mut cfg = base_config();
        cfg.password = Some("env-secret".to_string());

        let pw = resolve_unlock_source(Some(""), &cfg)
            .await
            .expect("empty input password resolves");
        assert_eq!(&*pw, "");
    }
}
