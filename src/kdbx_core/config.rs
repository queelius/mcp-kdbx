//! Environment-variable configuration and validation.
//!
//! v0.1 takes all configuration from `KDBX_*` environment variables (spec
//! section 2 "Configuration surface" and section 5 "Configuration"). There are
//! no CLI flags and no config file, so there is a single source and no
//! precedence rules to reason about.
//!
//! Two error surfaces live in this crate, and they are deliberately separate:
//!
//! - [`crate::kdbx_core::error::CoreError`] is the per-tool-call surface. It
//!   maps onto the MCP protocol error envelope and is recoverable: a bad tool
//!   call returns an error, the server keeps running.
//! - [`ConfigError`] (defined here) is fatal startup configuration. A bad
//!   environment means the server cannot run at all, so `main` reports it to
//!   stderr and exits non-zero. It never reaches the protocol.
//!
//! Validation is stricter than typical env-var parsing (spec section 5):
//! boolean flags must be exactly `"true"` or absent, integers parse within
//! explicit ranges, the log level is one of five names, and the vault path must
//! resolve to an existing, readable file. The intent is to fail loudly at
//! startup rather than silently mis-configure (for example, a typo'd
//! `KDBX_ALLOW_WRITES=yes` must not quietly leave writes disabled while the
//! operator believes they enabled them).
//!
//! [`Config::from_map`] is the testable core: it takes a `HashMap` of
//! variables and never touches global process state.
//! [`Config::from_env`] reads `std::env` into such a map and delegates, so the
//! tests below stay free of global env mutation.

use std::collections::HashMap;
use std::path::PathBuf;

use thiserror::Error;

use crate::kdbx_core::secret::Secret;

/// Upper bound for the two integer settings, in seconds. 86400 is one day,
/// which is far beyond any sane idle window or secret-manager round trip while
/// still rejecting obvious overflow or garbage values.
const MAX_SECONDS: u64 = 86_400;

/// The verbosity levels accepted by `KDBX_LOG_LEVEL`, ordered least to most
/// verbose. The wire/config names are the lowercase variant names; parsing is
/// case-sensitive to keep the contract unambiguous.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    Error,
    Warn,
    /// The default level. Captures lifecycle and reveal events (spec section 5
    /// defaults rationale).
    #[default]
    Info,
    Debug,
    Trace,
}

impl LogLevel {
    /// The stable config string for this level.
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Error => "error",
            LogLevel::Warn => "warn",
            LogLevel::Info => "info",
            LogLevel::Debug => "debug",
            LogLevel::Trace => "trace",
        }
    }

    /// Parse one of the five accepted level names. Anything else is rejected so
    /// a misspelled level does not silently fall back to a default.
    fn parse(raw: &str) -> Result<Self, ConfigError> {
        match raw {
            "error" => Ok(LogLevel::Error),
            "warn" => Ok(LogLevel::Warn),
            "info" => Ok(LogLevel::Info),
            "debug" => Ok(LogLevel::Debug),
            "trace" => Ok(LogLevel::Trace),
            other => Err(ConfigError::InvalidLogLevel {
                value: other.to_string(),
            }),
        }
    }
}

/// A fatal startup-configuration error.
///
/// Each variant carries enough context for a clear stderr message. These are
/// never returned from a tool call: they are produced once, while reading the
/// environment, and they end the process.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// `KDBX_VAULT_PATH` was not set. It is the one required variable.
    #[error("KDBX_VAULT_PATH is required but was not set")]
    MissingVaultPath,

    /// `KDBX_VAULT_PATH` was set but the file does not exist or could not be
    /// stat'd (for example, a missing parent directory or a permissions
    /// problem).
    #[error("KDBX_VAULT_PATH {path} does not exist or is not readable: {reason}")]
    VaultPathUnreadable { path: String, reason: String },

    /// `KDBX_VAULT_PATH` resolves to something that is not a regular file (for
    /// example, a directory).
    #[error("KDBX_VAULT_PATH {path} is not a regular file")]
    VaultPathNotAFile { path: String },

    /// A strict-boolean variable held a value other than exactly `"true"`.
    /// Values like `"yes"`, `"1"`, or `"TRUE"` are rejected on purpose.
    #[error("{var} must be exactly \"true\" or unset, got {value:?}")]
    InvalidBool { var: &'static str, value: String },

    /// An integer variable did not parse as a base-10 unsigned integer.
    #[error("{var} must be an integer, got {value:?}")]
    InvalidInteger { var: &'static str, value: String },

    /// An integer variable parsed but fell outside its allowed range.
    #[error("{var} must be within {min}..={max}, got {value}")]
    IntegerOutOfRange {
        var: &'static str,
        value: u64,
        min: u64,
        max: u64,
    },

    /// `KDBX_LOG_LEVEL` was not one of error, warn, info, debug, trace.
    #[error("KDBX_LOG_LEVEL must be one of error, warn, info, debug, trace, got {value:?}")]
    InvalidLogLevel { value: String },
}

/// The fully validated server configuration, derived from the environment at
/// startup. Every field corresponds to one row of the spec section 2
/// configuration surface.
///
/// The two secret fields, `password` and `unlock_cmd`, are [`Secret`]s, so the
/// derived `Debug` shows only whether each is set, never its value: a stray
/// `tracing::debug!(?config)` cannot leak the master password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Absolute path to the .kdbx vault. Required, and validated to exist and
    /// be a readable regular file.
    pub vault_path: PathBuf,

    /// Optional keyfile for two-factor unlock (`KDBX_KEYFILE_PATH`). Presence
    /// is recorded here; the keyfile is read later, during unlock.
    pub keyfile_path: Option<PathBuf>,

    /// Master password from `KDBX_PASSWORD`, if injected directly. This is a
    /// secret: it is never logged and never echoed by `kdbx_status`.
    pub password: Option<Secret<String>>,

    /// Shell command whose stdout is the master password (`KDBX_UNLOCK_CMD`).
    /// Also a secret source: not logged, not echoed.
    pub unlock_cmd: Option<Secret<String>>,

    /// Timeout for the unlock command, in seconds
    /// (`KDBX_UNLOCK_CMD_TIMEOUT_SECONDS`). Default 30.
    pub unlock_cmd_timeout_seconds: u64,

    /// Whether write tools are enabled (`KDBX_ALLOW_WRITES`). Off unless the
    /// variable is exactly `"true"`.
    pub allow_writes: bool,

    /// Idle auto-lock window in seconds (`KDBX_IDLE_TIMEOUT_SECONDS`). Default
    /// 900 (15 minutes). A value of 0 means no idle lock.
    pub idle_timeout_seconds: u64,

    /// Whether to clean orphan `*.tmp.*` files at startup
    /// (`KDBX_AUTO_CLEAN_ORPHANS`). Off unless exactly `"true"`.
    pub auto_clean_orphans: bool,

    /// Log verbosity (`KDBX_LOG_LEVEL`). Default info.
    pub log_level: LogLevel,

    /// Append-only audit log path (`KDBX_LOG_FILE`). When unset, logs go to
    /// stderr only.
    pub log_file: Option<PathBuf>,
}

impl Config {
    /// Build a [`Config`] from a map of variable names to values, validating
    /// every field per spec section 5. This is the testable core: it does not
    /// read or mutate any global state.
    ///
    /// An absent key is treated the same as an unset environment variable. A
    /// key whose value is the empty string is treated as present-but-empty,
    /// which matters for the strict-boolean rules (an empty string is not
    /// `"true"`, so it leaves the flag disabled) and for `KDBX_LOG_FILE`
    /// (empty means stderr only, the same as unset).
    pub fn from_map(vars: &HashMap<String, String>) -> Result<Config, ConfigError> {
        let vault_path_raw = vars
            .get("KDBX_VAULT_PATH")
            .filter(|v| !v.is_empty())
            .ok_or(ConfigError::MissingVaultPath)?;
        let vault_path = resolve_vault_path(vault_path_raw)?;

        let keyfile_path = optional_path(vars, "KDBX_KEYFILE_PATH");
        let password = optional_string(vars, "KDBX_PASSWORD").map(Secret::new);
        let unlock_cmd = optional_string(vars, "KDBX_UNLOCK_CMD").map(Secret::new);

        let unlock_cmd_timeout_seconds =
            parse_seconds(vars, "KDBX_UNLOCK_CMD_TIMEOUT_SECONDS", 30, 1, MAX_SECONDS)?;

        let allow_writes = parse_strict_bool(vars, "KDBX_ALLOW_WRITES")?;

        // Idle accepts 0 (no idle lock), so its floor is 0, not 1.
        let idle_timeout_seconds =
            parse_seconds(vars, "KDBX_IDLE_TIMEOUT_SECONDS", 900, 0, MAX_SECONDS)?;

        let auto_clean_orphans = parse_strict_bool(vars, "KDBX_AUTO_CLEAN_ORPHANS")?;

        let log_level = match vars.get("KDBX_LOG_LEVEL").filter(|v| !v.is_empty()) {
            Some(raw) => LogLevel::parse(raw)?,
            None => LogLevel::default(),
        };

        let log_file = optional_path(vars, "KDBX_LOG_FILE");

        Ok(Config {
            vault_path,
            keyfile_path,
            password,
            unlock_cmd,
            unlock_cmd_timeout_seconds,
            allow_writes,
            idle_timeout_seconds,
            auto_clean_orphans,
            log_level,
            log_file,
        })
    }

    /// Read the process environment into a map and delegate to
    /// [`Config::from_map`]. This is the only function here that touches global
    /// state, which keeps the validation logic unit-testable without mutating
    /// `std::env`.
    pub fn from_env() -> Result<Config, ConfigError> {
        let vars: HashMap<String, String> = std::env::vars().collect();
        Config::from_map(&vars)
    }
}

impl Default for Config {
    /// A configuration with sane defaults and a placeholder vault path, for use
    /// in tests that need a `Config` but do not exercise path validation. The
    /// `vault_path` here is a dummy and is not checked for existence: construct
    /// via [`Config::from_map`] when path validation matters.
    fn default() -> Self {
        Config {
            vault_path: PathBuf::from("/nonexistent/dummy.kdbx"),
            keyfile_path: None,
            password: None,
            unlock_cmd: None,
            unlock_cmd_timeout_seconds: 30,
            allow_writes: false,
            idle_timeout_seconds: 900,
            auto_clean_orphans: false,
            log_level: LogLevel::Info,
            log_file: None,
        }
    }
}

/// Read an optional string value, treating an absent key or an empty string as
/// unset.
fn optional_string(vars: &HashMap<String, String>, key: &str) -> Option<String> {
    vars.get(key).filter(|v| !v.is_empty()).cloned()
}

/// Read an optional filesystem path, treating an absent key or an empty string
/// as unset.
fn optional_path(vars: &HashMap<String, String>, key: &str) -> Option<PathBuf> {
    optional_string(vars, key).map(PathBuf::from)
}

/// Apply the strict-boolean rule: exactly `"true"` enables, an absent or empty
/// value disables, and anything else is a startup error. Case-sensitive, no
/// whitespace trimming (spec section 5).
fn parse_strict_bool(
    vars: &HashMap<String, String>,
    var: &'static str,
) -> Result<bool, ConfigError> {
    match vars.get(var) {
        None => Ok(false),
        Some(v) if v.is_empty() => Ok(false),
        Some(v) if v == "true" => Ok(true),
        Some(v) => Err(ConfigError::InvalidBool {
            var,
            value: v.clone(),
        }),
    }
}

/// Parse an integer seconds value within `[min, max]`, falling back to
/// `default` when the variable is absent or empty. Malformed input and
/// out-of-range values are both startup errors.
fn parse_seconds(
    vars: &HashMap<String, String>,
    var: &'static str,
    default: u64,
    min: u64,
    max: u64,
) -> Result<u64, ConfigError> {
    let raw = match vars.get(var).filter(|v| !v.is_empty()) {
        Some(raw) => raw,
        None => return Ok(default),
    };
    let value: u64 = raw.parse().map_err(|_| ConfigError::InvalidInteger {
        var,
        value: raw.clone(),
    })?;
    if value < min || value > max {
        return Err(ConfigError::IntegerOutOfRange {
            var,
            value,
            min,
            max,
        });
    }
    Ok(value)
}

/// Resolve the vault path to absolute and confirm it is an existing, readable
/// regular file. `std::fs::metadata` follows symlinks and fails when the file
/// is absent or unreadable, which covers the existence and readability checks
/// the spec calls for. Resolving to absolute is done by joining against the
/// current directory when the input is relative.
fn resolve_vault_path(raw: &str) -> Result<PathBuf, ConfigError> {
    let path = PathBuf::from(raw);
    let absolute = if path.is_absolute() {
        path
    } else {
        // std::env::current_dir reads global state, but it does not mutate it,
        // and tests use absolute temp-file paths so this branch stays out of
        // their way.
        match std::env::current_dir() {
            Ok(cwd) => cwd.join(path),
            Err(e) => {
                return Err(ConfigError::VaultPathUnreadable {
                    path: raw.to_string(),
                    reason: e.to_string(),
                });
            }
        }
    };

    let meta = std::fs::metadata(&absolute).map_err(|e| ConfigError::VaultPathUnreadable {
        path: absolute.display().to_string(),
        reason: e.to_string(),
    })?;
    if !meta.is_file() {
        return Err(ConfigError::VaultPathNotAFile {
            path: absolute.display().to_string(),
        });
    }
    Ok(absolute)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// A temp file that exists on disk, plus a base variable map that points
    /// `KDBX_VAULT_PATH` at it. Returning the `NamedTempFile` keeps it alive
    /// for the duration of the test (dropping it deletes the file).
    fn vault_fixture() -> (NamedTempFile, HashMap<String, String>) {
        let mut file = NamedTempFile::new().expect("create temp vault file");
        // Contents do not matter here; config only stats the path.
        file.write_all(b"not a real kdbx").expect("write temp file");
        let path = file.path().to_str().expect("utf8 temp path").to_string();
        let mut vars = HashMap::new();
        vars.insert("KDBX_VAULT_PATH".to_string(), path);
        (file, vars)
    }

    fn set(vars: &mut HashMap<String, String>, key: &str, value: &str) {
        vars.insert(key.to_string(), value.to_string());
    }

    #[test]
    fn fully_populated_map_yields_expected_config() {
        let (file, mut vars) = vault_fixture();
        set(&mut vars, "KDBX_KEYFILE_PATH", "/keys/vault.key");
        set(&mut vars, "KDBX_PASSWORD", "hunter2");
        set(&mut vars, "KDBX_UNLOCK_CMD", "pass show vault");
        set(&mut vars, "KDBX_UNLOCK_CMD_TIMEOUT_SECONDS", "45");
        set(&mut vars, "KDBX_ALLOW_WRITES", "true");
        set(&mut vars, "KDBX_IDLE_TIMEOUT_SECONDS", "300");
        set(&mut vars, "KDBX_AUTO_CLEAN_ORPHANS", "true");
        set(&mut vars, "KDBX_LOG_LEVEL", "debug");
        set(&mut vars, "KDBX_LOG_FILE", "/var/log/mcp-kdbx.jsonl");

        let cfg = Config::from_map(&vars).expect("valid config");

        assert_eq!(cfg.vault_path, file.path());
        assert_eq!(cfg.keyfile_path, Some(PathBuf::from("/keys/vault.key")));
        assert_eq!(
            cfg.password.as_ref().map(|p| p.expose().as_str()),
            Some("hunter2")
        );
        assert_eq!(
            cfg.unlock_cmd.as_ref().map(|c| c.expose().as_str()),
            Some("pass show vault")
        );
        assert_eq!(cfg.unlock_cmd_timeout_seconds, 45);
        assert!(cfg.allow_writes);
        assert_eq!(cfg.idle_timeout_seconds, 300);
        assert!(cfg.auto_clean_orphans);
        assert_eq!(cfg.log_level, LogLevel::Debug);
        assert_eq!(cfg.log_file, Some(PathBuf::from("/var/log/mcp-kdbx.jsonl")));
    }

    #[test]
    fn defaults_apply_when_optional_vars_absent() {
        let (_file, vars) = vault_fixture();
        let cfg = Config::from_map(&vars).expect("valid config");

        assert_eq!(cfg.keyfile_path, None);
        assert_eq!(cfg.password, None);
        assert_eq!(cfg.unlock_cmd, None);
        assert_eq!(cfg.unlock_cmd_timeout_seconds, 30);
        assert!(!cfg.allow_writes);
        assert_eq!(cfg.idle_timeout_seconds, 900);
        assert!(!cfg.auto_clean_orphans);
        assert_eq!(cfg.log_level, LogLevel::Info);
        assert_eq!(cfg.log_file, None);
    }

    #[test]
    fn allow_writes_true_enables() {
        let (_file, mut vars) = vault_fixture();
        set(&mut vars, "KDBX_ALLOW_WRITES", "true");
        let cfg = Config::from_map(&vars).expect("valid config");
        assert!(cfg.allow_writes);
    }

    #[test]
    fn allow_writes_absent_disables() {
        let (_file, vars) = vault_fixture();
        let cfg = Config::from_map(&vars).expect("valid config");
        assert!(!cfg.allow_writes);
    }

    #[test]
    fn allow_writes_empty_string_disables() {
        let (_file, mut vars) = vault_fixture();
        set(&mut vars, "KDBX_ALLOW_WRITES", "");
        let cfg = Config::from_map(&vars).expect("valid config");
        assert!(!cfg.allow_writes);
    }

    #[test]
    fn allow_writes_near_miss_values_rejected() {
        for bad in ["yes", "1", "TRUE", "True", " true", "true "] {
            let (_file, mut vars) = vault_fixture();
            set(&mut vars, "KDBX_ALLOW_WRITES", bad);
            let err = Config::from_map(&vars).expect_err("should reject");
            match err {
                ConfigError::InvalidBool { var, value } => {
                    assert_eq!(var, "KDBX_ALLOW_WRITES");
                    assert_eq!(value, bad);
                }
                other => panic!("expected InvalidBool for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn auto_clean_orphans_follows_strict_bool_rule() {
        // true enables.
        let (_f1, mut vars) = vault_fixture();
        set(&mut vars, "KDBX_AUTO_CLEAN_ORPHANS", "true");
        assert!(Config::from_map(&vars).unwrap().auto_clean_orphans);

        // absent disables.
        let (_f2, vars) = vault_fixture();
        assert!(!Config::from_map(&vars).unwrap().auto_clean_orphans);

        // a near-miss is rejected.
        let (_f3, mut vars) = vault_fixture();
        set(&mut vars, "KDBX_AUTO_CLEAN_ORPHANS", "TRUE");
        let err = Config::from_map(&vars).expect_err("should reject");
        assert!(matches!(
            err,
            ConfigError::InvalidBool {
                var: "KDBX_AUTO_CLEAN_ORPHANS",
                ..
            }
        ));
    }

    #[test]
    fn idle_timeout_accepts_zero_meaning_no_idle_lock() {
        let (_file, mut vars) = vault_fixture();
        set(&mut vars, "KDBX_IDLE_TIMEOUT_SECONDS", "0");
        let cfg = Config::from_map(&vars).expect("valid config");
        assert_eq!(cfg.idle_timeout_seconds, 0);
    }

    #[test]
    fn idle_timeout_accepts_upper_bound() {
        let (_file, mut vars) = vault_fixture();
        set(&mut vars, "KDBX_IDLE_TIMEOUT_SECONDS", "86400");
        let cfg = Config::from_map(&vars).expect("valid config");
        assert_eq!(cfg.idle_timeout_seconds, 86_400);
    }

    #[test]
    fn idle_timeout_above_range_rejected() {
        let (_file, mut vars) = vault_fixture();
        set(&mut vars, "KDBX_IDLE_TIMEOUT_SECONDS", "86401");
        let err = Config::from_map(&vars).expect_err("should reject");
        match err {
            ConfigError::IntegerOutOfRange {
                var,
                value,
                min,
                max,
            } => {
                assert_eq!(var, "KDBX_IDLE_TIMEOUT_SECONDS");
                assert_eq!(value, 86_401);
                assert_eq!(min, 0);
                assert_eq!(max, 86_400);
            }
            other => panic!("expected IntegerOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn idle_timeout_malformed_rejected() {
        let (_file, mut vars) = vault_fixture();
        set(&mut vars, "KDBX_IDLE_TIMEOUT_SECONDS", "nine hundred");
        let err = Config::from_map(&vars).expect_err("should reject");
        assert!(matches!(
            err,
            ConfigError::InvalidInteger {
                var: "KDBX_IDLE_TIMEOUT_SECONDS",
                ..
            }
        ));
    }

    #[test]
    fn unlock_cmd_timeout_zero_rejected_because_floor_is_one() {
        let (_file, mut vars) = vault_fixture();
        set(&mut vars, "KDBX_UNLOCK_CMD_TIMEOUT_SECONDS", "0");
        let err = Config::from_map(&vars).expect_err("should reject");
        match err {
            ConfigError::IntegerOutOfRange { var, min, .. } => {
                assert_eq!(var, "KDBX_UNLOCK_CMD_TIMEOUT_SECONDS");
                assert_eq!(min, 1);
            }
            other => panic!("expected IntegerOutOfRange, got {other:?}"),
        }
    }

    #[test]
    fn unlock_cmd_timeout_malformed_rejected() {
        let (_file, mut vars) = vault_fixture();
        set(&mut vars, "KDBX_UNLOCK_CMD_TIMEOUT_SECONDS", "-5");
        let err = Config::from_map(&vars).expect_err("should reject");
        assert!(matches!(
            err,
            ConfigError::InvalidInteger {
                var: "KDBX_UNLOCK_CMD_TIMEOUT_SECONDS",
                ..
            }
        ));
    }

    #[test]
    fn every_log_level_name_parses() {
        let cases = [
            ("error", LogLevel::Error),
            ("warn", LogLevel::Warn),
            ("info", LogLevel::Info),
            ("debug", LogLevel::Debug),
            ("trace", LogLevel::Trace),
        ];
        for (name, expected) in cases {
            let (_file, mut vars) = vault_fixture();
            set(&mut vars, "KDBX_LOG_LEVEL", name);
            let cfg = Config::from_map(&vars).expect("valid config");
            assert_eq!(cfg.log_level, expected);
            assert_eq!(cfg.log_level.as_str(), name);
        }
    }

    #[test]
    fn invalid_log_level_rejected() {
        let (_file, mut vars) = vault_fixture();
        set(&mut vars, "KDBX_LOG_LEVEL", "verbose");
        let err = Config::from_map(&vars).expect_err("should reject");
        match err {
            ConfigError::InvalidLogLevel { value } => assert_eq!(value, "verbose"),
            other => panic!("expected InvalidLogLevel, got {other:?}"),
        }
    }

    #[test]
    fn log_level_is_case_sensitive() {
        let (_file, mut vars) = vault_fixture();
        set(&mut vars, "KDBX_LOG_LEVEL", "INFO");
        let err = Config::from_map(&vars).expect_err("should reject uppercase");
        assert!(matches!(err, ConfigError::InvalidLogLevel { .. }));
    }

    #[test]
    fn missing_vault_path_rejected() {
        let vars: HashMap<String, String> = HashMap::new();
        let err = Config::from_map(&vars).expect_err("should reject");
        assert!(matches!(err, ConfigError::MissingVaultPath));
    }

    #[test]
    fn empty_vault_path_treated_as_missing() {
        let mut vars: HashMap<String, String> = HashMap::new();
        set(&mut vars, "KDBX_VAULT_PATH", "");
        let err = Config::from_map(&vars).expect_err("should reject");
        assert!(matches!(err, ConfigError::MissingVaultPath));
    }

    #[test]
    fn nonexistent_vault_path_rejected() {
        let mut vars: HashMap<String, String> = HashMap::new();
        set(
            &mut vars,
            "KDBX_VAULT_PATH",
            "/this/path/should/not/exist/vault.kdbx",
        );
        let err = Config::from_map(&vars).expect_err("should reject");
        match err {
            ConfigError::VaultPathUnreadable { path, .. } => {
                assert!(path.contains("vault.kdbx"));
            }
            other => panic!("expected VaultPathUnreadable, got {other:?}"),
        }
    }

    #[test]
    fn vault_path_directory_rejected() {
        let dir = tempfile::tempdir().expect("create temp dir");
        let mut vars: HashMap<String, String> = HashMap::new();
        set(
            &mut vars,
            "KDBX_VAULT_PATH",
            dir.path().to_str().expect("utf8 dir path"),
        );
        let err = Config::from_map(&vars).expect_err("should reject directory");
        assert!(matches!(err, ConfigError::VaultPathNotAFile { .. }));
    }

    #[test]
    fn debug_redacts_password_and_unlock_cmd_when_set() {
        let cfg = Config {
            password: Some("hunter2".to_string().into()),
            unlock_cmd: Some("pass show vault".to_string().into()),
            ..Config::default()
        };
        let rendered = format!("{cfg:?}");
        // The secret values must not appear anywhere in the debug output.
        assert!(!rendered.contains("hunter2"));
        assert!(!rendered.contains("pass show vault"));
        // Both secrets render as a set marker, showing presence without value.
        assert!(rendered.contains("password: Some(<redacted>)"));
        assert!(rendered.contains("unlock_cmd: Some(<redacted>)"));
    }

    #[test]
    fn debug_shows_none_for_unset_secrets_and_keeps_paths() {
        let cfg = Config {
            password: None,
            unlock_cmd: None,
            keyfile_path: Some(PathBuf::from("/keys/vault.key")),
            log_file: Some(PathBuf::from("/var/log/mcp-kdbx.jsonl")),
            ..Config::default()
        };
        let rendered = format!("{cfg:?}");
        // Unset secrets render as None: the shape is visible, no value to hide.
        assert!(rendered.contains("password: None"));
        assert!(rendered.contains("unlock_cmd: None"));
        // Path fields are not secret and must still render their values.
        assert!(rendered.contains("/keys/vault.key"));
        assert!(rendered.contains("/var/log/mcp-kdbx.jsonl"));
    }

    #[test]
    fn default_config_has_sane_values() {
        let cfg = Config::default();
        assert_eq!(cfg.unlock_cmd_timeout_seconds, 30);
        assert_eq!(cfg.idle_timeout_seconds, 900);
        assert!(!cfg.allow_writes);
        assert!(!cfg.auto_clean_orphans);
        assert_eq!(cfg.log_level, LogLevel::Info);
        assert_eq!(cfg.password, None);
        assert_eq!(cfg.log_file, None);
    }
}
