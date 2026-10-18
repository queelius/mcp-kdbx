//! The locked/unlocked vault state machine over canonical and working dbs.
//!
//! A [`Vault`] is either `Locked` (no secrets in memory) or `Unlocked`, holding
//! the parsed canonical database, a working clone the write tools mutate, the
//! master key, and two timestamps (last activity for the Phase 2 idle timer, and
//! the file mtime captured at unlock for the Phase 3 external-modification
//! check). See spec section 2 ("State machine", "Unlock sequence", "Lock
//! sequence") and section 3 ("Working-copy model").
//!
//! This module is deliberately free of MCP types, audit emission, and idle-timer
//! wiring. The idle timer is Task 11 (Phase 2); audit emission happens in the
//! Phase 3 adapter. [`Vault::lock`] returns the information the caller needs to
//! log (the [`LockReason`] is passed in, the pending count is returned), rather
//! than writing to the audit log itself.
//!
//! ## Working-copy model (spec section 3)
//!
//! At unlock, `working_db = canonical_db.clone()`. Read tools query the working
//! db so they see staged writes immediately. Write tools mutate the working db;
//! the canonical db stays as the on-disk baseline. Locking drops both databases,
//! which is what discards the pending stage: there is no separate stage data
//! structure to clear.

use crate::kdbx_core::error::{CoreError, CoreResult, ErrorCode};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime};
use zeroize::Zeroize;

/// Why a lock happened. Passed into [`Vault::lock`] so the caller can record it
/// in the audit log. Phase 1 does not emit audit events from this module; the
/// reason is threaded through for the Phase 3 adapter and for tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    /// An explicit `kdbx_lock` tool call.
    Manual,
    /// The Phase 2 idle timer fired after inactivity.
    IdleTimeout,
    /// The server is shutting down (SIGTERM/SIGINT or process exit).
    Shutdown,
}

impl LockReason {
    /// The stable lowercase label used in audit events and the [`LockInfo`]
    /// returned to the adapter. The adapter attaches this to the
    /// `VAULT_LOCKED` error so the first call after a lock can say why.
    pub fn label(self) -> &'static str {
        match self {
            LockReason::Manual => "manual",
            LockReason::IdleTimeout => "idle_timeout",
            LockReason::Shutdown => "shutdown",
        }
    }
}

/// What a lock discarded, captured at lock time so the first tool call after a
/// lock can report what staged work was thrown away (spec section 2, "Pending
/// changes on lock").
///
/// The adapter takes this once (via [`Vault::take_last_lock`]) and attaches it
/// to the next `VAULT_LOCKED` error. `reason` is the [`LockReason::label`]
/// string; `pending_discarded_count` is the number of added plus modified
/// entries that were dropped; `summary` labels them (vault path, or UUID for a
/// record with no addressable path, see `DiffPending::entry_labels`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LockInfo {
    /// The lock reason as a stable label: `"manual"`, `"idle_timeout"`, or
    /// `"shutdown"`.
    pub reason: String,
    /// How many staged entries (added plus modified) the lock discarded.
    pub pending_discarded_count: usize,
    /// The discarded added and modified entries: each one's vault path, or its
    /// UUID when it has no addressable path.
    pub summary: Vec<String>,
}

/// The two states a vault can be in.
///
/// `Locked` carries no secrets. `Unlocked` owns everything that must be zeroed
/// or dropped on the way back to `Locked`: the master key (zeroed), the two
/// databases (dropped), and the bookkeeping timestamps.
///
/// The `Unlocked` variant is much larger than `Locked` (two parsed databases
/// plus the key). clippy flags the size gap, but there is exactly one `Vault`
/// per server process and it lives `Unlocked` while serving requests, so the
/// unused space in the `Locked` case costs nothing. Keeping the unlocked secret
/// state inline rather than boxed also avoids extra heap copies of key material
/// to track and zero.
#[allow(clippy::large_enum_variant)]
pub enum VaultState {
    /// No secrets in memory. The initial state and the state after any lock.
    Locked,
    /// Secrets are in memory.
    Unlocked {
        /// The parsed on-disk baseline. Untouched by write tools.
        canonical_db: keepass::Database,
        /// A clone of `canonical_db` that write tools mutate in place. Reads go
        /// here so they reflect staged writes.
        working_db: keepass::Database,
        /// The master key, retained so saves can re-encrypt without a re-prompt.
        /// Zeroed on lock (it is also `ZeroizeOnDrop`, so the drop is belt and
        /// suspenders).
        key: keepass::DatabaseKey,
        /// When the vault was last touched by a tool call. The Phase 2 idle
        /// timer reads this; [`Vault::touch`] updates it.
        last_activity: Instant,
        /// The vault file's mtime at unlock time. The Phase 3 save path compares
        /// the current mtime against this to refuse writes when the file changed
        /// out from under us.
        file_mtime_at_unlock: SystemTime,
    },
}

/// A single vault and its lock state. One `Vault` per server process (the v0.1
/// scope is per-vault).
pub struct Vault {
    /// Path to the `.kdbx` file on disk.
    path: PathBuf,
    /// The current lock state.
    state: VaultState,
    /// What the most recent lock discarded, if any, and not yet reported. Set
    /// by [`lock`](Self::lock) when there was staged work, cleared by a
    /// successful [`unlock`](Self::unlock) and by [`take_last_lock`](Self::take_last_lock).
    last_lock: Option<LockInfo>,
}

impl Vault {
    /// Build a new, locked vault for the file at `path`. No I/O happens here;
    /// the file is read on [`unlock`](Self::unlock).
    pub fn new(path: PathBuf) -> Vault {
        Vault {
            path,
            state: VaultState::Locked,
            last_lock: None,
        }
    }

    /// The path to the vault file.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Move from `Locked` to `Unlocked`.
    ///
    /// Reads the file at `self.path` (a missing or unreadable file is
    /// [`ErrorCode::VaultNotFound`]), captures its mtime, builds a
    /// [`keepass::DatabaseKey`] from `password` and the optional `keyfile`
    /// bytes, and attempts decryption. A decryption failure is
    /// [`ErrorCode::AuthFailed`] and the vault stays `Locked`. On success,
    /// `working_db` is a clone of the parsed canonical db and `last_activity`
    /// is `Instant::now()`.
    ///
    /// Calling this while already unlocked is [`ErrorCode::VaultAlreadyUnlocked`].
    ///
    /// This method only resolves a key from the `password` (and `keyfile`)
    /// arguments it is given. Resolving the password from env vars or a
    /// shell-out command is the unlock module's job (Task 7); it calls this with
    /// the resolved password.
    pub fn unlock(&mut self, password: &str, keyfile: Option<&[u8]>) -> CoreResult<()> {
        if self.is_unlocked() {
            return Err(ErrorCode::VaultAlreadyUnlocked.into());
        }

        let bytes = std::fs::read(&self.path).map_err(|e| {
            CoreError::new(ErrorCode::VaultNotFound).with_message(format!(
                "could not read vault file at {}: {}",
                self.path.display(),
                e
            ))
        })?;

        // Capture the mtime now, before decryption, so the external-modification
        // baseline reflects the bytes we actually parsed. If the metadata read
        // fails, fall back to the current time, which is conservative: the
        // Phase 3 save check would then refuse on any later modification.
        let file_mtime_at_unlock = std::fs::metadata(&self.path)
            .and_then(|m| m.modified())
            .unwrap_or_else(|_| SystemTime::now());

        let mut key = keepass::DatabaseKey::new().with_password(password);
        if let Some(keyfile_bytes) = keyfile {
            let mut reader = std::io::Cursor::new(keyfile_bytes);
            key = key.with_keyfile(&mut reader).map_err(|e| {
                CoreError::new(ErrorCode::AuthFailed)
                    .with_message(format!("could not read keyfile: {e}"))
            })?;
        }

        let canonical_db = keepass::Database::open(&mut std::io::Cursor::new(&bytes), key.clone())
            .map_err(|_| CoreError::new(ErrorCode::AuthFailed))?;

        let working_db = canonical_db.clone();

        self.state = VaultState::Unlocked {
            canonical_db,
            working_db,
            key,
            last_activity: Instant::now(),
            file_mtime_at_unlock,
        };

        // A fresh session has no prior discard to report. Clear any LockInfo
        // left over from an earlier lock so the next VAULT_LOCKED (if it ever
        // comes) reflects this session, not a stale one.
        self.last_lock = None;

        Ok(())
    }

    /// Move from `Unlocked` back to `Locked`, returning the count of pending
    /// changes that were discarded.
    ///
    /// Before dropping the databases, the discard summary is computed against
    /// the canonical and working dbs and stashed in `last_lock`, so the first
    /// tool call after the lock can report what staged work was thrown away
    /// (spec section 2, "Pending changes on lock"). The adapter reads it once
    /// via [`take_last_lock`](Self::take_last_lock).
    ///
    /// The master key is zeroed before the state transition; dropping the
    /// `Unlocked` state then drops both databases, which is what discards the
    /// pending stage (the working db is the stage). `reason` is recorded in the
    /// stashed [`LockInfo`] (as its [`label`](LockReason::label)) so the caller
    /// can say why.
    ///
    /// Locking an already-locked vault is a no-op that returns 0 and leaves
    /// `last_lock` untouched.
    ///
    /// The returned count is the real number of added plus modified entries
    /// discarded, the same `pending_discarded_count` stored in `last_lock`.
    pub fn lock(&mut self, reason: LockReason) -> usize {
        // Compute the discard summary while the databases are still live. When
        // unlocked, diff the canonical baseline against the working stage; an
        // already-locked vault has nothing to summarize.
        let (count, summary) = match &self.state {
            VaultState::Unlocked {
                canonical_db,
                working_db,
                ..
            } => {
                let diff = crate::kdbx_core::stage::diff_pending(canonical_db, working_db);
                let count = diff.summary.num_added + diff.summary.num_modified;
                (count, diff.entry_labels())
            }
            VaultState::Locked => (0, Vec::new()),
        };

        // Take the state out so we can zero the key before it drops. Replacing
        // with `Locked` also drops the old `Unlocked` value (and both databases)
        // at the end of this scope.
        let old = std::mem::replace(&mut self.state, VaultState::Locked);
        match old {
            VaultState::Unlocked { mut key, .. } => {
                key.zeroize();
                // Stash what this lock discarded for the next VAULT_LOCKED.
                self.last_lock = Some(LockInfo {
                    reason: reason.label().to_string(),
                    pending_discarded_count: count,
                    summary,
                });
            }
            VaultState::Locked => {
                // No-op lock: leave any existing last_lock untouched.
            }
        }

        count
    }

    /// Take the most recent lock's discard summary, clearing it.
    ///
    /// The adapter calls this once per lock to attach the discard summary to the
    /// next `VAULT_LOCKED` error. Returns `None` when there is nothing to report
    /// (no lock since the last unlock, or it was already taken).
    pub fn take_last_lock(&mut self) -> Option<LockInfo> {
        self.last_lock.take()
    }

    /// True when the vault is unlocked.
    pub fn is_unlocked(&self) -> bool {
        matches!(self.state, VaultState::Unlocked { .. })
    }

    /// Borrow the working db (what read and write tools operate on).
    ///
    /// [`ErrorCode::VaultLocked`] when locked.
    pub fn working_db(&self) -> CoreResult<&keepass::Database> {
        match &self.state {
            VaultState::Unlocked { working_db, .. } => Ok(working_db),
            VaultState::Locked => Err(ErrorCode::VaultLocked.into()),
        }
    }

    /// Mutably borrow the working db so write tools can stage changes.
    ///
    /// [`ErrorCode::VaultLocked`] when locked.
    pub fn working_db_mut(&mut self) -> CoreResult<&mut keepass::Database> {
        match &mut self.state {
            VaultState::Unlocked { working_db, .. } => Ok(working_db),
            VaultState::Locked => Err(ErrorCode::VaultLocked.into()),
        }
    }

    /// Borrow the canonical db (the on-disk baseline).
    ///
    /// [`ErrorCode::VaultLocked`] when locked.
    pub fn canonical_db(&self) -> CoreResult<&keepass::Database> {
        match &self.state {
            VaultState::Unlocked { canonical_db, .. } => Ok(canonical_db),
            VaultState::Locked => Err(ErrorCode::VaultLocked.into()),
        }
    }

    /// Update `last_activity` to now. Called on every tool use so the Phase 2
    /// idle timer measures inactivity from the last real interaction. No-op when
    /// locked.
    pub fn touch(&mut self) {
        if let VaultState::Unlocked { last_activity, .. } = &mut self.state {
            *last_activity = Instant::now();
        }
    }

    /// True when the vault is unlocked and the working db differs from the
    /// canonical db.
    ///
    /// Phase 1 compares the parsed databases structurally. The working db is a
    /// clone of the canonical db at unlock, so the two are equal until a write
    /// tool mutates the working db. `keepass::Database` derives `PartialEq`, so
    /// this compares the in-memory record tree, not encrypted bytes.
    ///
    /// Comparing re-serialized KDBX bytes would be wrong: each save uses a fresh
    /// nonce, so two structurally equal databases produce different bytes, and
    /// every unlocked vault would look dirty right after unlock. The structural
    /// comparison is deterministic and settles cleanly after a save (which
    /// re-clones the canonical db from the working db).
    ///
    /// This is a boolean "is there anything to save", which is all `lock` and the
    /// save path need in Phase 1. A precise per-change count, and the
    /// discarded-changes summary the spec shows on a re-locked vault, are a
    /// Phase 2 concern handled by diff-kdbx against `canonical_db` and
    /// `working_db`.
    pub fn has_pending_changes(&self) -> bool {
        match &self.state {
            VaultState::Unlocked {
                canonical_db,
                working_db,
                ..
            } => working_db != canonical_db,
            VaultState::Locked => false,
        }
    }

    /// The number of pending changes: added plus modified entries between the
    /// canonical baseline and the working stage. Zero when locked.
    ///
    /// This is the precise count [`has_pending_changes`](Self::has_pending_changes)
    /// reduces to a boolean. It runs the same diff-kdbx stage diff the lock
    /// summary and the save outcome use, so all three agree on the count.
    pub fn pending_count(&self) -> usize {
        match &self.state {
            VaultState::Unlocked {
                canonical_db,
                working_db,
                ..
            } => {
                let diff = crate::kdbx_core::stage::diff_pending(canonical_db, working_db);
                diff.summary.num_added + diff.summary.num_modified
            }
            VaultState::Locked => 0,
        }
    }

    /// Whether the idle timer should lock the vault now.
    ///
    /// True when the vault is unlocked, `idle_timeout` is non-zero, and at least
    /// `idle_timeout` has elapsed since the last [`touch`](Self::touch). A zero
    /// timeout means "never idle-lock" (spec: `KDBX_IDLE_TIMEOUT_SECONDS=0`).
    ///
    /// This is a pure predicate so it is testable without a running clock. The
    /// Phase 3 server owns the actual tokio timer task: it periodically calls
    /// this with `Instant::now()` and the configured timeout, and calls
    /// [`lock`](Self::lock) with [`LockReason::IdleTimeout`] when it returns true.
    pub fn should_lock(&self, now: Instant, idle_timeout: Duration) -> bool {
        if idle_timeout.is_zero() {
            return false;
        }
        match &self.state {
            VaultState::Unlocked { last_activity, .. } => {
                now.saturating_duration_since(*last_activity) >= idle_timeout
            }
            VaultState::Locked => false,
        }
    }

    /// Whole seconds remaining before the idle timer would lock, for
    /// `kdbx_status.idle_timeout_remaining_seconds` (spec: "number or null,
    /// null if locked").
    ///
    /// Returns `None` when locked or when `timeout` is zero (idle lock
    /// disabled), and `Some(remaining)` otherwise: the saturating difference
    /// between `timeout` and the elapsed time since the last
    /// [`touch`](Self::touch), truncated to whole seconds. A vault that is
    /// already past its timeout (but not yet locked) reports `Some(0)`. Mirrors
    /// [`should_lock`](Self::should_lock) in structure so the two stay in step.
    pub fn idle_remaining(&self, now: Instant, timeout: Duration) -> Option<u64> {
        if timeout.is_zero() {
            return None;
        }
        match &self.state {
            VaultState::Unlocked { last_activity, .. } => {
                let elapsed = now.saturating_duration_since(*last_activity);
                Some(timeout.saturating_sub(elapsed).as_secs())
            }
            VaultState::Locked => None,
        }
    }

    /// The vault file's mtime as captured at unlock. The save path compares the
    /// current on-disk mtime against this to detect external modification.
    ///
    /// [`ErrorCode::VaultLocked`] when locked.
    pub fn mtime_at_unlock(&self) -> CoreResult<SystemTime> {
        match &self.state {
            VaultState::Unlocked {
                file_mtime_at_unlock,
                ..
            } => Ok(*file_mtime_at_unlock),
            VaultState::Locked => Err(ErrorCode::VaultLocked.into()),
        }
    }

    /// Borrow the working db and the master key together, for serializing the
    /// vault to disk. The save path needs both at once, which the individual
    /// accessors cannot give without a second mutable borrow.
    ///
    /// [`ErrorCode::VaultLocked`] when locked.
    pub fn working_db_and_key(&self) -> CoreResult<(&keepass::Database, &keepass::DatabaseKey)> {
        match &self.state {
            VaultState::Unlocked {
                working_db, key, ..
            } => Ok((working_db, key)),
            VaultState::Locked => Err(ErrorCode::VaultLocked.into()),
        }
    }

    /// Borrow the canonical and working dbs together, in that order, for the
    /// stage diff. Both are shared borrows, which the single-field accessors
    /// cannot hand out at the same time.
    ///
    /// [`ErrorCode::VaultLocked`] when locked.
    pub fn canonical_and_working(&self) -> CoreResult<(&keepass::Database, &keepass::Database)> {
        match &self.state {
            VaultState::Unlocked {
                canonical_db,
                working_db,
                ..
            } => Ok((canonical_db, working_db)),
            VaultState::Locked => Err(ErrorCode::VaultLocked.into()),
        }
    }

    /// Discard the staged changes: reset the working db to a fresh clone of the
    /// canonical baseline. Returns the real number of pending changes (added
    /// plus modified entries) that were discarded, computed before the reset.
    ///
    /// [`ErrorCode::VaultLocked`] when locked.
    pub fn discard_working(&mut self) -> CoreResult<usize> {
        // Count before the reset: after it the dbs are equal and the count is 0.
        let pending = self.pending_count();
        match &mut self.state {
            VaultState::Unlocked {
                canonical_db,
                working_db,
                ..
            } => {
                *working_db = canonical_db.clone();
                Ok(pending)
            }
            VaultState::Locked => Err(ErrorCode::VaultLocked.into()),
        }
    }

    /// Record that the working db was successfully written to disk: adopt it as
    /// the new canonical baseline (so `has_pending_changes` settles to false) and
    /// update the external-modification mtime to the freshly written file's.
    ///
    /// [`ErrorCode::VaultLocked`] when locked.
    pub fn mark_saved(&mut self, new_mtime: SystemTime) -> CoreResult<()> {
        match &mut self.state {
            VaultState::Unlocked {
                canonical_db,
                working_db,
                file_mtime_at_unlock,
                ..
            } => {
                *canonical_db = working_db.clone();
                *file_mtime_at_unlock = new_mtime;
                Ok(())
            }
            VaultState::Locked => Err(ErrorCode::VaultLocked.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use keepass::{Database, DatabaseKey};
    use std::io::Write;

    /// The fixture password. Matches the repo convention.
    const TEST_PASSWORD: &str = "test-password-do-not-use";

    /// Build a tiny KDBX in memory (root group plus one entry), save it to a
    /// fresh tempfile under `TEST_PASSWORD`, and return both the temp handle
    /// (kept alive so the file is not deleted) and its path. Mirrors the
    /// fixture-building helper in web-kdbx/src/vault.rs.
    fn write_fixture() -> (tempfile::NamedTempFile, PathBuf) {
        let mut db = Database::new();
        {
            let mut root = db.root_mut();
            let mut entry = root.add_entry();
            entry.edit(|e| {
                e.set_unprotected(keepass::db::fields::TITLE, "Test Entry");
                e.set_unprotected(keepass::db::fields::USERNAME, "alice");
                e.set_protected(keepass::db::fields::PASSWORD, "hunter2");
            });
        }

        let mut buf = Vec::new();
        db.save(&mut buf, DatabaseKey::new().with_password(TEST_PASSWORD))
            .expect("save fixture");

        let mut tmp = tempfile::NamedTempFile::new().expect("create tempfile");
        tmp.write_all(&buf).expect("write fixture bytes");
        tmp.flush().expect("flush fixture");
        let path = tmp.path().to_path_buf();
        (tmp, path)
    }

    #[test]
    fn new_vault_is_locked() {
        let vault = Vault::new(PathBuf::from("/nonexistent/vault.kdbx"));
        assert!(!vault.is_unlocked());
    }

    #[test]
    fn unlock_with_correct_password_succeeds() {
        let (_tmp, path) = write_fixture();
        let mut vault = Vault::new(path);

        assert!(vault.unlock(TEST_PASSWORD, None).is_ok());
        assert!(vault.is_unlocked());
    }

    #[test]
    fn unlock_when_already_unlocked_errors() {
        let (_tmp, path) = write_fixture();
        let mut vault = Vault::new(path);

        vault.unlock(TEST_PASSWORD, None).expect("first unlock");
        let err = vault
            .unlock(TEST_PASSWORD, None)
            .expect_err("second unlock should fail");
        assert_eq!(err.code_enum(), ErrorCode::VaultAlreadyUnlocked);
        // Still unlocked after the rejected re-unlock.
        assert!(vault.is_unlocked());
    }

    #[test]
    fn unlock_with_wrong_password_fails_and_stays_locked() {
        let (_tmp, path) = write_fixture();
        let mut vault = Vault::new(path);

        let err = vault
            .unlock("the-wrong-password", None)
            .expect_err("wrong password should fail");
        assert_eq!(err.code_enum(), ErrorCode::AuthFailed);
        assert!(!vault.is_unlocked());
    }

    #[test]
    fn unlock_missing_file_is_vault_not_found() {
        let mut vault = Vault::new(PathBuf::from("/nonexistent/definitely/missing.kdbx"));
        let err = vault
            .unlock(TEST_PASSWORD, None)
            .expect_err("missing file should fail");
        assert_eq!(err.code_enum(), ErrorCode::VaultNotFound);
        assert!(!vault.is_unlocked());
    }

    #[test]
    fn working_db_mut_errors_when_locked() {
        let (_tmp, path) = write_fixture();
        let mut vault = Vault::new(path);

        let err = vault
            .working_db_mut()
            .expect_err("locked vault has no working db");
        assert_eq!(err.code_enum(), ErrorCode::VaultLocked);
    }

    #[test]
    fn working_db_accessors_error_when_locked() {
        let vault = Vault::new(PathBuf::from("/nonexistent/vault.kdbx"));
        assert_eq!(
            vault.working_db().unwrap_err().code_enum(),
            ErrorCode::VaultLocked
        );
        assert_eq!(
            vault.canonical_db().unwrap_err().code_enum(),
            ErrorCode::VaultLocked
        );
    }

    #[test]
    fn working_db_readable_when_unlocked() {
        let (_tmp, path) = write_fixture();
        let mut vault = Vault::new(path);
        vault.unlock(TEST_PASSWORD, None).expect("unlock");

        let db = vault.working_db().expect("working db available");
        let titles: Vec<_> = db
            .iter_all_entries()
            .map(|er| er.get_title().unwrap_or("").to_string())
            .collect();
        assert!(titles.iter().any(|t| t == "Test Entry"));
    }

    #[test]
    fn lock_returns_and_clears_unlocked_state() {
        let (_tmp, path) = write_fixture();
        let mut vault = Vault::new(path);
        vault.unlock(TEST_PASSWORD, None).expect("unlock");
        assert!(vault.is_unlocked());

        // No writes yet, so nothing pending to discard.
        let discarded = vault.lock(LockReason::Manual);
        assert_eq!(discarded, 0);
        assert!(!vault.is_unlocked());
    }

    #[test]
    fn lock_when_already_locked_is_noop() {
        let mut vault = Vault::new(PathBuf::from("/nonexistent/vault.kdbx"));
        assert_eq!(vault.lock(LockReason::Shutdown), 0);
        assert!(!vault.is_unlocked());
    }

    #[test]
    fn lock_reports_one_pending_after_a_write() {
        let (_tmp, path) = write_fixture();
        let mut vault = Vault::new(path);
        vault.unlock(TEST_PASSWORD, None).expect("unlock");

        // Stage a change directly on the working db.
        let db = vault.working_db_mut().expect("working db");
        let entry_id = db
            .iter_all_entries()
            .next()
            .map(|er| er.id())
            .expect("at least one entry");
        let mut em = db.entry_mut(entry_id).expect("entry mut");
        em.edit(|e| {
            e.set_unprotected("URL", "https://example.com");
        });

        assert!(vault.has_pending_changes());
        let discarded = vault.lock(LockReason::IdleTimeout);
        assert_eq!(discarded, 1);
        assert!(!vault.is_unlocked());
    }

    #[test]
    fn touch_is_noop_when_locked() {
        let mut vault = Vault::new(PathBuf::from("/nonexistent/vault.kdbx"));
        // Should not panic and should leave the vault locked.
        vault.touch();
        assert!(!vault.is_unlocked());
    }

    #[test]
    fn no_pending_changes_right_after_unlock() {
        let (_tmp, path) = write_fixture();
        let mut vault = Vault::new(path);
        vault.unlock(TEST_PASSWORD, None).expect("unlock");
        // working_db is a fresh clone of canonical_db, so serialized bytes match.
        assert!(!vault.has_pending_changes());
    }

    // Phase 2 additions: idle predicate and save support.

    #[test]
    fn should_lock_is_false_when_locked() {
        let vault = Vault::new(PathBuf::from("/nonexistent/vault.kdbx"));
        assert!(!vault.should_lock(Instant::now(), Duration::from_secs(1)));
    }

    #[test]
    fn should_lock_zero_timeout_never_locks() {
        let (_tmp, path) = write_fixture();
        let mut vault = Vault::new(path);
        vault.unlock(TEST_PASSWORD, None).expect("unlock");
        // A zero timeout means "never idle-lock", even far in the future.
        let far_future = Instant::now() + Duration::from_secs(86_400);
        assert!(!vault.should_lock(far_future, Duration::ZERO));
    }

    #[test]
    fn should_lock_fires_after_timeout_elapses() {
        let (_tmp, path) = write_fixture();
        let mut vault = Vault::new(path);
        vault.unlock(TEST_PASSWORD, None).expect("unlock");
        let now = Instant::now();
        // Not yet: only a moment has passed since unlock set last_activity.
        assert!(!vault.should_lock(now, Duration::from_secs(60)));
        // Yes: pretend a minute has gone by with no touch.
        let later = now + Duration::from_secs(61);
        assert!(vault.should_lock(later, Duration::from_secs(60)));
    }

    #[test]
    fn mtime_and_key_accessors_error_when_locked() {
        let vault = Vault::new(PathBuf::from("/nonexistent/vault.kdbx"));
        assert_eq!(
            vault.mtime_at_unlock().unwrap_err().code_enum(),
            ErrorCode::VaultLocked
        );
        assert_eq!(
            vault.working_db_and_key().unwrap_err().code_enum(),
            ErrorCode::VaultLocked
        );
    }

    #[test]
    fn mark_saved_settles_pending_and_updates_mtime() {
        let (_tmp, path) = write_fixture();
        let mut vault = Vault::new(path);
        vault.unlock(TEST_PASSWORD, None).expect("unlock");

        // Stage a change so the vault is dirty.
        {
            let db = vault.working_db_mut().expect("unlocked");
            let id = db.iter_all_entries().next().expect("an entry").id();
            db.entry_mut(id)
                .expect("entry")
                .edit(|e| e.set_unprotected(keepass::db::fields::URL, "https://example.com"));
        }
        assert!(vault.has_pending_changes());

        // Marking saved adopts working as the new canonical baseline and updates
        // the external-modification mtime.
        let new_mtime = SystemTime::now() + Duration::from_secs(5);
        vault.mark_saved(new_mtime).expect("mark saved");
        assert!(!vault.has_pending_changes());
        assert_eq!(vault.mtime_at_unlock().expect("unlocked"), new_mtime);
    }

    // Lock-recovery, real counts, and idle-remaining additions.

    /// Stage a change on the working db so the vault is dirty. Adds a URL field
    /// to the first entry.
    fn stage_one_change(vault: &mut Vault) {
        let db = vault.working_db_mut().expect("working db");
        let id = db.iter_all_entries().next().expect("an entry").id();
        db.entry_mut(id)
            .expect("entry")
            .edit(|e| e.set_unprotected(keepass::db::fields::URL, "https://example.com"));
    }

    #[test]
    fn lock_reason_labels_are_stable() {
        assert_eq!(LockReason::Manual.label(), "manual");
        assert_eq!(LockReason::IdleTimeout.label(), "idle_timeout");
        assert_eq!(LockReason::Shutdown.label(), "shutdown");
    }

    #[test]
    fn lock_stashes_discard_summary_taken_once() {
        let (_tmp, path) = write_fixture();
        let mut vault = Vault::new(path);
        vault.unlock(TEST_PASSWORD, None).expect("unlock");
        stage_one_change(&mut vault);

        let discarded = vault.lock(LockReason::IdleTimeout);
        assert_eq!(discarded, 1);

        let info = vault.take_last_lock().expect("a discard to report");
        assert_eq!(info.reason, "idle_timeout");
        assert_eq!(info.pending_discarded_count, 1);
        assert_eq!(info.summary.len(), 1);
        // The summary holds the human path of the modified entry.
        assert_eq!(info.summary[0], "/Test Entry");

        // Taken once: a second take is None.
        assert!(vault.take_last_lock().is_none());
    }

    #[test]
    fn lock_with_no_changes_still_records_zero_discard() {
        let (_tmp, path) = write_fixture();
        let mut vault = Vault::new(path);
        vault.unlock(TEST_PASSWORD, None).expect("unlock");

        let discarded = vault.lock(LockReason::Manual);
        assert_eq!(discarded, 0);

        // A clean lock still records a LockInfo so the adapter can report the
        // reason; the count is zero and the summary empty.
        let info = vault.take_last_lock().expect("clean lock still records");
        assert_eq!(info.reason, "manual");
        assert_eq!(info.pending_discarded_count, 0);
        assert!(info.summary.is_empty());
    }

    #[test]
    fn noop_lock_does_not_record_last_lock() {
        let mut vault = Vault::new(PathBuf::from("/nonexistent/vault.kdbx"));
        // Locking an already-locked vault is a no-op and records nothing.
        assert_eq!(vault.lock(LockReason::Shutdown), 0);
        assert!(vault.take_last_lock().is_none());
    }

    #[test]
    fn unlock_clears_prior_last_lock() {
        let (_tmp, path) = write_fixture();
        let mut vault = Vault::new(path);
        vault.unlock(TEST_PASSWORD, None).expect("first unlock");
        stage_one_change(&mut vault);
        vault.lock(LockReason::Manual);

        // A fresh unlock clears the stashed discard: a new session has nothing
        // prior to report.
        vault.unlock(TEST_PASSWORD, None).expect("second unlock");
        assert!(vault.take_last_lock().is_none());
    }

    #[test]
    fn pending_count_zero_then_one() {
        let (_tmp, path) = write_fixture();
        let mut vault = Vault::new(path);
        vault.unlock(TEST_PASSWORD, None).expect("unlock");
        assert_eq!(vault.pending_count(), 0);

        stage_one_change(&mut vault);
        assert_eq!(vault.pending_count(), 1);
    }

    #[test]
    fn pending_count_is_zero_when_locked() {
        let vault = Vault::new(PathBuf::from("/nonexistent/vault.kdbx"));
        assert_eq!(vault.pending_count(), 0);
    }

    #[test]
    fn discard_working_returns_real_count() {
        let (_tmp, path) = write_fixture();
        let mut vault = Vault::new(path);
        vault.unlock(TEST_PASSWORD, None).expect("unlock");
        stage_one_change(&mut vault);

        let discarded = vault.discard_working().expect("discard");
        assert_eq!(discarded, 1);
        assert_eq!(vault.pending_count(), 0);
    }

    #[test]
    fn idle_remaining_is_none_when_locked() {
        let vault = Vault::new(PathBuf::from("/nonexistent/vault.kdbx"));
        assert_eq!(
            vault.idle_remaining(Instant::now(), Duration::from_secs(60)),
            None
        );
    }

    #[test]
    fn idle_remaining_is_none_for_zero_timeout() {
        let (_tmp, path) = write_fixture();
        let mut vault = Vault::new(path);
        vault.unlock(TEST_PASSWORD, None).expect("unlock");
        assert_eq!(vault.idle_remaining(Instant::now(), Duration::ZERO), None);
    }

    #[test]
    fn idle_remaining_counts_down() {
        let (_tmp, path) = write_fixture();
        let mut vault = Vault::new(path);
        vault.unlock(TEST_PASSWORD, None).expect("unlock");
        let now = Instant::now();
        // Right after unlock, close to the full timeout remains.
        let remaining = vault
            .idle_remaining(now, Duration::from_secs(900))
            .expect("unlocked has a remaining");
        assert!((899..=900).contains(&remaining));

        // Halfway through: about half remains.
        let halfway = now + Duration::from_secs(450);
        let remaining = vault
            .idle_remaining(halfway, Duration::from_secs(900))
            .expect("still unlocked");
        assert!((449..=450).contains(&remaining));
    }

    #[test]
    fn idle_remaining_saturates_to_zero_past_timeout() {
        let (_tmp, path) = write_fixture();
        let mut vault = Vault::new(path);
        vault.unlock(TEST_PASSWORD, None).expect("unlock");
        let now = Instant::now();
        // Past the timeout but not yet locked: reports zero, not an underflow.
        let later = now + Duration::from_secs(1_000);
        assert_eq!(
            vault.idle_remaining(later, Duration::from_secs(900)),
            Some(0)
        );
    }
}
