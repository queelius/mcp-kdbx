//! The vault file on disk: content identity, the writer lock, and the atomic
//! replace.
//!
//! The save path (`stage::save_pending`) composes three pieces from here:
//!
//! 1. [`FileFingerprint`]: the identity of the exact bytes a session parsed.
//!    It is a sha256 of the file content plus the mtime read from the same open
//!    handle. External-modification detection compares the content hash, never
//!    the mtime: a timestamp can move backward (a restore or sync tool that
//!    preserves an older mtime) or land inside any slack window, and both used
//!    to let a save silently clobber another writer. The mtime is kept only for
//!    reporting (audit events and error details).
//! 2. [`WriterLock`]: an advisory exclusive lock on a sidecar `<vault>.lock`
//!    file, held across re-read, compare, write, and rename so two mcp-kdbx
//!    instances cannot interleave their check and their rename. It uses the
//!    standard library's `File::try_lock` (flock(2) on Unix), so it adds no
//!    dependency. The sidecar is never deleted: removing a lock file while
//!    another process may be about to open it is its own race.
//! 3. [`write_atomically`]: temp file in the same directory, fsync, rename over
//!    the vault, fsync the directory. The save first resolves symlinks
//!    ([`resolve_write_target`]) so a linked vault stays linked.
//!
//! Residual risk, documented in the spec: the lock coordinates mcp-kdbx
//! instances only. Another program (KeePassXC) does not take it, so a write by
//! that program landing between the re-read and the rename (a window of one
//! write and one rename) is not detected. Everything outside that window is.

use crate::kdbx_core::error::{CoreError, CoreResult, ErrorCode};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

/// How long a save waits for another mcp-kdbx instance to release the writer
/// lock before giving up with `WRITE_FAILED`. Another instance holds it only
/// for one re-read, write, and rename, so a few seconds is generous.
pub const WRITER_LOCK_WAIT: Duration = Duration::from_secs(5);

/// The poll interval while waiting for the writer lock.
const WRITER_LOCK_POLL: Duration = Duration::from_millis(25);

/// The identity of one version of the vault file: a sha256 of its bytes, plus
/// the mtime observed on the same open handle (for reporting only).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileFingerprint {
    sha256: [u8; 32],
    mtime: SystemTime,
}

impl FileFingerprint {
    /// Fingerprint `bytes` observed with modification time `mtime`.
    pub fn new(bytes: &[u8], mtime: SystemTime) -> FileFingerprint {
        FileFingerprint {
            sha256: Sha256::digest(bytes).into(),
            mtime,
        }
    }

    /// True when `other` has the same content (the mtime is ignored).
    pub fn same_content(&self, other: &FileFingerprint) -> bool {
        self.sha256 == other.sha256
    }

    /// The mtime observed alongside the content.
    pub fn mtime(&self) -> SystemTime {
        self.mtime
    }
}

/// Read the whole vault file through one open handle and fingerprint it. The
/// mtime comes from that handle's metadata, so it describes the same inode the
/// bytes came from even if the path is replaced concurrently.
pub fn read_with_fingerprint(path: &Path) -> std::io::Result<(Vec<u8>, FileFingerprint)> {
    let mut file = File::open(path)?;
    let mtime = file.metadata()?.modified()?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    let fingerprint = FileFingerprint::new(&bytes, mtime);
    Ok((bytes, fingerprint))
}

/// The file a save must replace: `path` with every symlink resolved.
///
/// The atomic rename replaces whatever directory entry it targets. Renaming
/// onto the configured path when it is a symlink would replace the link with a
/// regular file, silently detaching the vault from the file the link pointed
/// at (a dotfile manager's or sync folder's copy). So the save resolves the
/// link and works next to the real file: the temp file, the rename, and the
/// writer lock all use the resolved path, which also means two instances that
/// reach one vault through different links share one lock. A vault file that
/// no longer exists is `WRITE_FAILED`.
pub fn resolve_write_target(path: &Path) -> CoreResult<PathBuf> {
    std::fs::canonicalize(path).map_err(|e| {
        CoreError::new(ErrorCode::WriteFailed)
            .with_message(format!("could not resolve the vault file path: {e}"))
            .with_details(serde_json::json!({ "step": SaveStep::Reread }))
    })
}

/// The sidecar lock-file path for `vault`: `<vault>.lock` in the same
/// directory.
pub fn lock_path(vault: &Path) -> PathBuf {
    let mut name = vault
        .file_name()
        .map(|n| n.to_os_string())
        .unwrap_or_default();
    name.push(".lock");
    vault.with_file_name(name)
}

/// An exclusive advisory lock on a vault's sidecar lock file. Released when
/// dropped (closing the file releases the flock).
#[derive(Debug)]
pub struct WriterLock {
    _file: File,
}

impl WriterLock {
    /// Take the writer lock for `vault`, waiting up to `wait` for another
    /// holder to release it. A lock that is still held after `wait`, or a lock
    /// file that cannot be opened, is `WRITE_FAILED`.
    pub fn acquire(vault: &Path, wait: Duration) -> CoreResult<WriterLock> {
        let path = lock_path(vault);
        let file = open_lock_file(&path).map_err(|e| {
            CoreError::new(ErrorCode::WriteFailed)
                .with_message(format!(
                    "could not open the writer lock file {}: {e}",
                    path.display()
                ))
                .with_details(serde_json::json!({ "step": SaveStep::Lock }))
        })?;
        let deadline = Instant::now() + wait;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(WriterLock { _file: file }),
                Err(std::fs::TryLockError::WouldBlock) if Instant::now() < deadline => {
                    std::thread::sleep(WRITER_LOCK_POLL);
                }
                Err(std::fs::TryLockError::WouldBlock) => {
                    return Err(CoreError::new(ErrorCode::WriteFailed)
                        .with_message(
                            "another mcp-kdbx instance is saving this vault; try again shortly",
                        )
                        .with_details(serde_json::json!({ "step": SaveStep::Lock })));
                }
                Err(std::fs::TryLockError::Error(e)) => {
                    return Err(CoreError::new(ErrorCode::WriteFailed)
                        .with_message(format!("could not take the writer lock: {e}"))
                        .with_details(serde_json::json!({ "step": SaveStep::Lock })));
                }
            }
        }
    }
}

/// Open (creating if needed) the sidecar lock file, owner-only on Unix.
fn open_lock_file(path: &Path) -> std::io::Result<File> {
    let mut options = File::options();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path)
}

/// Which step of a save failed. Carried as `details.step` on `WRITE_FAILED` so
/// the agent and the audit trail can tell a lock timeout from a disk error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SaveStep {
    /// Taking the writer lock.
    Lock,
    /// Re-reading the vault file for the conflict check.
    Reread,
    /// Serializing (and encrypting) the working database.
    Serialize,
    /// Writing and syncing the temp file.
    WriteTemp,
    /// Renaming the temp file over the vault.
    Rename,
}

/// Write `bytes` to `path` atomically: a uniquely-named temp file in the same
/// directory, `write_all`, fsync, rename over `path`, then a best-effort fsync
/// of the parent directory. Returns the fingerprint of what was written (the
/// mtime is read from the temp file's handle after the sync, which the rename
/// preserves). On any pre-rename failure the temp file is unlinked and
/// `WRITE_FAILED` is returned, so the vault is untouched.
pub fn write_atomically(path: &Path, bytes: &[u8]) -> CoreResult<FileFingerprint> {
    use std::io::Write;

    let parent = path.parent().ok_or_else(|| {
        CoreError::new(ErrorCode::WriteFailed).with_message("vault path has no parent directory")
    })?;

    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "vault.kdbx".to_string());

    let temp_path = parent.join(format!(
        "{}.tmp.{}.{}",
        file_name,
        std::process::id(),
        temp_suffix()
    ));

    // create_new (O_EXCL) refuses to clobber a pre-existing temp file. Any
    // failure here unlinks the temp and surfaces WRITE_FAILED; the vault file
    // is untouched.
    let write_result = (|| -> std::io::Result<SystemTime> {
        let mut file = File::options()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        file.metadata()?.modified()
    })();
    let mtime = match write_result {
        Ok(mtime) => mtime,
        Err(e) => {
            let _ = std::fs::remove_file(&temp_path);
            return Err(CoreError::new(ErrorCode::WriteFailed)
                .with_message(format!("writing the temp file failed: {e}"))
                .with_details(serde_json::json!({ "step": SaveStep::WriteTemp })));
        }
    };

    // Preserve the user's file hardening across the rename (see
    // preserve_temp_permissions).
    preserve_temp_permissions(path, &temp_path);

    if let Err(e) = std::fs::rename(&temp_path, path) {
        let _ = std::fs::remove_file(&temp_path);
        return Err(CoreError::new(ErrorCode::WriteFailed)
            .with_message(format!("renaming the temp file over the vault failed: {e}"))
            .with_details(serde_json::json!({ "step": SaveStep::Rename })));
    }

    // Best-effort parent-directory fsync for POSIX durability. The rename has
    // already happened, so a failure here does not corrupt anything.
    if let Ok(dir) = File::open(parent) {
        let _ = dir.sync_all();
    }

    Ok(FileFingerprint::new(bytes, mtime))
}

/// Copy the existing vault file's permission bits onto the temp file so the
/// atomic rename preserves the user's hardening. When the vault file does not
/// yet exist (a first save), fall back to 0600. Any error is swallowed: the
/// save is more important than the mode tweak.
#[cfg(unix)]
fn preserve_temp_permissions(vault_path: &Path, temp_path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let perms = match std::fs::metadata(vault_path) {
        Ok(meta) => meta.permissions(),
        Err(_) => std::fs::Permissions::from_mode(0o600),
    };
    let _ = std::fs::set_permissions(temp_path, perms);
}

/// Non-Unix fallback: no POSIX permission model to copy.
#[cfg(not(unix))]
fn preserve_temp_permissions(_vault_path: &Path, _temp_path: &Path) {}

/// A per-call suffix for the temp file name, from the current time's nanos.
/// Combined with the pid in the name, unique enough for a short-lived file.
fn temp_suffix() -> u128 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_identity_is_the_content_not_the_mtime() {
        let t0 = SystemTime::UNIX_EPOCH;
        let t1 = t0 + Duration::from_secs(10);
        assert!(FileFingerprint::new(b"abc", t0).same_content(&FileFingerprint::new(b"abc", t1)));
        assert!(!FileFingerprint::new(b"abc", t0).same_content(&FileFingerprint::new(b"abd", t0)));
    }

    #[test]
    fn read_with_fingerprint_hashes_the_bytes_read() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("v.kdbx");
        std::fs::write(&p, b"vault bytes").unwrap();
        let (bytes, fp) = read_with_fingerprint(&p).unwrap();
        assert_eq!(bytes, b"vault bytes");
        assert!(fp.same_content(&FileFingerprint::new(b"vault bytes", fp.mtime())));
        assert_eq!(
            fp.mtime(),
            std::fs::metadata(&p).unwrap().modified().unwrap()
        );
    }

    #[test]
    fn lock_path_is_a_sidecar_next_to_the_vault() {
        assert_eq!(
            lock_path(Path::new("/a/b/vault.kdbx")),
            PathBuf::from("/a/b/vault.kdbx.lock")
        );
    }

    #[test]
    fn writer_lock_excludes_a_second_holder_until_released() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v.kdbx");
        std::fs::write(&vault, b"x").unwrap();

        let held = WriterLock::acquire(&vault, Duration::ZERO).expect("first holder");
        // flock is per open file description, so a second open in this process
        // contends exactly like another process would.
        let err = WriterLock::acquire(&vault, Duration::from_millis(60))
            .expect_err("second holder must wait and give up");
        assert_eq!(err.code_enum(), ErrorCode::WriteFailed);
        assert_eq!(err.details().unwrap()["step"], serde_json::json!("lock"));

        drop(held);
        WriterLock::acquire(&vault, Duration::ZERO).expect("free after release");
    }

    #[test]
    fn write_atomically_returns_the_fingerprint_of_what_it_wrote() {
        let dir = tempfile::tempdir().unwrap();
        let vault = dir.path().join("v.kdbx");
        std::fs::write(&vault, b"old").unwrap();
        let fp = write_atomically(&vault, b"new contents").unwrap();
        let (bytes, on_disk) = read_with_fingerprint(&vault).unwrap();
        assert_eq!(bytes, b"new contents");
        assert_eq!(fp, on_disk);
    }
}
