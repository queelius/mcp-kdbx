//! Startup cleanup of leftover `*.tmp.*` save files.
//!
//! The save flow (see `stage`) writes the new vault bytes to a temp file in the
//! vault's own directory, named `<vault_file>.tmp.<pid>.<nonce>` (decimal; see
//! `vault_file::TempName`), then fsyncs and atomically renames it over the
//! vault. If the process is killed between the
//! temp write and the rename, that temp file is orphaned: it never became the
//! vault and nothing will ever rename it away.
//!
//! [`clean_orphans`] scans the vault's directory for such leftovers belonging to
//! THIS vault and unlinks the ones older than one hour. The age floor is a guard
//! against racing a live process: another mcp-kdbx instance (or a concurrent save
//! in this one) may be mid-write on a temp file right now, and a recently-modified
//! temp file might still be in use.
//!
//! This runs only when `KDBX_AUTO_CLEAN_ORPHANS=true`. The config gate is checked
//! by the caller (spec section 2, startup step 8); this function just performs the
//! scan when asked and returns a [`CleanReport`] for the caller to log. It does not
//! touch the audit log itself.

use crate::engine::vault_file::TempName;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// One hour, in seconds. A temp file must be older than this to be removed.
const ORPHAN_MIN_AGE: Duration = Duration::from_secs(3600);

/// Summary of one cleanup pass.
///
/// `removed` lists the temp files that were unlinked. `skipped_recent` counts
/// matching temp files left in place because they were newer than the age floor
/// (a live process may still be writing them). `errors` collects per-file or
/// directory-level problems as strings; a single failure does not abort the scan.
#[derive(Debug, Default)]
pub struct CleanReport {
    pub removed: Vec<PathBuf>,
    pub skipped_recent: usize,
    pub errors: Vec<String>,
}

/// Scan the vault's directory and remove orphaned save temp files older than one
/// hour. `now` is injected (rather than read from `SystemTime::now()` inside) so
/// callers and tests control the clock and the result is deterministic.
///
/// Conservative by design: it only considers files whose name parses as a
/// `vault_file::TempName` for this exact vault (`<vault_file>.tmp.<pid>.<nonce>`,
/// both decimal), so the vault file itself and unrelated files in the directory
/// are never candidates. When a
/// file cannot be stat'd or its age cannot be computed, it is skipped and the
/// reason recorded, not removed.
///
/// Runs only when `KDBX_AUTO_CLEAN_ORPHANS=true`; that gate is the caller's
/// responsibility (spec section 2, startup step 8).
pub fn clean_orphans(vault_path: &Path, now: SystemTime) -> CleanReport {
    let mut report = CleanReport::default();
    // Saves resolve symlinks and write their temp files next to the real vault
    // file, so scan there. A path that cannot be resolved is scanned as given.
    let resolved = std::fs::canonicalize(vault_path).ok();
    let vault_path = resolved.as_deref().unwrap_or(vault_path);

    let parent = match vault_path.parent() {
        // An empty parent ("") means the current directory; normalize to ".".
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };

    let vault_file = match vault_path.file_name().and_then(|n| n.to_str()) {
        Some(name) => name,
        None => {
            report.errors.push(format!(
                "vault path has no file name component: {}",
                vault_path.display()
            ));
            return report;
        }
    };

    let entries = match fs::read_dir(parent) {
        Ok(entries) => entries,
        Err(err) => {
            // Unreadable or missing directory: report it, do not panic, return
            // an otherwise empty report.
            report.errors.push(format!(
                "cannot read vault directory {}: {err}",
                parent.display()
            ));
            return report;
        }
    };

    for entry in entries {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                report
                    .errors
                    .push(format!("cannot read a directory entry: {err}"));
                continue;
            }
        };

        let name = match entry.file_name().into_string() {
            Ok(name) => name,
            // Non-UTF-8 names cannot match our ASCII pattern; skip quietly.
            Err(_) => continue,
        };

        if !is_orphan_temp_name(&name, vault_file) {
            continue;
        }

        let path = entry.path();

        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(err) => {
                report
                    .errors
                    .push(format!("cannot stat {}: {err}", path.display()));
                continue;
            }
        };

        // Only regular files are removed; a directory that happens to match the
        // name pattern is left alone.
        if !metadata.is_file() {
            continue;
        }

        let modified = match metadata.modified() {
            Ok(modified) => modified,
            Err(err) => {
                report.errors.push(format!(
                    "cannot read modified time of {}: {err}",
                    path.display()
                ));
                continue;
            }
        };

        // Age is now minus modified. If the file is from the future relative to
        // `now` (clock skew, or an injected past `now`), treat it as recent.
        match now.duration_since(modified) {
            Ok(age) if age > ORPHAN_MIN_AGE => match fs::remove_file(&path) {
                Ok(()) => report.removed.push(path),
                Err(err) => report
                    .errors
                    .push(format!("cannot remove {}: {err}", path.display())),
            },
            Ok(_) => report.skipped_recent += 1,
            Err(_) => report.skipped_recent += 1,
        }
    }

    report
}

/// True when `name` is a save temp file for the vault file `vault_file`: it
/// parses as a [`TempName`] for that vault, the same type the writer formats
/// the name with. Anything the writer could not have produced is left alone.
/// Skipping a real orphan is cheap (it gets cleaned next time, or by hand);
/// removing the wrong file is not.
fn is_orphan_temp_name(name: &str, vault_file: &str) -> bool {
    TempName::parse(name, vault_file).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    /// `now` two hours ahead makes a just-created file read as two hours old, so
    /// it is past the one-hour floor and eligible for removal.
    fn two_hours_ahead() -> SystemTime {
        SystemTime::now() + Duration::from_secs(7200)
    }

    fn touch(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        let mut f = File::create(&path).expect("create test file");
        f.write_all(b"x").expect("write test file");
        path
    }

    #[test]
    fn removes_orphan_temp_older_than_one_hour() {
        let dir = tempdir().unwrap();
        let vault = touch(dir.path(), "vault.kdbx");
        let orphan = touch(dir.path(), "vault.kdbx.tmp.12345.67890");

        let report = clean_orphans(&vault, two_hours_ahead());

        assert_eq!(report.removed, vec![orphan.clone()]);
        assert!(!orphan.exists(), "orphan temp should be unlinked");
        assert!(vault.exists(), "vault file must never be removed");
        assert_eq!(report.skipped_recent, 0);
        assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
    }

    #[test]
    fn never_removes_the_vault_file_itself() {
        let dir = tempdir().unwrap();
        let vault = touch(dir.path(), "vault.kdbx");

        // `now` far in the future: even so, the vault is not a temp file.
        let report = clean_orphans(&vault, two_hours_ahead());

        assert!(vault.exists(), "vault file must never be removed");
        assert!(report.removed.is_empty());
    }

    #[test]
    fn never_removes_unrelated_files() {
        let dir = tempdir().unwrap();
        let vault = touch(dir.path(), "vault.kdbx");
        let other = touch(dir.path(), "other.txt");
        let backup = touch(dir.path(), "vault.kdbx.bak");
        // A temp file for a DIFFERENT vault must also be left alone.
        let other_vault_tmp = touch(dir.path(), "elsewhere.kdbx.tmp.999.111");

        let report = clean_orphans(&vault, two_hours_ahead());

        assert!(other.exists(), "unrelated file must survive");
        assert!(backup.exists(), "backup file must survive");
        assert!(other_vault_tmp.exists(), "other vault's temp must survive");
        assert!(report.removed.is_empty(), "removed: {:?}", report.removed);
    }

    #[test]
    fn skips_recent_temp() {
        let dir = tempdir().unwrap();
        let vault = touch(dir.path(), "vault.kdbx");
        let recent = touch(dir.path(), "vault.kdbx.tmp.777.888");

        // `now` is the real present, so a just-created file has age ~0.
        let report = clean_orphans(&vault, SystemTime::now());

        assert!(recent.exists(), "recent temp must be left in place");
        assert!(report.removed.is_empty());
        assert_eq!(report.skipped_recent, 1);
        assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
    }

    #[test]
    fn under_matched_temp_names_are_left_alone() {
        let dir = tempdir().unwrap();
        let vault = touch(dir.path(), "vault.kdbx");
        // Bare ".tmp." with nothing after: must not match.
        let bare = touch(dir.path(), "vault.kdbx.tmp.");
        // pid but no rand component: must not match.
        let no_rand = touch(dir.path(), "vault.kdbx.tmp.12345");

        let report = clean_orphans(&vault, two_hours_ahead());

        assert!(bare.exists(), "bare .tmp. must not be matched");
        assert!(no_rand.exists(), "pid-only temp must not be matched");
        assert!(report.removed.is_empty(), "removed: {:?}", report.removed);
    }

    #[test]
    fn non_numeric_temp_lookalikes_are_left_alone() {
        // The writer only ever produces "<vault>.tmp.<digits>.<digits>", so a
        // user's backup that merely starts with ".tmp." is not ours to delete.
        let dir = tempdir().unwrap();
        let vault = touch(dir.path(), "vault.kdbx");
        let keep = [
            touch(dir.path(), "vault.kdbx.tmp.old.bak"),
            touch(dir.path(), "vault.kdbx.tmp.123.abc"),
            touch(dir.path(), "vault.kdbx.tmp.1.2.3"),
            touch(dir.path(), "vault.kdbx.tmp.-1.2"),
        ];

        let report = clean_orphans(&vault, two_hours_ahead());

        for f in &keep {
            assert!(f.exists(), "{} must survive", f.display());
        }
        assert!(report.removed.is_empty(), "removed: {:?}", report.removed);
    }

    #[test]
    fn unreadable_directory_yields_empty_report_without_panic() {
        // Point at a vault inside a directory that does not exist.
        let missing = Path::new("/no/such/dir/vault.kdbx");

        let report = clean_orphans(missing, two_hours_ahead());

        assert!(report.removed.is_empty());
        assert_eq!(report.skipped_recent, 0);
        assert_eq!(report.errors.len(), 1, "errors: {:?}", report.errors);
    }

    #[test]
    fn multiple_orphans_all_removed() {
        let dir = tempdir().unwrap();
        let vault = touch(dir.path(), "vault.kdbx");
        let a = touch(dir.path(), "vault.kdbx.tmp.1.111");
        let b = touch(dir.path(), "vault.kdbx.tmp.2.222");

        let report = clean_orphans(&vault, two_hours_ahead());

        assert_eq!(report.removed.len(), 2);
        assert!(!a.exists());
        assert!(!b.exists());
        assert!(vault.exists());
        assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
    }

    #[test]
    fn directory_matching_temp_pattern_is_left_alone() {
        // A directory whose name matches the temp pattern must survive: the
        // !is_file() guard skips it. We push `now` two hours ahead so age is not
        // the reason it survives; only the is_file check can be.
        let dir = tempdir().unwrap();
        let vault = touch(dir.path(), "vault.kdbx");
        let dir_named_like_temp = dir.path().join("vault.kdbx.tmp.1.333");
        std::fs::create_dir(&dir_named_like_temp).expect("create dir named like a temp file");

        let report = clean_orphans(&vault, two_hours_ahead());

        assert!(
            dir_named_like_temp.exists() && dir_named_like_temp.is_dir(),
            "a directory matching the temp pattern must be left alone"
        );
        assert!(
            !report.removed.contains(&dir_named_like_temp),
            "the directory must not be in report.removed: {:?}",
            report.removed
        );
        assert!(vault.exists(), "vault file must never be removed");
    }

    #[test]
    #[cfg(unix)]
    fn cleans_next_to_the_symlink_target() {
        // Saves write their temp files next to the resolved vault file, so the
        // cleanup must look there too when the configured path is a link.
        let real_dir = tempdir().unwrap();
        let link_dir = tempdir().unwrap();
        let vault = touch(real_dir.path(), "vault.kdbx");
        let orphan = touch(real_dir.path(), "vault.kdbx.tmp.12345.67890");
        let link = link_dir.path().join("link.kdbx");
        std::os::unix::fs::symlink(&vault, &link).unwrap();

        let report = clean_orphans(&link, two_hours_ahead());

        assert!(!orphan.exists(), "orphan next to the target is removed");
        assert!(vault.exists());
        assert!(report.errors.is_empty(), "errors: {:?}", report.errors);
    }

    #[test]
    fn name_matcher_is_structural() {
        assert!(is_orphan_temp_name("vault.kdbx.tmp.123.456", "vault.kdbx"));
        // Wrong vault.
        assert!(!is_orphan_temp_name("other.kdbx.tmp.123.456", "vault.kdbx"));
        // The vault itself.
        assert!(!is_orphan_temp_name("vault.kdbx", "vault.kdbx"));
        // Missing rand component.
        assert!(!is_orphan_temp_name("vault.kdbx.tmp.123", "vault.kdbx"));
        // Nothing after the infix.
        assert!(!is_orphan_temp_name("vault.kdbx.tmp.", "vault.kdbx"));
        // Empty pid component.
        assert!(!is_orphan_temp_name("vault.kdbx.tmp..456", "vault.kdbx"));
    }
}
