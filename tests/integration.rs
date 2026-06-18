//! Layer 2 integration suite: stateful flows over the real binary.
//!
//! These cover the behaviors that span more than one tool call or that touch
//! disk, the parts a per-tool shape check (in `protocol_conformance.rs`) cannot
//! reach:
//!
//! - the audit log file: an unlock and a reveal are recorded, and the revealed
//!   value never appears in plaintext (only its domain-separated sha256),
//! - the stage-then-commit cycle persists across a reopen,
//! - a manual lock discards the stage and the first locked call reports what was
//!   dropped,
//! - the idle timer locks an untouched vault (short TTL),
//! - an external write to the vault file refuses the save with VAULT_FILE_MODIFIED.

mod common;

use std::time::{Duration, SystemTime};

use common::*;
use mcp_kdbx::kdbx_core::audit::hash_revealed;
use serde_json::{Value, json};

/// Spawn against a writable temp copy of a fixture, with the given extra env,
/// and unlock. Returns the tempdir guard (which must outlive the server), the
/// path to the vault copy, and the unlocked server.
fn writable(
    fixture: &str,
    extra_env: &[(&str, &str)],
) -> (tempfile::TempDir, std::path::PathBuf, McpServer) {
    let (dir, path) = temp_copy_of(fixture);
    let mut envs = vec![
        ("KDBX_VAULT_PATH", path.to_str().unwrap()),
        ("KDBX_ALLOW_WRITES", "true"),
    ];
    envs.extend_from_slice(extra_env);
    let mut server = McpServer::spawn(&envs);
    server.unlock_with_fixture_password();
    (dir, path, server)
}

/// Read a JSONL audit file into one `Value` per non-empty line.
fn read_audit_lines(path: &std::path::Path) -> Vec<Value> {
    let text = std::fs::read_to_string(path).expect("read audit log file");
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("audit line is JSON"))
        .collect()
}

#[test]
fn audit_log_records_unlock_and_reveal_without_plaintext() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let vault = fixture_path("flat.kdbx");

    let mut server = McpServer::spawn(&[
        ("KDBX_VAULT_PATH", vault.to_str().unwrap()),
        ("KDBX_LOG_FILE", log_path.to_str().unwrap()),
    ]);
    server.unlock_with_fixture_password();
    let revealed = server.call_ok("kdbx_reveal_password", json!({ "path": "/Bank" }));
    assert_eq!(revealed["password"], json!("bank-secret-456"));

    let events = read_audit_lines(&log_path);

    // The unlock was recorded, with the source the password came from (input).
    let unlocked = events
        .iter()
        .find(|e| e["event"] == json!("vault_unlocked"))
        .expect("vault_unlocked event present");
    assert_eq!(unlocked["details"]["unlock_source"], json!("input"));
    assert_eq!(unlocked["level"], json!("info"));

    // The reveal was recorded with the domain-separated sha256, never the value.
    let reveal = events
        .iter()
        .find(|e| e["event"] == json!("reveal_password"))
        .expect("reveal_password event present");
    assert_eq!(reveal["details"]["target_path"], json!("/Bank"));
    assert_eq!(
        reveal["details"]["sha256"],
        json!(hash_revealed("bank-secret-456")),
        "reveal event must log the domain-separated hash of the value"
    );

    // The security invariant: neither the revealed value nor the master password
    // appears anywhere in the audit file.
    let raw = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !raw.contains("bank-secret-456"),
        "revealed value leaked into the audit log"
    );
    assert!(
        !raw.contains(FIXTURE_PASSWORD),
        "master password leaked into the audit log"
    );
}

#[test]
fn stage_save_reopen_persists_changes() {
    let (_dir, path, mut server) = writable("flat.kdbx", &[]);

    // Stage a field change and a brand-new entry, then commit.
    server.call_ok(
        "kdbx_update_field",
        json!({ "path": "/GitHub", "field_name": "URL", "value": "https://changed.example" }),
    );
    server.call_ok(
        "kdbx_add_entry",
        json!({ "group_path": "/", "title": "Persisted", "fields": { "UserName": { "value": "persisted-user", "protected": false } } }),
    );
    let saved = server.call_ok("kdbx_save_pending", json!({}));
    assert_eq!(saved["num_changes"], json!(2));
    drop(server);

    // Reopen the same file in a fresh process and confirm both changes survived
    // the atomic save and the round-trip through KDBX serialization.
    let mut reopened = McpServer::spawn(&[("KDBX_VAULT_PATH", path.to_str().unwrap())]);
    reopened.unlock_with_fixture_password();

    let github = reopened.call_ok("kdbx_get_entry", json!({ "path": "/GitHub" }));
    assert_eq!(github["url"], json!("https://changed.example"));

    let persisted = reopened.call_ok("kdbx_get_entry", json!({ "path": "/Persisted" }));
    assert_eq!(persisted["title"], json!("Persisted"));
    assert_eq!(persisted["username"], json!("persisted-user"));
}

#[test]
fn manual_lock_discards_stage_and_first_locked_call_reports_it() {
    let (_dir, _path, mut server) = writable("flat.kdbx", &[]);

    // Stage one change, then lock manually. The lock reports one discarded.
    server.call_ok(
        "kdbx_update_field",
        json!({ "path": "/GitHub", "field_name": "URL", "value": "https://staged-but-discarded.example" }),
    );
    let locked = server.call_ok("kdbx_lock", json!({}));
    assert_eq!(locked["pending_discarded"], json!(1));

    // The first call after the lock carries the discard details so the agent can
    // recover.
    let first = server.call_error("kdbx_list_entries", json!({ "group_path": "/" }));
    assert_eq!(first["code"], json!("VAULT_LOCKED"));
    assert_eq!(first["details"]["lock_reason"], json!("manual"));
    assert_eq!(first["details"]["pending_discarded_count"], json!(1));
    let summary = first["details"]["pending_discarded_summary"]
        .as_array()
        .unwrap();
    assert_eq!(summary.len(), 1);
    assert_eq!(summary[0], json!("/GitHub"));

    // The details are reported once: the next locked call is bare.
    let second = server.call_error("kdbx_list_entries", json!({ "group_path": "/" }));
    assert_eq!(second["code"], json!("VAULT_LOCKED"));
    assert!(
        second.get("details").is_none(),
        "discard details are reported only on the first locked call"
    );
}

#[test]
fn external_modification_refuses_save_with_conflict() {
    let (_dir, path, mut server) = writable("flat.kdbx", &[]);

    server.call_ok(
        "kdbx_update_field",
        json!({ "path": "/GitHub", "field_name": "URL", "value": "https://mine.example" }),
    );

    // Simulate another writer (KeePassXC, a second mcp-kdbx) touching the file:
    // push its mtime well past the mtime captured at unlock. The save must refuse
    // rather than clobber the external change.
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open vault file to bump mtime");
    file.set_modified(SystemTime::now() + Duration::from_secs(30))
        .expect("set a future mtime on the vault file");
    drop(file);

    let err = server.call_error("kdbx_save_pending", json!({}));
    assert_eq!(err["code"], json!("VAULT_FILE_MODIFIED"));
    assert!(err["details"]["file_mtime_now"].is_string());
    assert!(err["details"]["file_mtime_at_unlock"].is_string());

    // The stage is preserved (the save was refused, not discarded): a diff still
    // shows the pending change.
    let diff = server.call_ok("kdbx_diff_pending", json!({}));
    assert_eq!(diff["summary"]["num_modified"], json!(1));
}

/// Idle-timeout test. The idle timer ticks on an interval clamped to a 5-second
/// floor, so even a 1-second TTL needs roughly one tick to fire. This test
/// therefore waits several seconds; it is the slowest in the suite.
#[test]
fn idle_timeout_locks_untouched_vault_and_discards_stage() {
    let (_dir, _path, mut server) = writable("flat.kdbx", &[("KDBX_IDLE_TIMEOUT_SECONDS", "1")]);

    // Stage a change so the idle lock has something to discard.
    server.call_ok(
        "kdbx_update_field",
        json!({ "path": "/GitHub", "field_name": "URL", "value": "https://will-be-dropped.example" }),
    );

    // Wait past one timer tick without making any call (a call would reset the
    // idle clock; kdbx_status is itself a keep-alive).
    std::thread::sleep(Duration::from_secs(7));

    // The next call finds the vault idle-locked, with the staged change reported
    // as discarded.
    let err = server.call_error("kdbx_list_entries", json!({ "group_path": "/" }));
    assert_eq!(err["code"], json!("VAULT_LOCKED"));
    assert_eq!(err["details"]["lock_reason"], json!("idle_timeout"));
    assert_eq!(err["details"]["pending_discarded_count"], json!(1));
}
