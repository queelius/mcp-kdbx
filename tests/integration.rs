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
//! - an external write to the vault file refuses the save with VAULT_FILE_MODIFIED,
//! - an untitled entry never aliases another entry through its path.

mod common;

use std::time::Duration;

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

/// A protected standard field (KeePassXC's per-attribute "Protect" toggle on
/// UserName or Notes) must behave like any other protected value: bulk reads
/// return it as null and mark it protected, search never matches it, and the
/// only way out is `kdbx_reveal_protected`, which audits a sha256 of the value.
#[test]
fn protected_standard_fields_are_hidden_from_reads_and_search_but_revealable() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let (_vault_dir, _path, mut server) = writable(
        "flat.kdbx",
        &[("KDBX_LOG_FILE", log_path.to_str().unwrap())],
    );

    // Flip protection on in place: same values, now protected.
    server.call_ok(
        "kdbx_update_field",
        json!({ "path": "/GitHub", "field_name": "UserName", "value": "octocat", "protected": true }),
    );
    server.call_ok(
        "kdbx_update_field",
        json!({ "path": "/GitHub", "field_name": "Notes", "value": "primary dev account", "protected": true }),
    );

    // Summary view (list): protected values are null and flagged; the
    // unprotected URL is unchanged.
    let listed = server.call_ok("kdbx_list_entries", json!({ "group_path": "/" }));
    let github = listed["entries"]
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["title"] == json!("GitHub"))
        .expect("GitHub listed")
        .clone();
    assert_eq!(github["username"], Value::Null);
    assert_eq!(github["notes_preview"], Value::Null);
    assert_eq!(github["url"], json!("https://github.com"));
    let flags: Vec<(String, bool)> = github["standard_field_names"]
        .as_array()
        .unwrap()
        .iter()
        .map(|f| {
            (
                f["name"].as_str().unwrap().to_string(),
                f["protected"].as_bool().unwrap(),
            )
        })
        .collect();
    assert!(flags.contains(&("UserName".to_string(), true)), "{flags:?}");
    assert!(flags.contains(&("Notes".to_string(), true)), "{flags:?}");
    assert!(flags.contains(&("URL".to_string(), false)), "{flags:?}");

    // Full view (get): same treatment, full notes field is null too.
    let detail = server.call_ok("kdbx_get_entry", json!({ "path": "/GitHub" }));
    assert_eq!(detail["username"], Value::Null);
    assert_eq!(detail["notes"], Value::Null);
    assert_eq!(detail["url"], json!("https://github.com"));
    let detail_text = detail.to_string();
    assert!(!detail_text.contains("octocat") && !detail_text.contains("primary dev account"));

    // Search is not an oracle on the protected values, but unprotected fields
    // still match.
    let by_user = server.call_ok("kdbx_find_entry", json!({ "query": "octocat" }));
    assert_eq!(by_user["matched_count"], json!(0));
    let by_notes = server.call_ok(
        "kdbx_find_entry",
        json!({ "query": "primary dev", "fields": ["notes"] }),
    );
    assert_eq!(by_notes["matched_count"], json!(0));
    let by_url = server.call_ok(
        "kdbx_find_entry",
        json!({ "query": "github.com", "fields": ["url"] }),
    );
    assert_eq!(by_url["matched_count"], json!(1));

    // The consent-gated reveal returns each value by its standard field name.
    let user = server.call_ok(
        "kdbx_reveal_protected",
        json!({ "path": "/GitHub", "field_name": "UserName" }),
    );
    assert_eq!(user["value"], json!("octocat"));
    let notes = server.call_ok(
        "kdbx_reveal_protected",
        json!({ "path": "/GitHub", "field_name": "Notes" }),
    );
    assert_eq!(notes["value"], json!("primary dev account"));

    // Each reveal is audited with the domain-separated hash, never the value.
    let events = read_audit_lines(&log_path);
    for (field, value) in [("UserName", "octocat"), ("Notes", "primary dev account")] {
        let reveal = events
            .iter()
            .find(|e| {
                e["event"] == json!("reveal_protected")
                    && e["details"]["field_name"] == json!(field)
            })
            .unwrap_or_else(|| panic!("reveal_protected event for {field} present"));
        assert_eq!(reveal["details"]["target_path"], json!("/GitHub"));
        assert_eq!(reveal["details"]["sha256"], json!(hash_revealed(value)));
    }
    let raw = std::fs::read_to_string(&log_path).unwrap();
    assert!(
        !raw.contains("octocat"),
        "revealed UserName leaked into the audit log"
    );
    assert!(
        !raw.contains("primary dev account"),
        "revealed Notes leaked into the audit log"
    );
}

#[test]
fn stage_save_reopen_persists_changes() {
    let (_dir, path, mut server) = writable("flat.kdbx", &[]);
    let modified_before =
        server.call_ok("kdbx_get_entry", json!({ "path": "/GitHub" }))["modified_at"].clone();

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
    // The edit bumped the entry's modification time (tracked edit).
    assert_ne!(github["modified_at"], modified_before);

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

    // Simulate another writer replacing the file, the way a restore or sync
    // tool does: new content, but an mtime older than the one seen at unlock.
    // The old mtime heuristic let this through; the content check must not.
    let before = std::fs::metadata(&path).unwrap().modified().unwrap();
    std::fs::copy(fixture_path("nested.kdbx"), &path).expect("external write");
    let file = std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .expect("open vault file to backdate mtime");
    file.set_modified(before - Duration::from_secs(60))
        .expect("backdate the vault file mtime");
    drop(file);

    let err = server.call_error("kdbx_save_pending", json!({}));
    assert_eq!(err["code"], json!("VAULT_FILE_MODIFIED"));
    assert!(err["details"]["file_mtime_now"].is_string());
    assert!(err["details"]["file_mtime_at_unlock"].is_string());
    assert_eq!(err["details"]["pending_changes"], json!(1));

    // The stage is preserved (the save was refused, not discarded): a diff still
    // shows the pending change.
    let diff = server.call_ok("kdbx_diff_pending", json!({}));
    assert_eq!(diff["summary"]["num_modified"], json!(1));
}

#[test]
fn concurrent_instances_first_save_wins_second_is_refused() {
    // Two mcp-kdbx processes on one vault, both staging a change. The first
    // save wins; the second is refused even though it lands within the same
    // second (the old one-second mtime slack let it clobber the first).
    let (_dir, path) = temp_copy_of("flat.kdbx");
    let envs = [
        ("KDBX_VAULT_PATH", path.to_str().unwrap()),
        ("KDBX_ALLOW_WRITES", "true"),
    ];
    let mut a = McpServer::spawn(&envs);
    let mut b = McpServer::spawn(&envs);
    a.unlock_with_fixture_password();
    b.unlock_with_fixture_password();

    a.call_ok(
        "kdbx_update_field",
        json!({ "path": "/GitHub", "field_name": "URL", "value": "https://from-a.example" }),
    );
    b.call_ok(
        "kdbx_update_field",
        json!({ "path": "/Bank", "field_name": "URL", "value": "https://from-b.example" }),
    );

    a.call_ok("kdbx_save_pending", json!({}));
    let err = b.call_error("kdbx_save_pending", json!({}));
    assert_eq!(err["code"], json!("VAULT_FILE_MODIFIED"));

    // A's change is on disk; B did not clobber it.
    drop(a);
    drop(b);
    let mut reader = McpServer::spawn(&[("KDBX_VAULT_PATH", path.to_str().unwrap())]);
    reader.unlock_with_fixture_password();
    let github = reader.call_ok("kdbx_get_entry", json!({ "path": "/GitHub" }));
    assert_eq!(github["url"], json!("https://from-a.example"));
}

#[test]
fn save_committed_audit_records_the_new_file_mtime() {
    let (dir, path) = temp_copy_of("flat.kdbx");
    let log = dir.path().join("audit.jsonl");
    let mut server = McpServer::spawn(&[
        ("KDBX_VAULT_PATH", path.to_str().unwrap()),
        ("KDBX_ALLOW_WRITES", "true"),
        ("KDBX_LOG_FILE", log.to_str().unwrap()),
    ]);
    server.unlock_with_fixture_password();
    server.call_ok(
        "kdbx_update_field",
        json!({ "path": "/GitHub", "field_name": "URL", "value": "https://x.example" }),
    );
    server.call_ok("kdbx_save_pending", json!({}));

    let mtime: chrono::DateTime<chrono::Utc> =
        std::fs::metadata(&path).unwrap().modified().unwrap().into();
    let lines = read_audit_lines(&log);
    let committed = lines
        .iter()
        .find(|l| l["event"] == json!("save_committed"))
        .expect("save_committed event");
    assert_eq!(
        committed["details"]["after_mtime"],
        json!(mtime.format("%Y-%m-%dT%H:%M:%SZ").to_string())
    );
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

/// Build a vault on disk holding a root entry titled "Email" and a group
/// "Email" that holds an entry with no Title. Returns the tempdir guard, the
/// vault path, and the untitled entry's uuid.
fn vault_with_untitled_entry_in_same_named_group() -> (tempfile::TempDir, std::path::PathBuf, String)
{
    use keepass::db::fields;
    let mut db = keepass::Database::new();
    db.root_mut().add_entry().edit(|e| {
        e.set_unprotected(fields::TITLE, "Email");
        e.set_protected(fields::PASSWORD, "root-email-secret");
    });
    let gid = db
        .root_mut()
        .add_group()
        .edit(|g| g.name = "Email".to_string())
        .id();
    let untitled = db
        .group_mut(gid)
        .unwrap()
        .add_entry()
        .edit(|e| e.set_protected(fields::PASSWORD, "untitled-secret"))
        .id();
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("aliasing.kdbx");
    let mut file = std::fs::File::create(&path).expect("create vault");
    db.save(
        &mut file,
        keepass::DatabaseKey::new().with_password(FIXTURE_PASSWORD),
    )
    .expect("save vault");
    (dir, path, untitled.uuid().to_string())
}

#[test]
fn untitled_entry_never_aliases_a_same_named_entry() {
    let (_dir, path, untitled_uuid) = vault_with_untitled_entry_in_same_named_group();
    let mut server = McpServer::spawn(&[
        ("KDBX_VAULT_PATH", path.to_str().unwrap()),
        ("KDBX_ALLOW_WRITES", "true"),
    ]);
    server.unlock_with_fixture_password();

    // The untitled entry is listed with a null path (it has no addressable
    // path), never with "/Email/", which names the group.
    let entries = server.call_ok("kdbx_list_entries", json!({ "group_path": "/Email" }))["entries"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["path"], Value::Null);
    assert_eq!(entries[0]["uuid"], json!(untitled_uuid));

    // The path the old formatter produced must not reach the root entry.
    assert_eq!(
        server.call_error_code("kdbx_reveal_password", json!({ "path": "/Email/" })),
        "ENTRY_NOT_FOUND"
    );
    assert_eq!(
        server.call_error_code(
            "kdbx_update_field",
            json!({ "path": "/Email/", "field_name": "URL", "value": "x" })
        ),
        "ENTRY_NOT_FOUND"
    );

    // The uuid reaches the right entry.
    let pw = server.call_ok("kdbx_reveal_password", json!({ "uuid": untitled_uuid }));
    assert_eq!(pw["password"], json!("untitled-secret"));
    let root_pw = server.call_ok("kdbx_reveal_password", json!({ "path": "/Email" }));
    assert_eq!(root_pw["password"], json!("root-email-secret"));
}
