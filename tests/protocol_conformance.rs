//! Layer 3 protocol-conformance suite.
//!
//! Spawns the real `mcp-kdbx` binary and asserts the wire contract from spec
//! section 1, end to end over stdio MCP:
//!
//! 1. `tools/list` exposes exactly the 17 tools, each with the property and
//!    `required` shape the spec defines (the input-schema surface).
//! 2. The server identifies itself as `mcp-kdbx` (not rmcp's default name).
//! 3. Every tool's happy path returns the `{ ok: true, data }` envelope with the
//!    documented data keys.
//! 4. Every error code the tool surface can produce is forced and asserted
//!    (`{ ok: false, error: { code, .. } }`). Two codes are not triggerable
//!    here and are documented below.
//! 5. Round-trips: non-ASCII strings, base64 of binary, and integer-range edges.
//!
//! The schema check asserts the property-name set and the `required` set per
//! tool rather than byte-equal JSON Schema. Those two sets are the wire contract
//! an MCP host depends on; the surrounding schemars boilerplate (`$schema`,
//! titles, descriptions) is an implementation detail that would make a
//! byte-equal assertion brittle across schemars versions.

mod common;

use base64::Engine;
use common::*;
use serde_json::{Value, json};

/// The full tool surface: `(name, sorted properties, sorted required)`. This is
/// the spec section 1 input-schema contract, transcribed. The list is sorted by
/// name to match the extraction below.
const EXPECTED_TOOLS: &[(&str, &[&str], &[&str])] = &[
    (
        "kdbx_add_entry",
        &["attachments", "fields", "group_path", "group_uuid", "title"],
        &["title"],
    ),
    ("kdbx_diff_pending", &[], &[]),
    ("kdbx_discard_pending", &[], &[]),
    (
        "kdbx_download_attachment",
        &["entry_path", "name", "uuid"],
        &["name"],
    ),
    ("kdbx_find_entry", &["fields", "query"], &["query"]),
    ("kdbx_get_entry", &["path", "uuid"], &[]),
    ("kdbx_get_otp", &["path", "time_unix", "uuid"], &[]),
    ("kdbx_list_attachments", &["entry_path", "uuid"], &[]),
    ("kdbx_list_entries", &["group_path", "uuid"], &[]),
    ("kdbx_list_groups", &["parent_path", "uuid"], &[]),
    ("kdbx_lock", &[], &[]),
    ("kdbx_reveal_password", &["path", "uuid"], &[]),
    (
        "kdbx_reveal_protected",
        &["field_name", "path", "uuid"],
        &["field_name"],
    ),
    ("kdbx_save_pending", &[], &[]),
    ("kdbx_status", &[], &[]),
    ("kdbx_unlock", &["keyfile_bytes", "password"], &[]),
    (
        "kdbx_update_field",
        &["field_name", "path", "protected", "uuid", "value"],
        &["field_name", "value"],
    ),
];

/// Spawn the server against a committed fixture, read-only, and unlock it.
fn unlocked(fixture: &str) -> McpServer {
    let path = fixture_path(fixture);
    let mut server = McpServer::spawn(&[("KDBX_VAULT_PATH", path.to_str().unwrap())]);
    server.unlock_with_fixture_password();
    server
}

/// Spawn the server against a writable temp copy of a fixture, unlock it, and
/// return the tempdir guard (which must outlive the server) and the server.
fn unlocked_writable(fixture: &str) -> (tempfile::TempDir, McpServer) {
    let (dir, path) = temp_copy_of(fixture);
    let mut server = McpServer::spawn(&[
        ("KDBX_VAULT_PATH", path.to_str().unwrap()),
        ("KDBX_ALLOW_WRITES", "true"),
    ]);
    server.unlock_with_fixture_password();
    (dir, server)
}

/// Sorted keys of a JSON object, or an empty vec when the value is not an object
/// or the key is absent.
fn sorted_keys(obj: &Value, key: &str) -> Vec<String> {
    let mut out: Vec<String> = obj
        .get(key)
        .and_then(Value::as_object)
        .map(|m| m.keys().cloned().collect())
        .unwrap_or_default();
    out.sort();
    out
}

/// Sorted string elements of a JSON array field, or an empty vec when absent.
fn sorted_array(obj: &Value, key: &str) -> Vec<String> {
    let mut out: Vec<String> = obj
        .get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// 1. tools/list surface
// ---------------------------------------------------------------------------

#[test]
fn tools_list_matches_the_spec_surface() {
    let path = fixture_path("empty.kdbx");
    let mut server = McpServer::spawn(&[("KDBX_VAULT_PATH", path.to_str().unwrap())]);
    let listed = server.list_tools();
    let tools = listed["tools"].as_array().expect("tools is an array");

    assert_eq!(
        tools.len(),
        EXPECTED_TOOLS.len(),
        "tool count drifted from the spec surface"
    );

    // Index actual tools by name for a per-tool schema comparison.
    let mut by_name = std::collections::BTreeMap::new();
    for t in tools {
        let name = t["name"]
            .as_str()
            .expect("tool name is a string")
            .to_string();
        by_name.insert(name, t.clone());
    }

    let actual_names: Vec<&String> = by_name.keys().collect();
    let expected_names: Vec<&str> = EXPECTED_TOOLS.iter().map(|(n, _, _)| *n).collect();
    assert_eq!(
        actual_names.len(),
        expected_names.len(),
        "duplicate or missing tool names"
    );
    for name in &expected_names {
        assert!(by_name.contains_key(*name), "missing tool: {name}");
    }

    for (name, props, required) in EXPECTED_TOOLS {
        let tool = &by_name[*name];
        let schema = &tool["inputSchema"];
        assert_eq!(
            sorted_keys(schema, "properties"),
            *props,
            "input properties for {name} drifted from the spec"
        );
        assert_eq!(
            sorted_array(schema, "required"),
            *required,
            "required fields for {name} drifted from the spec"
        );
        // Secret-wrapped inputs keep a plain string schema on the wire.
        for secret_prop in ["value", "password", "keyfile_bytes"] {
            if let Some(prop) = schema["properties"].get(secret_prop) {
                assert!(
                    prop.to_string().contains("\"string\""),
                    "{name}.{secret_prop} schema is not a string: {prop}"
                );
            }
        }
        // Every tool must carry a non-empty description (agents rely on it).
        assert!(
            tool["description"]
                .as_str()
                .map(|d| !d.is_empty())
                .unwrap_or(false),
            "tool {name} has no description"
        );
    }
}

#[test]
fn server_identifies_as_mcp_kdbx() {
    let path = fixture_path("empty.kdbx");
    let result = McpServer::initialize_result(&[("KDBX_VAULT_PATH", path.to_str().unwrap())]);

    assert_eq!(
        result["serverInfo"]["name"],
        json!("mcp-kdbx"),
        "server must identify as mcp-kdbx, not rmcp's default name"
    );
    assert_eq!(
        result["serverInfo"]["version"],
        json!(env!("CARGO_PKG_VERSION")),
        "server version must be this crate's version"
    );
    // A protocol version is negotiated, the tools capability is advertised, and
    // the usage instructions are present.
    assert!(result["protocolVersion"].is_string());
    assert!(result["capabilities"]["tools"].is_object());
    assert!(
        result["instructions"]
            .as_str()
            .map(|s| s.contains("kdbx"))
            .unwrap_or(false),
        "instructions should mention the kdbx tools"
    );
}

#[test]
fn instructions_teach_the_path_grammar_and_unlock_avoids_chat_passwords() {
    let path = fixture_path("empty.kdbx");
    let result = McpServer::initialize_result(&[("KDBX_VAULT_PATH", path.to_str().unwrap())]);
    let instructions = result["instructions"].as_str().unwrap();
    for needle in ["leading '/'", "\\/", ":N", "uuid"] {
        assert!(
            instructions.contains(needle),
            "instructions should explain {needle}: {instructions}"
        );
    }

    let mut server = McpServer::spawn(&[("KDBX_VAULT_PATH", path.to_str().unwrap())]);
    let tools = server.list_tools();
    let unlock = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == json!("kdbx_unlock"))
        .unwrap()
        .clone();
    let description = unlock["description"].as_str().unwrap();
    assert!(description.contains("KDBX_PASSWORD") && description.contains("KDBX_UNLOCK_CMD"));
    assert!(
        description.contains("Do not ask the user"),
        "kdbx_unlock must steer agents away from asking for the password in chat: {description}"
    );
}

/// MCP tool annotations per tool: (name, readOnlyHint, destructiveHint,
/// idempotentHint). Every tool is closed-world (one vault file). Reads and
/// reveals change nothing; unlock and lock change only the session, and lock
/// discards a stage; the write tools stage changes, and save and discard are
/// the destructive ones (save replaces the vault file).
const EXPECTED_ANNOTATIONS: &[(&str, bool, bool, bool)] = &[
    ("kdbx_add_entry", false, false, false),
    ("kdbx_diff_pending", true, false, true),
    ("kdbx_discard_pending", false, true, true),
    ("kdbx_download_attachment", true, false, true),
    ("kdbx_find_entry", true, false, true),
    ("kdbx_get_entry", true, false, true),
    ("kdbx_get_otp", true, false, true),
    ("kdbx_list_attachments", true, false, true),
    ("kdbx_list_entries", true, false, true),
    ("kdbx_list_groups", true, false, true),
    ("kdbx_lock", false, true, true),
    ("kdbx_reveal_password", true, false, true),
    ("kdbx_reveal_protected", true, false, true),
    ("kdbx_save_pending", false, true, false),
    ("kdbx_status", true, false, true),
    ("kdbx_unlock", false, false, true),
    ("kdbx_update_field", false, false, false),
];

#[test]
fn tool_annotations_tell_reads_from_writes() {
    let path = fixture_path("empty.kdbx");
    let mut server = McpServer::spawn(&[("KDBX_VAULT_PATH", path.to_str().unwrap())]);
    let listed = server.list_tools();
    let tools = listed["tools"].as_array().unwrap();
    assert_eq!(tools.len(), EXPECTED_ANNOTATIONS.len());
    for (name, read_only, destructive, idempotent) in EXPECTED_ANNOTATIONS {
        let tool = tools
            .iter()
            .find(|t| t["name"] == json!(name))
            .unwrap_or_else(|| panic!("missing tool {name}"));
        let a = &tool["annotations"];
        assert_eq!(a["readOnlyHint"], json!(read_only), "{name} readOnlyHint");
        assert_eq!(
            a["destructiveHint"],
            json!(destructive),
            "{name} destructiveHint"
        );
        assert_eq!(
            a["idempotentHint"],
            json!(idempotent),
            "{name} idempotentHint"
        );
        assert_eq!(a["openWorldHint"], json!(false), "{name} openWorldHint");
    }
}

#[test]
fn instructions_say_whether_writes_are_enabled() {
    let (_dir, path) = temp_copy_of("empty.kdbx");
    let vault = path.to_str().unwrap();
    let off = McpServer::initialize_result(&[("KDBX_VAULT_PATH", vault)]);
    let off = off["instructions"].as_str().unwrap();
    assert!(off.contains("Writes are disabled"), "{off}");
    assert!(off.contains("WRITES_DISABLED"), "{off}");
    let on =
        McpServer::initialize_result(&[("KDBX_VAULT_PATH", vault), ("KDBX_ALLOW_WRITES", "true")]);
    let on = on["instructions"].as_str().unwrap();
    assert!(on.contains("Writes are enabled"), "{on}");
    assert!(!on.contains("WRITES_DISABLED"), "{on}");
}

// ---------------------------------------------------------------------------
// 2. Happy-path envelope shapes (every tool)
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_tools_happy_path() {
    let path = fixture_path("flat.kdbx");
    let mut server = McpServer::spawn(&[("KDBX_VAULT_PATH", path.to_str().unwrap())]);

    // status (locked): reports locked true, writes_allowed false, and version.
    let status = server.call_ok("kdbx_status", json!({}));
    assert_eq!(status["locked"], json!(true));
    assert_eq!(status["writes_allowed"], json!(false));
    assert_eq!(status["server_version"], json!(env!("CARGO_PKG_VERSION")));
    // The configured idle window is reported even while locked (900 by
    // default), so an agent can tell "locked" from "no idle lock".
    assert_eq!(status["idle_timeout_seconds"], json!(900));
    assert!(status["idle_timeout_remaining_seconds"].is_null());
    assert!(
        status["vault_path"]
            .as_str()
            .unwrap()
            .ends_with("flat.kdbx")
    );

    // unlock: locked false, no pending changes.
    let unlocked = server.call_ok("kdbx_unlock", json!({ "password": FIXTURE_PASSWORD }));
    assert_eq!(unlocked["locked"], json!(false));
    assert_eq!(unlocked["has_pending_changes"], json!(false));

    // status (unlocked): now reports has_pending_changes false and an idle window.
    let status = server.call_ok("kdbx_status", json!({}));
    assert_eq!(status["locked"], json!(false));
    assert_eq!(status["has_pending_changes"], json!(false));
    assert!(status["idle_timeout_remaining_seconds"].is_number());

    // lock: locked true, zero pending discarded.
    let locked = server.call_ok("kdbx_lock", json!({}));
    assert_eq!(locked["locked"], json!(true));
    assert_eq!(locked["pending_discarded"], json!(0));
}

#[test]
fn read_tools_happy_path() {
    let mut server = unlocked("nested.kdbx");

    // list_groups at root: one child group, Personal.
    let groups = server.call_ok("kdbx_list_groups", json!({}))["groups"]
        .as_array()
        .unwrap()
        .clone();
    let names: Vec<&str> = groups.iter().map(|g| g["name"].as_str().unwrap()).collect();
    assert!(
        names.contains(&"Personal"),
        "root should contain Personal: {names:?}"
    );

    // The listed group itself is reported, which is how an agent gets the
    // root group's uuid; listing by that uuid gives the same children.
    let root = server.call_ok("kdbx_list_groups", json!({}))["parent"].clone();
    assert_eq!(root["path"], json!("/"));
    let by_uuid = server.call_ok("kdbx_list_groups", json!({ "uuid": root["uuid"] }));
    assert_eq!(by_uuid["parent"], root);
    assert_eq!(by_uuid["groups"].as_array().unwrap().len(), groups.len());
    let personal = server.call_ok("kdbx_list_groups", json!({ "parent_path": "/Personal/" }));
    assert_eq!(personal["parent"]["path"], json!("/Personal/"));

    // list_entries in the deepest group: Checking Account.
    let entries = server.call_ok(
        "kdbx_list_entries",
        json!({ "group_path": "/Personal/Finance/Banking" }),
    )["entries"]
        .as_array()
        .unwrap()
        .clone();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0]["title"], json!("Checking Account"));
    // Bulk reads never carry a password value.
    assert!(!entries[0].to_string().contains("checking-secret"));

    // get_entry detail: full timestamps and metadata, no secret.
    let detail = server.call_ok(
        "kdbx_get_entry",
        json!({ "path": "/Personal/Finance/Banking/Checking Account" }),
    );
    assert_eq!(detail["title"], json!("Checking Account"));
    assert_eq!(detail["username"], json!("alice"));
    assert!(detail["created_at"].is_string());
    assert!(detail["modified_at"].is_string());
    assert!(!detail.to_string().contains("checking-secret"));

    // find_entry by title substring.
    let found = server.call_ok("kdbx_find_entry", json!({ "query": "Checking" }));
    assert_eq!(found["matched_count"], json!(1));
    assert_eq!(found["truncated"], json!(false));
    assert_eq!(found["entries"][0]["title"], json!("Checking Account"));
}

#[test]
fn list_attachments_happy_path() {
    let mut server = unlocked("with_attachments.kdbx");
    let data = server.call_ok(
        "kdbx_list_attachments",
        json!({ "entry_path": "/Document A" }),
    );
    let attachments = data["attachments"].as_array().unwrap();
    assert_eq!(attachments.len(), 1);
    assert_eq!(attachments[0]["name"], json!("notes.txt"));
    assert_eq!(attachments[0]["size_bytes"], json!("meeting notes\n".len()));
    // A fingerprint under the random per-session key (never the stable audit
    // key, and never a plain sha256: a plain digest of a small file would be
    // a lookup oracle, and an audit-keyed one next to the downloaded bytes a
    // master-password oracle).
    assert!(attachments[0].get("sha256").is_none());
    let listed = attachments[0]["fingerprint"].as_str().unwrap().to_string();
    assert_eq!(listed.len(), 64);
    // Within the session, the download reports the same fingerprint for the
    // same bytes.
    let downloaded = server.call_ok(
        "kdbx_download_attachment",
        json!({ "entry_path": "/Document A", "name": "notes.txt" }),
    );
    assert_eq!(downloaded["fingerprint"], json!(listed));
    assert!(downloaded.get("sha256").is_none());
}

#[test]
fn tool_fingerprints_are_session_keyed() {
    // Fingerprints in tool responses use a random per-session key, so they
    // identify content within one unlock only and give the client no oracle
    // on the master password: the same attachment fingerprints differently
    // after a re-unlock.
    let mut server = unlocked("with_attachments.kdbx");
    let listed = |server: &mut McpServer| {
        server.call_ok(
            "kdbx_list_attachments",
            json!({ "entry_path": "/Document A" }),
        )["attachments"][0]["fingerprint"]
            .clone()
    };
    let first = listed(&mut server);
    assert_eq!(first, listed(&mut server), "stable within a session");
    server.call_ok("kdbx_lock", json!({}));
    server.unlock_with_fixture_password();
    assert_ne!(first, listed(&mut server), "a new session, a new key");
}

#[test]
fn reveal_tools_happy_path() {
    let mut server = unlocked("flat.kdbx");

    // reveal_password returns the plaintext for an entry's Password field.
    let pw = server.call_ok("kdbx_reveal_password", json!({ "path": "/Bank" }));
    assert_eq!(pw["password"], json!("bank-secret-456"));

    // reveal_protected returns a custom protected field's value.
    let pin = server.call_ok(
        "kdbx_reveal_protected",
        json!({ "path": "/Bank", "field_name": "PIN" }),
    );
    assert_eq!(pin["value"], json!("4321"));

    // Both echo what they answer for (canonical path, uuid, field name), so
    // an agent can correlate several reveals from the payloads alone.
    let bank = server.call_ok("kdbx_get_entry", json!({ "path": "/Bank" }));
    for (reveal, field) in [(&pw, "Password"), (&pin, "PIN")] {
        assert_eq!(reveal["path"], json!("/Bank"));
        assert_eq!(reveal["uuid"], bank["uuid"]);
        assert_eq!(reveal["field_name"], json!(field));
    }
    let by_uuid = server.call_ok("kdbx_reveal_password", json!({ "uuid": bank["uuid"] }));
    assert_eq!(by_uuid["path"], json!("/Bank"));
}

#[test]
fn download_attachment_happy_path() {
    let mut server = unlocked("with_attachments.kdbx");
    let data = server.call_ok(
        "kdbx_download_attachment",
        json!({ "entry_path": "/Document A", "name": "notes.txt" }),
    );
    assert_eq!(data["name"], json!("notes.txt"));
    assert_eq!(data["size_bytes"], json!("meeting notes\n".len()));
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(data["base64"].as_str().unwrap())
        .unwrap();
    assert_eq!(decoded, b"meeting notes\n");
}

#[test]
fn get_otp_happy_path() {
    let mut server = unlocked("with_otp.kdbx");
    let otp = server.call_ok("kdbx_get_otp", json!({ "path": "/TOTP Account" }));
    let code = otp["code"].as_str().expect("code is a string");
    assert_eq!(code.len(), 6, "default TOTP code is 6 digits");
    assert!(
        code.chars().all(|c| c.is_ascii_digit()),
        "code is all digits"
    );
    assert_eq!(otp["period_seconds"], json!(30));
    let valid_for = otp["valid_for_seconds"].as_u64().unwrap();
    assert!(
        (1..=30).contains(&valid_for),
        "valid_for in 1..=30: {valid_for}"
    );
}

#[test]
fn write_and_stage_tools_happy_path() {
    let (_dir, mut server) = unlocked_writable("flat.kdbx");

    // add_entry stages a new entry and reports its path and uuid.
    let added = server.call_ok(
        "kdbx_add_entry",
        json!({
            "group_path": "/",
            "title": "NewService",
            "fields": { "UserName": { "value": "newuser", "protected": false } },
        }),
    );
    assert_eq!(added["staged"], json!(true));
    assert_eq!(added["path"], json!("/NewService"));
    assert!(added["uuid"].as_str().unwrap().len() >= 32);

    // update_field stages a change on an existing entry.
    let updated = server.call_ok(
        "kdbx_update_field",
        json!({ "path": "/GitHub", "field_name": "URL", "value": "https://github.example" }),
    );
    assert_eq!(updated["staged"], json!(true));
    assert_eq!(updated["field_name"], json!("URL"));

    // diff_pending shows one added and one modified entry, with protected
    // values never shown.
    let diff = server.call_ok("kdbx_diff_pending", json!({}));
    assert_eq!(diff["summary"]["num_added"], json!(1));
    assert_eq!(diff["summary"]["num_modified"], json!(1));
    let added_paths: Vec<&str> = diff["added"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["path"].as_str().unwrap())
        .collect();
    assert!(added_paths.contains(&"/NewService"));
    // A shown field change carries both flags and the values.
    assert_eq!(
        diff["modified"][0]["field_changes"],
        json!([{
            "field_name": "URL",
            "secret": false,
            "protected": false,
            "protection_changed": false,
            "value_changed": true,
            "before": "https://github.com",
            "after": "https://github.example",
        }])
    );

    // save_pending commits the stage and reports the change count.
    let saved = server.call_ok("kdbx_save_pending", json!({}));
    assert_eq!(saved["saved"], json!(true));
    assert_eq!(saved["num_changes"], json!(2));
    assert!(saved["written_at"].is_string());

    // discard_pending with nothing staged is a no-op success.
    let discarded = server.call_ok("kdbx_discard_pending", json!({}));
    assert_eq!(discarded["discarded"], json!(true));
    assert_eq!(discarded["num_dropped"], json!(0));
}

// ---------------------------------------------------------------------------
// 3. Error codes (every triggerable code)
// ---------------------------------------------------------------------------
//
// Two codes are not triggerable from a black-box protocol test and are covered
// by unit tests in engine instead:
//   - VAULT_NOT_FOUND: the config layer refuses to start when the vault path is
//     missing, so a running server never reaches this from a tool call.
//   - WRITE_FAILED: requires a filesystem write failure mid-save, which is not
//     reproducible deterministically over the protocol.

#[test]
fn error_vault_locked() {
    let path = fixture_path("flat.kdbx");
    let mut server = McpServer::spawn(&[("KDBX_VAULT_PATH", path.to_str().unwrap())]);
    // A read before unlock is VAULT_LOCKED.
    assert_eq!(
        server.call_error_code("kdbx_list_entries", json!({ "group_path": "/" })),
        "VAULT_LOCKED"
    );
}

#[test]
fn error_vault_already_unlocked() {
    let mut server = unlocked("flat.kdbx");
    assert_eq!(
        server.call_error_code("kdbx_unlock", json!({ "password": FIXTURE_PASSWORD })),
        "VAULT_ALREADY_UNLOCKED"
    );
}

#[test]
fn error_auth_failed() {
    let path = fixture_path("flat.kdbx");
    let mut server = McpServer::spawn(&[("KDBX_VAULT_PATH", path.to_str().unwrap())]);
    assert_eq!(
        server.call_error_code("kdbx_unlock", json!({ "password": "wrong-password" })),
        "AUTH_FAILED"
    );
}

#[test]
fn find_entry_rejects_unknown_field_names_and_lists_the_allowed_ones() {
    let mut server = unlocked("flat.kdbx");
    // An unknown field name is rejected as invalid params instead of being
    // silently dropped.
    let resp = server.call_raw(
        "kdbx_find_entry",
        json!({ "query": "x", "fields": ["password"] }),
    );
    let rejected = resp.get("error").is_some() || resp["result"]["isError"] == json!(true);
    assert!(rejected, "unknown field name must be rejected: {resp}");

    // The schema enumerates the allowed values.
    let tools = server.list_tools();
    let find = tools["tools"]
        .as_array()
        .unwrap()
        .iter()
        .find(|t| t["name"] == json!("kdbx_find_entry"))
        .unwrap()
        .clone();
    let schema = find["inputSchema"].to_string();
    for name in ["title", "username", "url", "notes"] {
        assert!(
            schema.contains(&format!("\"{name}\"")),
            "{name} missing: {schema}"
        );
    }
}

#[test]
fn error_vault_unreadable() {
    // A file that is not a KDBX database fails before any key is checked:
    // VAULT_UNREADABLE with a reason, not AUTH_FAILED.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("not-a-vault.kdbx");
    std::fs::write(&path, b"plain text, not a keepass database").unwrap();
    let mut server = McpServer::spawn(&[("KDBX_VAULT_PATH", path.to_str().unwrap())]);
    let err = server.call_error("kdbx_unlock", json!({ "password": FIXTURE_PASSWORD }));
    assert_eq!(err["code"], json!("VAULT_UNREADABLE"));
    assert_eq!(err["details"]["reason"], json!("not_kdbx"));
}

#[test]
fn error_path_invalid() {
    let mut server = unlocked("flat.kdbx");
    // A missing leading slash is a malformed path, from entry and group tools
    // alike, not a not-found.
    assert_eq!(
        server.call_error_code("kdbx_get_entry", json!({ "path": "Bank" })),
        "PATH_INVALID"
    );
    assert_eq!(
        server.call_error_code("kdbx_list_entries", json!({ "group_path": "Web//x" })),
        "PATH_INVALID"
    );
    // The ecosystem grammar (kdbx-core) is strict about escapes: an unknown
    // escape is malformed rather than decoded to the bare character.
    let err = server.call_error("kdbx_get_entry", json!({ "path": "/B\\q" }));
    assert_eq!(err["code"], json!("PATH_INVALID"));
    assert_eq!(err["details"]["path"], json!("/B\\q"));
}

#[test]
fn error_unlock_source_missing() {
    let path = fixture_path("flat.kdbx");
    // No password argument and no KDBX_PASSWORD configured.
    let mut server = McpServer::spawn(&[("KDBX_VAULT_PATH", path.to_str().unwrap())]);
    assert_eq!(
        server.call_error_code("kdbx_unlock", json!({})),
        "UNLOCK_SOURCE_MISSING"
    );
}

#[test]
fn error_group_not_found() {
    let mut server = unlocked("flat.kdbx");
    assert_eq!(
        server.call_error_code("kdbx_list_entries", json!({ "group_path": "/Nope" })),
        "GROUP_NOT_FOUND"
    );
}

#[test]
fn error_entry_not_found() {
    let mut server = unlocked("flat.kdbx");
    assert_eq!(
        server.call_error_code("kdbx_get_entry", json!({ "path": "/Nope" })),
        "ENTRY_NOT_FOUND"
    );
}

#[test]
fn error_field_not_found() {
    let mut server = unlocked("flat.kdbx");
    assert_eq!(
        server.call_error_code(
            "kdbx_reveal_protected",
            json!({ "path": "/Bank", "field_name": "Nonexistent" })
        ),
        "FIELD_NOT_FOUND"
    );
}

#[test]
fn error_field_not_protected() {
    let mut server = unlocked("flat.kdbx");
    // Server.Port is an unprotected custom field; revealing it is refused.
    assert_eq!(
        server.call_error_code(
            "kdbx_reveal_protected",
            json!({ "path": "/Server", "field_name": "Port" })
        ),
        "FIELD_NOT_PROTECTED"
    );
}

#[test]
fn an_unprotected_password_is_still_a_secret() {
    // kdbx-core's one secret predicate: a Password is a secret whatever its
    // protection flag. Turning the flag off must not move it into bulk reads,
    // search, or the stage diff, and kdbx_reveal_protected treats it as a
    // secret too.
    let (_dir, mut server) = unlocked_writable("flat.kdbx");
    server.call_ok(
        "kdbx_update_field",
        json!({ "path": "/Bank", "field_name": "Password", "value": "plain-pw-0x51", "protected": false }),
    );
    let bulk = [
        server.call_ok("kdbx_list_entries", json!({ "group_path": "/" })),
        server.call_ok("kdbx_get_entry", json!({ "path": "/Bank" })),
        server.call_ok("kdbx_diff_pending", json!({})),
    ];
    for out in &bulk {
        assert!(
            !out.to_string().contains("plain-pw-0x51"),
            "an unprotected Password leaked into a bulk read: {out}"
        );
    }
    let found = server.call_ok(
        "kdbx_find_entry",
        json!({ "query": "plain-pw", "fields": ["title", "username", "url", "notes"] }),
    );
    assert_eq!(found["matched_count"], json!(0));
    let revealed = server.call_ok(
        "kdbx_reveal_protected",
        json!({ "path": "/Bank", "field_name": "Password" }),
    );
    assert_eq!(revealed["value"], json!("plain-pw-0x51"));
}

#[test]
fn error_attachment_not_found() {
    let mut server = unlocked("with_attachments.kdbx");
    assert_eq!(
        server.call_error_code(
            "kdbx_download_attachment",
            json!({ "entry_path": "/Document A", "name": "missing.txt" })
        ),
        "ATTACHMENT_NOT_FOUND"
    );
}

#[test]
fn error_no_otp_configured() {
    let mut server = unlocked("flat.kdbx");
    assert_eq!(
        server.call_error_code("kdbx_get_otp", json!({ "path": "/Bank" })),
        "NO_OTP_CONFIGURED"
    );
}

#[test]
fn error_otp_invalid() {
    // A configured but malformed TOTP source is a typed error, never "no
    // OTP": the agent learns the entry has OTP and why it cannot be used.
    let (_dir, mut server) = unlocked_writable("flat.kdbx");
    server.call_ok(
        "kdbx_update_field",
        json!({ "path": "/Bank", "field_name": "otp", "value": "otpauth://totp/x?secret=!!!" }),
    );
    let err = server.call_error("kdbx_get_otp", json!({ "path": "/Bank" }));
    assert_eq!(err["code"], json!("OTP_INVALID"));
    assert_eq!(err["details"]["source"], json!("uri"));
    assert_eq!(err["details"]["reason"], json!("invalid_secret"));
    // has_otp is true only for a configuration that resolves.
    let bank = server.call_ok("kdbx_get_entry", json!({ "path": "/Bank" }));
    assert_eq!(bank["has_otp"], json!(false));
    // A typed reason that carries a field names it.
    server.call_ok(
        "kdbx_update_field",
        json!({ "path": "/Email", "field_name": "TOTP Settings", "value": "30;6" }),
    );
    let err = server.call_error("kdbx_get_otp", json!({ "path": "/Email" }));
    assert_eq!(err["code"], json!("OTP_INVALID"));
    assert_eq!(err["details"]["source"], json!("legacy"));
    assert_eq!(
        err["details"]["reason"],
        json!({ "missing_field": "TOTP Seed" })
    );
}

#[test]
fn steam_totp_codes_are_supported() {
    let (_dir, mut server) = unlocked_writable("flat.kdbx");
    server.call_ok(
        "kdbx_update_field",
        json!({
            "path": "/Wifi",
            "field_name": "otp",
            "value": "otpauth://totp/Steam:me?secret=JBSWY3DPEHPK3PXP&encoder=steam",
        }),
    );
    let wifi = server.call_ok("kdbx_get_entry", json!({ "path": "/Wifi" }));
    assert_eq!(wifi["has_otp"], json!(true));
    let otp = server.call_ok("kdbx_get_otp", json!({ "path": "/Wifi" }));
    let code = otp["code"].as_str().unwrap();
    assert_eq!(code.chars().count(), 5, "Steam codes are five characters");
    assert!(
        code.chars()
            .all(|c| "23456789BCDFGHJKMNPQRTVWXY".contains(c)),
        "{code} uses the Steam alphabet"
    );
}

#[test]
fn error_writes_disabled() {
    // Writes not enabled: add_entry is refused before touching the vault.
    let mut server = unlocked("flat.kdbx");
    assert_eq!(
        server.call_error_code("kdbx_add_entry", json!({ "group_path": "/", "title": "X" })),
        "WRITES_DISABLED"
    );
}

#[test]
fn error_no_pending_changes() {
    let (_dir, mut server) = unlocked_writable("flat.kdbx");
    // Saving with nothing staged is NO_PENDING_CHANGES.
    assert_eq!(
        server.call_error_code("kdbx_save_pending", json!({})),
        "NO_PENDING_CHANGES"
    );
}

#[test]
fn error_entry_title_invalid() {
    let (_dir, mut server) = unlocked_writable("flat.kdbx");
    // An empty title fails validation.
    assert_eq!(
        server.call_error_code("kdbx_add_entry", json!({ "group_path": "/", "title": "" })),
        "ENTRY_TITLE_INVALID"
    );
}

#[test]
fn error_entry_title_invalid_on_every_title_write() {
    let (_dir, mut server) = unlocked_writable("flat.kdbx");
    // A right-to-left override in a title, via add_entry.
    assert_eq!(
        server.call_error_code(
            "kdbx_add_entry",
            json!({ "group_path": "/", "title": "\u{202e}buHtiG" })
        ),
        "ENTRY_TITLE_INVALID"
    );
    // update_field on Title is validated as a title, not just as a field name.
    assert_eq!(
        server.call_error_code(
            "kdbx_update_field",
            json!({ "path": "/GitHub", "field_name": "Title", "value": "" })
        ),
        "ENTRY_TITLE_INVALID"
    );
    // The fields map cannot carry a second, unvalidated Title.
    assert_eq!(
        server.call_error_code(
            "kdbx_add_entry",
            json!({
                "group_path": "/",
                "title": "Valid",
                "fields": { "Title": { "value": "", "protected": false } },
            })
        ),
        "FIELD_NAME_INVALID"
    );
}

#[test]
fn error_field_name_invalid() {
    let (_dir, mut server) = unlocked_writable("flat.kdbx");
    // A field name with leading whitespace fails validation.
    assert_eq!(
        server.call_error_code(
            "kdbx_add_entry",
            json!({
                "group_path": "/",
                "title": "Valid",
                "fields": { " bad": { "value": "x", "protected": false } },
            })
        ),
        "FIELD_NAME_INVALID"
    );
}

#[test]
fn error_invalid_input_bad_attachment_base64() {
    let (_dir, mut server) = unlocked_writable("flat.kdbx");
    // An attachment whose base64 does not decode is INVALID_INPUT.
    assert_eq!(
        server.call_error_code(
            "kdbx_add_entry",
            json!({
                "group_path": "/",
                "title": "WithBadAttachment",
                "attachments": { "f.bin": { "base64": "not valid base64 !!!" } },
            })
        ),
        "INVALID_INPUT"
    );
}

#[test]
fn error_invalid_input_entry_address_needs_exactly_one_of_path_or_uuid() {
    let mut server = unlocked("flat.kdbx");
    let uuid = server.call_ok("kdbx_get_entry", json!({ "path": "/Bank" }))["uuid"]
        .as_str()
        .unwrap()
        .to_string();
    // Both: refused rather than silently preferring one.
    let both = server.call_error(
        "kdbx_reveal_password",
        json!({ "path": "/Bank", "uuid": uuid }),
    );
    assert_eq!(both["code"], json!("INVALID_INPUT"));
    // Neither.
    assert_eq!(
        server.call_error_code("kdbx_get_entry", json!({})),
        "INVALID_INPUT"
    );
    // A malformed uuid.
    assert_eq!(
        server.call_error_code("kdbx_get_entry", json!({ "uuid": "not-a-uuid" })),
        "INVALID_INPUT"
    );
    // A well-formed uuid that names no entry.
    assert_eq!(
        server.call_error_code(
            "kdbx_get_entry",
            json!({ "uuid": "6f9619ff-8b86-d011-b42d-00c04fc964ff" })
        ),
        "ENTRY_NOT_FOUND"
    );
}

#[test]
fn entry_tools_accept_uuid_addressing() {
    let (_dir, mut server) = unlocked_writable("with_attachments.kdbx");
    let uuid = server.call_ok("kdbx_get_entry", json!({ "path": "/Document A" }))["uuid"]
        .as_str()
        .unwrap()
        .to_string();

    let detail = server.call_ok("kdbx_get_entry", json!({ "uuid": uuid }));
    assert_eq!(detail["path"], json!("/Document A"));
    let listed = server.call_ok("kdbx_list_attachments", json!({ "uuid": uuid }));
    assert_eq!(listed["attachments"][0]["name"], json!("notes.txt"));
    let downloaded = server.call_ok(
        "kdbx_download_attachment",
        json!({ "uuid": uuid, "name": "notes.txt" }),
    );
    assert_eq!(downloaded["size_bytes"], json!("meeting notes\n".len()));
    let updated = server.call_ok(
        "kdbx_update_field",
        json!({ "uuid": uuid, "field_name": "Secret", "value": "s", "protected": true }),
    );
    assert_eq!(updated["path"], json!("/Document A"));
    assert_eq!(updated["uuid"], json!(uuid));
    let revealed = server.call_ok(
        "kdbx_reveal_protected",
        json!({ "uuid": uuid, "field_name": "Secret" }),
    );
    assert_eq!(revealed["value"], json!("s"));
}

#[test]
fn group_tools_accept_uuid_addressing() {
    let (_dir, mut server) = unlocked_writable("nested.kdbx");
    let personal = server.call_ok("kdbx_list_groups", json!({}))["groups"][0].clone();
    assert_eq!(personal["name"], json!("Personal"));
    let finance = server.call_ok("kdbx_list_groups", json!({ "uuid": personal["uuid"] }))["groups"]
        [0]
    .clone();
    // Group paths keep their trailing slash (kdbx-core's canonical form), so
    // an emitted group path re-resolves as a group, never as an entry.
    assert_eq!(finance["path"], json!("/Personal/Finance/"));
    let banking = server.call_ok(
        "kdbx_list_groups",
        json!({ "parent_path": finance["path"] }),
    )["groups"][0]
        .clone();
    assert_eq!(banking["path"], json!("/Personal/Finance/Banking/"));

    let entries = server.call_ok("kdbx_list_entries", json!({ "uuid": banking["uuid"] }));
    assert_eq!(entries["entries"][0]["title"], json!("Checking Account"));

    let added = server.call_ok(
        "kdbx_add_entry",
        json!({ "group_uuid": banking["uuid"], "title": "Savings" }),
    );
    assert_eq!(added["path"], json!("/Personal/Finance/Banking/Savings"));

    // Exactly one of path or uuid, as for entry tools.
    assert_eq!(
        server.call_error_code(
            "kdbx_list_entries",
            json!({ "group_path": "/Personal", "uuid": personal["uuid"] })
        ),
        "INVALID_INPUT"
    );
    assert_eq!(
        server.call_error_code("kdbx_list_entries", json!({})),
        "INVALID_INPUT"
    );
    assert_eq!(
        server.call_error_code("kdbx_add_entry", json!({ "title": "Nowhere" })),
        "INVALID_INPUT"
    );
    assert_eq!(
        server.call_error_code(
            "kdbx_list_groups",
            json!({ "uuid": "6f9619ff-8b86-d011-b42d-00c04fc964ff" })
        ),
        "GROUP_NOT_FOUND"
    );
}

#[test]
fn entry_tools_refuse_a_group_shaped_path() {
    let mut server = unlocked("flat.kdbx");
    // "/Bank/" addresses a group (trailing slash); it never names the entry.
    assert_eq!(
        server.call_error_code("kdbx_reveal_password", json!({ "path": "/Bank/" })),
        "ENTRY_NOT_FOUND"
    );
}

// ---------------------------------------------------------------------------
// 4. Round-trips
// ---------------------------------------------------------------------------

#[test]
fn roundtrip_non_ascii_strings() {
    let (_dir, mut server) = unlocked_writable("flat.kdbx");
    let title = "café ☕ 日本語 Ωμέγα";
    let note = "naïve emoji 🔐 multibyte";
    server.call_ok(
        "kdbx_add_entry",
        json!({
            "group_path": "/",
            "title": title,
            "fields": { "Notes": { "value": note, "protected": false } },
        }),
    );
    let detail = server.call_ok("kdbx_get_entry", json!({ "path": format!("/{title}") }));
    assert_eq!(detail["title"], json!(title));
    assert_eq!(detail["notes"], json!(note));
}

#[test]
fn roundtrip_binary_attachment_base64() {
    let mut server = unlocked("with_attachments.kdbx");
    // Document B carries the 256 bytes 0x00..=0xff.
    let data = server.call_ok(
        "kdbx_download_attachment",
        json!({ "entry_path": "/Document B", "name": "data.bin" }),
    );
    assert_eq!(data["size_bytes"], json!(256));
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(data["base64"].as_str().unwrap())
        .unwrap();
    let expected: Vec<u8> = (0u8..=255).collect();
    assert_eq!(decoded, expected);
}

#[test]
fn roundtrip_integer_range_edges_for_otp_time_are_clamped() {
    let mut server = unlocked("with_otp.kdbx");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // time_unix at the low edge (0) and far-future values are accepted but
    // clamped to now plus or minus one 30-second period: no far-past or
    // far-future code can be harvested.
    for t in [0u64, 2_000_000_000, 4_000_000_000, u64::MAX] {
        let otp = server.call_ok(
            "kdbx_get_otp",
            json!({ "path": "/TOTP Account", "time_unix": t }),
        );
        let code = otp["code"].as_str().unwrap();
        assert_eq!(code.len(), 6, "code at time {t}");
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        let used = otp["time_unix"].as_u64().unwrap();
        assert!(
            used + 31 >= now && used <= now + 31,
            "time {t} was evaluated at {used}, outside now +/- one period"
        );
    }
}

/// Listings come back in record-UUID order (kdbx-core's keepass 0.12 capture
/// sorts children by UUID, since keepass 0.12 loses document order), the
/// same on every call and across a re-unlock, instead of hash-set order.
#[test]
fn listings_are_in_uuid_order() {
    let uuids = |list: &Value| -> Vec<String> {
        list.as_array()
            .unwrap()
            .iter()
            .map(|n| n["uuid"].as_str().unwrap().to_string())
            .collect()
    };
    let sorted = |v: &[String]| {
        let mut s = v.to_vec();
        s.sort();
        s
    };

    let mut flat = unlocked("flat.kdbx");
    let entries =
        uuids(&flat.call_ok("kdbx_list_entries", json!({ "group_path": "/" }))["entries"]);
    assert!(entries.len() >= 5, "{entries:?}");
    assert_eq!(
        entries,
        sorted(&entries),
        "entries are listed in uuid order"
    );
    flat.call_ok("kdbx_lock", json!({}));
    flat.unlock_with_fixture_password();
    let again = uuids(&flat.call_ok("kdbx_list_entries", json!({ "group_path": "/" }))["entries"]);
    assert_eq!(again, entries, "the order survives a re-unlock");

    // No committed fixture has sibling groups: build one with six.
    let mut db = keepass::Database::new();
    for name in ["Alpha", "Bravo", "Charlie", "Delta", "Echo", "Foxtrot"] {
        db.root_mut().add_group().name = name.to_string();
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("siblings.kdbx");
    let mut bytes = Vec::new();
    db.save(
        &mut bytes,
        keepass::DatabaseKey::new().with_password(FIXTURE_PASSWORD),
    )
    .unwrap();
    std::fs::write(&path, bytes).unwrap();
    let mut siblings = McpServer::spawn(&[("KDBX_VAULT_PATH", path.to_str().unwrap())]);
    siblings.unlock_with_fixture_password();
    let groups = uuids(&siblings.call_ok("kdbx_list_groups", json!({}))["groups"]);
    assert_eq!(groups.len(), 6, "{groups:?}");
    assert_eq!(groups, sorted(&groups), "groups are listed in uuid order");
    siblings.call_ok("kdbx_lock", json!({}));
    siblings.unlock_with_fixture_password();
    let again = uuids(&siblings.call_ok("kdbx_list_groups", json!({}))["groups"]);
    assert_eq!(again, groups, "the order survives a re-unlock");
}
