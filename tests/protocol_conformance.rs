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
        &["attachments", "fields", "group_path", "title"],
        &["group_path", "title"],
    ),
    ("kdbx_diff_pending", &[], &[]),
    ("kdbx_discard_pending", &[], &[]),
    (
        "kdbx_download_attachment",
        &["entry_path", "name"],
        &["entry_path", "name"],
    ),
    ("kdbx_find_entry", &["fields", "query"], &["query"]),
    ("kdbx_get_entry", &["path"], &["path"]),
    ("kdbx_get_otp", &["path", "time_unix"], &["path"]),
    ("kdbx_list_attachments", &["entry_path"], &["entry_path"]),
    ("kdbx_list_entries", &["group_path"], &["group_path"]),
    ("kdbx_list_groups", &["parent_path"], &[]),
    ("kdbx_lock", &[], &[]),
    ("kdbx_reveal_password", &["path"], &["path"]),
    (
        "kdbx_reveal_protected",
        &["field_name", "path"],
        &["field_name", "path"],
    ),
    ("kdbx_save_pending", &[], &[]),
    ("kdbx_status", &[], &[]),
    ("kdbx_unlock", &["keyfile_bytes", "password"], &[]),
    (
        "kdbx_update_field",
        &["field_name", "path", "protected", "value"],
        &["field_name", "path", "value"],
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
    assert!(attachments[0]["sha256"].as_str().unwrap().len() == 64);
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
// by unit tests in kdbx_core instead:
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
fn roundtrip_integer_range_edges_for_otp_time() {
    let mut server = unlocked("with_otp.kdbx");
    // time_unix at the low edge (0) and a far-future value both compute a code.
    for t in [0u64, 2_000_000_000, 4_000_000_000] {
        let otp = server.call_ok(
            "kdbx_get_otp",
            json!({ "path": "/TOTP Account", "time_unix": t }),
        );
        let code = otp["code"].as_str().unwrap();
        assert_eq!(code.len(), 6, "code at time {t}");
        assert!(code.chars().all(|c| c.is_ascii_digit()));
    }
}
