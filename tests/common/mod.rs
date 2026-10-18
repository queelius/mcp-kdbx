//! Shared MCP test client for the integration and protocol-conformance suites.
//!
//! Spawns the real `mcp-kdbx` binary (via `CARGO_BIN_EXE_mcp-kdbx`), completes
//! the MCP initialize handshake, and drives it with synchronous JSON-RPC over
//! stdio: send one request, block until the response with the matching id, then
//! return. There is no concurrency, so request/response ordering is
//! deterministic, no `sleep` required.
//!
//! Driving the actual binary over the actual protocol (rather than calling the
//! adapter in-process) is deliberate: it exercises config parsing, the idle
//! timer, audit-file emission, and the rmcp framing exactly as a real MCP host
//! would. The tool methods are private to the adapter anyway, so a `tests/`
//! crate could not call them in-process without widening their visibility.
//!
//! This module is included via `mod common;` in each test crate, so each crate
//! compiles it and uses a subset of the helpers; `dead_code` is allowed here.

#![allow(dead_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use serde_json::{Value, json};

/// The password every committed fixture is encrypted with (see
/// `src/bin/gen_fixtures.rs`).
pub const FIXTURE_PASSWORD: &str = "test-password-do-not-use";

/// The MCP protocol version the test client advertises. rmcp negotiates and
/// responds with its own supported version, so this only needs to be a
/// well-formed version string.
const CLIENT_PROTOCOL_VERSION: &str = "2025-06-18";

/// Absolute path to a committed fixture under `tests/fixtures/`.
pub fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

/// A running `mcp-kdbx` server process plus a synchronous JSON-RPC client over
/// its stdio. One per test: [`spawn`](Self::spawn), make calls, then let it drop
/// (which kills the child).
pub struct McpServer {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: i64,
}

impl McpServer {
    /// Spawn the server with the given `KDBX_*` environment and complete the
    /// initialize handshake. `KDBX_VAULT_PATH` must be present in `envs`.
    ///
    /// The child environment is cleared first (so an ambient `KDBX_*` variable
    /// from the developer's shell cannot leak into a test), then `PATH` is
    /// restored so the unlock-command shell-out path can still find `/bin/sh`.
    pub fn spawn(envs: &[(&str, &str)]) -> Self {
        let bin = env!("CARGO_BIN_EXE_mcp-kdbx");
        let mut cmd = Command::new(bin);
        cmd.env_clear();
        if let Ok(path) = std::env::var("PATH") {
            cmd.env("PATH", path);
        }
        for (k, v) in envs {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            // Inherit stderr so server diagnostics surface in a failing test's
            // captured output; cargo hides it on success.
            .stderr(Stdio::inherit());

        let mut child = cmd.spawn().expect("spawn mcp-kdbx binary");
        let stdin = child.stdin.take().expect("child stdin handle");
        let stdout = BufReader::new(child.stdout.take().expect("child stdout handle"));
        let mut server = McpServer {
            child,
            stdin,
            stdout,
            next_id: 1,
        };
        server.initialize();
        server
    }

    /// Run the MCP initialize handshake: the `initialize` request followed by
    /// the `notifications/initialized` notification.
    fn initialize(&mut self) {
        let resp = self.request(
            "initialize",
            json!({
                "protocolVersion": CLIENT_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "mcp-kdbx-tests", "version": "0.0.0" },
            }),
        );
        assert!(
            resp.get("result").is_some(),
            "initialize did not return a result: {resp}"
        );
        self.notify("notifications/initialized", json!({}));
    }

    /// The server's `initialize` result (protocol version, capabilities,
    /// serverInfo, instructions). Re-runs the handshake on a fresh process so it
    /// can be asserted directly.
    pub fn initialize_result(envs: &[(&str, &str)]) -> Value {
        let bin = env!("CARGO_BIN_EXE_mcp-kdbx");
        let mut cmd = Command::new(bin);
        cmd.env_clear();
        if let Ok(path) = std::env::var("PATH") {
            cmd.env("PATH", path);
        }
        for (k, v) in envs {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        let mut child = cmd.spawn().expect("spawn mcp-kdbx binary");
        let stdin = child.stdin.take().expect("child stdin handle");
        let stdout = BufReader::new(child.stdout.take().expect("child stdout handle"));
        let mut server = McpServer {
            child,
            stdin,
            stdout,
            next_id: 1,
        };
        server.request(
            "initialize",
            json!({
                "protocolVersion": CLIENT_PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "mcp-kdbx-tests", "version": "0.0.0" },
            }),
        )["result"]
            .clone()
    }

    /// Send a request, block until the response with the matching id arrives,
    /// and return the full JSON-RPC response object. Messages with a different
    /// id (or none, such as server notifications) are skipped.
    fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let req = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        self.send(&req);
        loop {
            let msg = self.read_message();
            if msg.get("id").and_then(Value::as_i64) == Some(id) {
                return msg;
            }
        }
    }

    /// Send a notification (no id, no response expected).
    fn notify(&mut self, method: &str, params: Value) {
        let note = json!({ "jsonrpc": "2.0", "method": method, "params": params });
        self.send(&note);
    }

    fn send(&mut self, msg: &Value) {
        let line = serde_json::to_string(msg).expect("serialize JSON-RPC message");
        self.stdin
            .write_all(line.as_bytes())
            .expect("write request to child stdin");
        self.stdin.write_all(b"\n").expect("write newline");
        self.stdin.flush().expect("flush child stdin");
    }

    /// Read one newline-delimited JSON message from the server's stdout,
    /// skipping blank lines. Panics if the server closes stdout first.
    fn read_message(&mut self) -> Value {
        let mut line = String::new();
        loop {
            line.clear();
            let n = self
                .stdout
                .read_line(&mut line)
                .expect("read line from child stdout");
            if n == 0 {
                panic!("mcp-kdbx closed stdout before responding");
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            return serde_json::from_str(trimmed).unwrap_or_else(|e| {
                panic!("server emitted a non-JSON stdout line ({e}): {trimmed:?}")
            });
        }
    }

    /// The `tools/list` result (`{ "tools": [...] }`).
    pub fn list_tools(&mut self) -> Value {
        self.request("tools/list", json!({}))["result"].clone()
    }

    /// Call a tool and return the raw JSON-RPC response (`result` or `error`),
    /// for asserting protocol-level rejections such as invalid params.
    pub fn call_raw(&mut self, tool: &str, args: Value) -> Value {
        self.request("tools/call", json!({ "name": tool, "arguments": args }))
    }

    /// Call a tool and return the parsed envelope (`{ ok, data } | { ok, error
    /// }`). The tool's `String` return is carried as the first text content
    /// block; this extracts and parses it.
    pub fn call(&mut self, tool: &str, args: Value) -> Value {
        let resp = self.request("tools/call", json!({ "name": tool, "arguments": args }));
        let result = resp
            .get("result")
            .unwrap_or_else(|| panic!("tools/call for {tool} returned no result: {resp}"));
        let text = result["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("tool result for {tool} had no text content: {result}"));
        serde_json::from_str(text)
            .unwrap_or_else(|e| panic!("tool envelope for {tool} was not JSON ({e}): {text:?}"))
    }

    /// Call a tool, assert `ok: true`, and return the `data` object.
    pub fn call_ok(&mut self, tool: &str, args: Value) -> Value {
        let env = self.call(tool, args);
        assert_eq!(env["ok"], json!(true), "expected ok for {tool}, got {env}");
        env["data"].clone()
    }

    /// Call a tool, assert `ok: false`, and return the full error object
    /// (`{ code, message, details? }`).
    pub fn call_error(&mut self, tool: &str, args: Value) -> Value {
        let env = self.call(tool, args);
        assert_eq!(
            env["ok"],
            json!(false),
            "expected an error envelope for {tool}, got {env}"
        );
        env["error"].clone()
    }

    /// Call a tool, assert `ok: false`, and return just the error `code` string.
    pub fn call_error_code(&mut self, tool: &str, args: Value) -> String {
        self.call_error(tool, args)["code"]
            .as_str()
            .expect("error code is a string")
            .to_string()
    }

    /// Unlock the vault with the shared fixture password, asserting success.
    pub fn unlock_with_fixture_password(&mut self) {
        self.call_ok("kdbx_unlock", json!({ "password": FIXTURE_PASSWORD }));
    }
}

impl Drop for McpServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Copy a committed fixture into a fresh temp dir and return the tempdir guard
/// plus the path to the copy. Tests that mutate a vault (save, conflict) must
/// work on a copy so the committed fixture is never written.
pub fn temp_copy_of(fixture: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("create temp dir");
    let dest = dir.path().join(fixture);
    std::fs::copy(fixture_path(fixture), &dest).expect("copy fixture into temp dir");
    (dir, dest)
}
