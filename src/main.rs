//! mcp-kdbx binary entry point.
//!
//! Phase 1 is a version stub. The stdio JSON-RPC transport and server wiring
//! land in Phase 3 (the MCP adapter layer), at which point this becomes the
//! async entry that reads config, opens the vault, and runs the request loop.

fn main() {
    println!("mcp-kdbx {}", env!("CARGO_PKG_VERSION"));
}
