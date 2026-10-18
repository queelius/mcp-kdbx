//! mcp-kdbx: a Model Context Protocol server for KeePass KDBX vaults.
//!
//! The crate is split into two layers. `engine` holds the vault logic with
//! no MCP-protocol types, so a future HTTP adapter (serv-kdbx) can reuse it
//! unchanged. The MCP adapter layer (Phase 3) wraps the core and speaks stdio
//! JSON-RPC. The dependency direction is one-way: the adapter depends on the
//! core, never the reverse.

pub mod adapter;
pub mod engine;
