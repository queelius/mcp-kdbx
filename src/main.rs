//! mcp-kdbx binary entry point.
//!
//! Reads configuration from the environment, builds the server, and serves the
//! MCP protocol over stdio (rmcp). The vault starts locked and is opened on the
//! first `kdbx_unlock` call. Logs go to stderr (and the audit file, when
//! configured) so they never collide with the JSON-RPC stream on stdout.

use mcp_kdbx::adapter::KdbxServer;
use mcp_kdbx::kdbx_core::config::Config;
use rmcp::ServiceExt;
use rmcp::transport::stdio;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Logs and the audit trail go to stderr; stdout is reserved for the
    // JSON-RPC stream that the MCP host reads.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_env("KDBX_LOG_LEVEL")
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    // A configuration error is fatal: report it on stderr and exit non-zero
    // rather than starting a server that cannot work.
    let config = match Config::from_env() {
        Ok(config) => config,
        Err(e) => {
            eprintln!("mcp-kdbx: configuration error: {e}");
            std::process::exit(1);
        }
    };

    let server = KdbxServer::new(config);
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
