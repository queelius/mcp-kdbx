//! mcp-kdbx binary entry point.
//!
//! Reads configuration from the environment, builds the audit log and the
//! server, and serves the MCP protocol over stdio (rmcp). The vault starts
//! locked and is opened on the first `kdbx_unlock`. Diagnostic logs and the
//! JSONL audit trail go to stderr (and the audit file, when configured) so they
//! never collide with the JSON-RPC stream on stdout.

use mcp_kdbx::adapter::KdbxServer;
use mcp_kdbx::kdbx_core::audit::AuditLog;
use mcp_kdbx::kdbx_core::config::Config;
use mcp_kdbx::kdbx_core::orphan;
use rmcp::ServiceExt;
use rmcp::transport::stdio;
use std::time::SystemTime;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Diagnostic tracing goes to stderr; stdout is reserved for the JSON-RPC
    // stream the MCP host reads. The audit trail is separate (AuditLog below).
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

    // Open the append-only audit file if KDBX_LOG_FILE is set. A failure to open
    // it is not fatal: fall back to stderr-only and warn, so auditing degrades
    // rather than blocking the server.
    let audit = build_audit_log(&config);

    // Startup step 8 (spec section 2): clean orphaned save temp files when asked.
    if config.auto_clean_orphans {
        let report = orphan::clean_orphans(&config.vault_path, SystemTime::now());
        for removed in &report.removed {
            tracing::info!(path = %removed.display(), "removed orphaned save temp file");
        }
        for problem in &report.errors {
            tracing::warn!("orphan cleanup: {problem}");
        }
    }

    let server = KdbxServer::new(config, audit);
    server.announce_start();

    // Spawn the idle-lock timer on a clone of the server (cheap: Arc fields).
    tokio::spawn(server.clone().run_idle_timer());

    // Serve MCP over stdio until the host closes the connection.
    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}

/// Build the audit log from the configured log file, falling back to stderr-only
/// when no file is set or it cannot be opened.
fn build_audit_log(config: &Config) -> AuditLog {
    let Some(path) = &config.log_file else {
        return AuditLog::stderr_only();
    };
    match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(file) => AuditLog::new(Some(file)),
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                "could not open audit log file, using stderr only: {e}"
            );
            AuditLog::stderr_only()
        }
    }
}
