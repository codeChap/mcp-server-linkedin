mod api;
mod auth;
mod config;
mod params;
mod server;

use anyhow::Result;
use rmcp::{ServiceExt, transport::stdio};
use tracing_subscriber::EnvFilter;

use api::LinkedInClient;
use server::LinkedInServer;

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    // Handle --auth flag: run the one-time browser authorization flow.
    if args.iter().any(|a| a == "--auth") {
        tracing_subscriber::fmt()
            .with_env_filter(EnvFilter::from_default_env())
            .with_writer(std::io::stderr)
            .init();

        let cfg = config::load()?;
        auth::authorize(&cfg.client_id, &cfg.client_secret, cfg.scopes.as_deref()).await?;
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cfg = config::load()?;

    let tokens = auth::load_tokens().ok_or_else(|| {
        anyhow::anyhow!(
            "No tokens found. Run `linkedin --auth` first to authorize with LinkedIn."
        )
    })?;

    let client = LinkedInClient::new(cfg.client_id, cfg.client_secret, tokens);
    let server = LinkedInServer::new(client);

    let service = server.serve(stdio()).await?;
    service.waiting().await?;
    Ok(())
}
