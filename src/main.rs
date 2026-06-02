mod config;
mod protocol;
mod router;
mod session;
mod tls;

use std::{path::PathBuf, sync::Arc};

use anyhow::Context;
use clap::Parser;
use tokio::signal;
use tracing::info;

use crate::{config::Config, protocol::inbound, router::Router};

#[derive(Debug, Parser)]
#[command(
    name = "rtunel",
    about = "A Rust proxy MVP with SOCKS5, AnyTLS, and TUIC"
)]
struct Args {
    #[arg(short, long, default_value = "rtunel.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let cfg = Config::load(&args.config)
        .with_context(|| format!("failed to load config {}", args.config.display()))?;

    tracing_subscriber::fmt()
        .with_env_filter(cfg.log_level.as_deref().unwrap_or("info"))
        .init();

    let router = Arc::new(Router::new(cfg.clone())?);
    for inbound_cfg in cfg.inbounds.clone() {
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(err) = inbound::run(inbound_cfg, router).await {
                tracing::error!(%err, "inbound exited");
            }
        });
    }

    info!("rtunel started");
    signal::ctrl_c()
        .await
        .context("failed to wait for ctrl-c")?;
    info!("rtunel stopped");
    Ok(())
}
