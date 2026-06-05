use std::{path::PathBuf, sync::Arc};

use anyhow::Context;
use clap::Parser;
use rtunnel::{acme::AcmeManager, config::Config, protocol, router::Router};
use tokio::signal;
use tracing::info;

#[derive(Debug, Parser)]
#[command(
    name = "rtunnel",
    about = "A Rust proxy MVP with SOCKS5, AnyTLS, and TUIC"
)]
struct Args {
    #[arg(short, long, default_value = "rtunnel.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut cfg = Config::load(&args.config)
        .with_context(|| format!("failed to load config {}", args.config.display()))?;

    tracing_subscriber::fmt()
        .with_env_filter(cfg.log_level.as_deref().unwrap_or("info"))
        .init();

    let acme = AcmeManager::prepare(&mut cfg).await?;
    if let Some(acme) = acme {
        acme.spawn_renewal_tasks();
    }

    let router = Arc::new(Router::new(cfg.clone())?);
    for inbound_cfg in cfg.inbounds.clone() {
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(err) = protocol::run_inbound(inbound_cfg, router).await {
                tracing::error!(%err, "inbound exited");
            }
        });
    }

    info!("rtunnel started");
    signal::ctrl_c()
        .await
        .context("failed to wait for ctrl-c")?;
    info!("rtunnel stopped");
    Ok(())
}
