use std::{path::PathBuf, sync::Arc};

use anyhow::Context;
use clap::Parser;
use mimalloc::MiMalloc;
use rtunnel::{acme::AcmeManager, config::Config, protocol, router::Router};
use tokio::{signal, task::JoinSet};
use tracing::info;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

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

    let router = Arc::new(Router::new(cfg.clone()).await?);
    let mut inbounds = JoinSet::new();
    for inbound_cfg in cfg.inbounds.clone() {
        let router = router.clone();
        inbounds.spawn(async move {
            let label = format!("inbound {} on {}", inbound_cfg.tag, inbound_cfg.listen);
            protocol::run_inbound(inbound_cfg, router)
                .await
                .with_context(|| format!("{label} failed"))?;
            anyhow::bail!("{label} exited unexpectedly")
        });
    }

    info!("rtunnel started");
    tokio::select! {
        result = inbounds.join_next() => {
            return result.context("no inbounds configured")?
                .context("inbound task failed")?;
        }
        result = signal::ctrl_c() => result.context("failed to wait for ctrl-c")?,
    }
    inbounds.abort_all();
    info!("rtunnel stopped");
    Ok(())
}
