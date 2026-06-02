use std::sync::Arc;

use anyhow::Context;
use tokio::net::UdpSocket;
use tracing::info;

use crate::{config::InboundConfig, router::Router};

pub async fn run(cfg: InboundConfig, _router: Arc<Router>) -> anyhow::Result<()> {
    let _ = std::any::type_name::<tokio_quiche::quiche::Config>();
    let _tls = cfg
        .tls
        .as_ref()
        .context("tuic inbound requires tls config")?;
    let socket = UdpSocket::bind(cfg.listen).await?;
    info!(
        tag = %cfg.tag,
        listen = %cfg.listen,
        local = %socket.local_addr()?,
        "tuic inbound bound with tokio-quiche selected; packet handling is not implemented in MVP"
    );
    std::future::pending::<()>().await;
    Ok(())
}
