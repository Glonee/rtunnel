use std::sync::Arc;

use anyhow::Context;
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader, copy_bidirectional},
    net::TcpListener,
};
use tokio_boring::accept;
use tracing::{debug, info};

use crate::{
    config::InboundConfig,
    router::Router,
    session::{Command, Session, TargetAddr},
    tls,
};

pub async fn run(cfg: InboundConfig, router: Arc<Router>) -> anyhow::Result<()> {
    let tls_cfg = cfg
        .tls
        .as_ref()
        .context("anytls inbound requires tls config")?;
    let acceptor = Arc::new(tls::server_acceptor(tls_cfg)?);
    let listener = TcpListener::bind(cfg.listen).await?;
    info!(tag = %cfg.tag, listen = %cfg.listen, "anytls inbound listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let cfg = cfg.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let result = async {
                let mut tls_stream = accept(&acceptor, stream).await?;
                let mut first_line = String::new();
                let mut reader = BufReader::new(&mut tls_stream);
                reader.read_line(&mut first_line).await?;
                let target = parse_target(first_line.trim())?;
                let session = Session {
                    inbound: cfg.tag,
                    command: Command::Connect,
                    target,
                };
                let mut outbound = router.dial(&session).await?;
                reader.get_mut().write_all(b"OK\n").await?;
                copy_bidirectional(reader.get_mut(), &mut outbound).await?;
                anyhow::Ok(())
            }
            .await;
            if let Err(err) = result {
                debug!(%peer, %err, "anytls session failed");
            }
        });
    }
}

fn parse_target(raw: &str) -> anyhow::Result<TargetAddr> {
    let (host, port) = raw
        .rsplit_once(':')
        .context("anytls MVP expects first line as host:port")?;
    Ok(TargetAddr::Domain {
        host: host.to_owned(),
        port: port.parse()?,
    })
}
