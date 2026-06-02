use std::sync::Arc;

use anyhow::Context;
use tokio::{io::copy_bidirectional, net::TcpListener};
use tokio_boring::accept;
use tracing::{debug, info};

use crate::{
    config::InboundConfig,
    protocol::anytls::codec,
    router::Router,
    session::{Command, Session},
    tls,
};

pub async fn run(cfg: InboundConfig, router: Arc<Router>) -> anyhow::Result<()> {
    let tls_cfg = cfg
        .tls
        .as_ref()
        .context("anytls inbound requires tls config")?;
    let padding_rules = codec::parse_padding_scheme(&cfg.padding_scheme)?;
    let acceptor = Arc::new(tls::server_acceptor(tls_cfg)?);
    let listener = TcpListener::bind(cfg.listen).await?;
    info!(
        tag = %cfg.tag,
        listen = %cfg.listen,
        padding_rules = padding_rules.len(),
        "anytls inbound listening"
    );

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let cfg = cfg.clone();
        let router = router.clone();
        tokio::spawn(async move {
            let result = async {
                let mut tls_stream = accept(&acceptor, stream).await?;
                let users = cfg
                    .users
                    .as_deref()
                    .context("anytls inbound requires users")?;
                let presented = codec::read_auth(&mut tls_stream).await?;
                let username = codec::verify_auth(tls_stream.ssl(), users, &presented)?;
                let target = codec::read_connect(&mut tls_stream).await?;
                let session = Session {
                    inbound: cfg.tag,
                    command: Command::Connect,
                    target,
                };
                let mut outbound = router.dial(&session).await?;
                debug!(%peer, %username, target = %session.target, "anytls connected");
                copy_bidirectional(&mut tls_stream, &mut outbound).await?;
                anyhow::Ok(())
            }
            .await;
            if let Err(err) = result {
                debug!(%peer, %err, "anytls session failed");
            }
        });
    }
}
