use std::sync::Arc;

use anyhow::Context;
use futures_util::StreamExt;
use tokio::net::UdpSocket;
use tokio_quiche::{
    ApplicationOverQuic, QuicResult,
    metrics::DefaultMetrics,
    quic::{HandshakeInfo, QuicheConnection},
    settings::{CertificateKind, ConnectionParams, Hooks, QuicSettings, TlsCertificatePaths},
};
use tracing::{debug, info};

use crate::{config::InboundConfig, router::Router};

pub async fn run(cfg: InboundConfig, _router: Arc<Router>) -> anyhow::Result<()> {
    let tls = cfg
        .tls
        .as_ref()
        .context("tuic inbound requires tls config")?;
    let mut settings = QuicSettings::default();
    settings.alpn = vec![b"tuic".to_vec()];
    settings.verify_peer = false;
    settings.disable_client_ip_validation = true;
    let params = ConnectionParams::new_server(
        settings,
        TlsCertificatePaths {
            cert: tls.certificate.as_str(),
            private_key: tls.private_key.as_str(),
            kind: CertificateKind::X509,
        },
        Hooks::default(),
    );

    let socket = UdpSocket::bind(cfg.listen).await?;
    let mut listeners = tokio_quiche::listen([socket], params, DefaultMetrics)?;
    let mut connections = listeners.remove(0);
    info!(
        tag = %cfg.tag,
        listen = %cfg.listen,
        "tuic inbound listening with tokio-quiche"
    );

    while let Some(conn) = connections.next().await {
        match conn {
            Ok(conn) => {
                debug!("accepted tuic quic connection");
                conn.start(NoopTuicApp::default());
            }
            Err(err) => debug!(%err, "tuic quic accept failed"),
        }
    }
    anyhow::bail!("tuic listener ended")
}

struct NoopTuicApp {
    buffer: [u8; 1350],
}

impl Default for NoopTuicApp {
    fn default() -> Self {
        Self { buffer: [0; 1350] }
    }
}

impl ApplicationOverQuic for NoopTuicApp {
    fn on_conn_established(
        &mut self,
        _qconn: &mut QuicheConnection,
        _handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        Ok(())
    }

    fn should_act(&self) -> bool {
        true
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    async fn wait_for_data(&mut self, _qconn: &mut QuicheConnection) -> QuicResult<()> {
        std::future::pending::<()>().await;
        Ok(())
    }

    fn process_reads(&mut self, _qconn: &mut QuicheConnection) -> QuicResult<()> {
        Ok(())
    }

    fn process_writes(&mut self, _qconn: &mut QuicheConnection) -> QuicResult<()> {
        Ok(())
    }
}
