use anyhow::Context;
use async_trait::async_trait;
use tokio::net::TcpStream;
use tokio_boring::connect;

use crate::{
    config::OutboundConfig,
    protocol::anytls::codec,
    router::Outbound,
    session::{BoxStream, Command, Session},
    tls,
};

pub struct AnytlsOutbound {
    cfg: OutboundConfig,
}

impl AnytlsOutbound {
    pub fn new(cfg: OutboundConfig) -> anyhow::Result<Self> {
        cfg.require_server()?;
        Ok(Self { cfg })
    }
}

#[async_trait]
impl Outbound for AnytlsOutbound {
    async fn dial(&self, session: &Session) -> anyhow::Result<BoxStream> {
        anyhow::ensure!(
            matches!(session.command, Command::Connect),
            "anytls outbound only supports CONNECT"
        );
        let tcp = TcpStream::connect(self.cfg.require_server()?).await?;
        let connector = tls::chrome_like_connector(self.cfg.insecure)?;
        let server_name = self
            .cfg
            .server_name
            .as_deref()
            .context("anytls outbound requires server_name")?;
        let mut stream = connect(connector.configure()?, server_name, tcp).await?;
        let password = self
            .cfg
            .password
            .as_deref()
            .context("anytls outbound requires password")?;
        let token = codec::token(stream.ssl(), password)?;
        codec::write_auth(&mut stream, &token).await?;
        codec::write_connect(&mut stream, &session.target, &[]).await?;
        Ok(Box::new(stream))
    }
}
