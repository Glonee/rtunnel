use anyhow::Context;
use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use tokio_boring::connect;

use crate::{
    config::OutboundConfig,
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
        stream
            .write_all(session.target.to_string().as_bytes())
            .await?;
        stream.write_all(b"\n").await?;
        let mut ok = [0; 3];
        stream.read_exact(&mut ok).await?;
        anyhow::ensure!(&ok == b"OK\n", "anytls peer rejected target");
        Ok(Box::new(stream))
    }
}
