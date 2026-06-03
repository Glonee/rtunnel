use std::sync::Arc;

use anyhow::Context;
use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
    sync::Mutex,
};
use tokio_boring::SslStreamBuilder;

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
        let ssl = connector.configure()?.into_ssl(server_name)?;
        ssl.set_enable_ech_grease(true);
        let mut stream = SslStreamBuilder::new(ssl, tcp).connect().await?;
        let password = self
            .cfg
            .password
            .as_deref()
            .context("anytls outbound requires password")?;

        codec::write_client_hello(&mut stream, password).await?;
        codec::write_frame(
            &mut stream,
            codec::CMD_SETTINGS,
            0,
            &codec::client_settings(),
        )
        .await?;
        codec::write_connect(&mut stream, &session.target).await?;

        let (client_side, relay_side) = tokio::io::duplex(64 * 1024);
        let (mut app_reader, mut app_writer) = tokio::io::split(relay_side);
        let (mut tls_reader, tls_writer) = tokio::io::split(stream);
        let tls_writer = Arc::new(Mutex::new(tls_writer));
        const STREAM_ID: u32 = 1;

        {
            let tls_writer = tls_writer.clone();
            tokio::spawn(async move {
                let mut buf = [0; 16 * 1024];
                loop {
                    match app_reader.read(&mut buf).await {
                        Ok(0) => {
                            let _ = write_frame(&tls_writer, codec::CMD_FIN, STREAM_ID, &[]).await;
                            break;
                        }
                        Ok(n) => {
                            if write_frame(&tls_writer, codec::CMD_PSH, STREAM_ID, &buf[..n])
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(_) => {
                            let _ = write_frame(&tls_writer, codec::CMD_FIN, STREAM_ID, &[]).await;
                            break;
                        }
                    }
                }
            });
        }

        tokio::spawn(async move {
            loop {
                match codec::read_frame(&mut tls_reader).await {
                    Ok(frame)
                        if frame.command == codec::CMD_PSH && frame.stream_id == STREAM_ID =>
                    {
                        if app_writer.write_all(&frame.data).await.is_err() {
                            break;
                        }
                    }
                    Ok(frame)
                        if frame.command == codec::CMD_FIN && frame.stream_id == STREAM_ID =>
                    {
                        break;
                    }
                    Ok(frame) if frame.command == codec::CMD_HEART_REQUEST => {
                        let _ = write_frame(
                            &tls_writer,
                            codec::CMD_HEART_RESPONSE,
                            frame.stream_id,
                            &[],
                        )
                        .await;
                    }
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
        });

        Ok(Box::new(client_side))
    }
}

async fn write_frame<W>(
    writer: &Arc<Mutex<W>>,
    command: u8,
    stream_id: u32,
    data: &[u8],
) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut writer = writer.lock().await;
    codec::write_frame(&mut *writer, command, stream_id, data).await
}
