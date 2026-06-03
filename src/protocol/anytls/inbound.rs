use std::{collections::HashMap, sync::Arc};

use anyhow::Context;
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tokio_boring::{SslStream, accept};
use tracing::{debug, info};

use crate::{
    config::InboundConfig,
    protocol::anytls::codec,
    router::Router,
    session::{BoxStream, Command, Session},
    tls,
};

type TlsWriteHalf = WriteHalf<SslStream<TcpStream>>;

pub async fn run(cfg: InboundConfig, router: Arc<Router>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    serve(listener, cfg, router).await
}

pub async fn serve(
    listener: TcpListener,
    cfg: InboundConfig,
    router: Arc<Router>,
) -> anyhow::Result<()> {
    let tls_cfg = cfg
        .tls
        .as_ref()
        .context("anytls inbound requires tls config")?;
    let padding_rules = codec::parse_padding_scheme(&cfg.padding_scheme)?;
    let server_padding_md5 = codec::padding_scheme_md5(&cfg.padding_scheme);
    let server_padding_scheme = codec::padding_scheme_payload(&cfg.padding_scheme);
    let acceptor = Arc::new(tls::server_acceptor(tls_cfg)?);
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
        let server_padding_md5 = server_padding_md5.clone();
        let server_padding_scheme = server_padding_scheme.clone();
        tokio::spawn(async move {
            let result: anyhow::Result<()> = async {
                let mut tls_stream = accept(&acceptor, stream).await?;
                let users = cfg
                    .users
                    .as_deref()
                    .context("anytls inbound requires users")?;
                let username = codec::read_client_hello(&mut tls_stream, users).await?;
                let (mut reader, writer) = tokio::io::split(tls_stream);
                let writer = Arc::new(Mutex::new(writer));
                let mut streams: HashMap<u32, WriteHalf<BoxStream>> = HashMap::new();
                let mut settings_seen = false;
                let mut client_v2 = false;

                loop {
                    let frame = codec::read_frame(&mut reader).await?;
                    match frame.command {
                        codec::CMD_SETTINGS => {
                            settings_seen = true;
                            client_v2 =
                                codec::settings_version(&frame.data).is_some_and(|v| v >= 2);
                            if client_v2 {
                                write_frame(
                                    &writer,
                                    codec::CMD_SERVER_SETTINGS,
                                    0,
                                    codec::settings(),
                                )
                                .await?;
                            }
                            if codec::settings_value(&frame.data, "padding-md5")
                                != Some(server_padding_md5.as_str())
                            {
                                write_frame(
                                    &writer,
                                    codec::CMD_UPDATE_PADDING_SCHEME,
                                    0,
                                    &server_padding_scheme,
                                )
                                .await?;
                            }
                        }
                        codec::CMD_SYN => {
                            if !settings_seen {
                                write_alert(&writer, "cmdSettings is required before cmdSYN")
                                    .await?;
                                anyhow::bail!("anytls stream opened before settings");
                            }
                        }
                        codec::CMD_PSH => {
                            if !settings_seen {
                                write_alert(&writer, "cmdSettings is required before cmdPSH")
                                    .await?;
                                anyhow::bail!("anytls data sent before settings");
                            }
                            if let Some(stream) = streams.get_mut(&frame.stream_id) {
                                stream.write_all(&frame.data).await?;
                                continue;
                            }

                            let (target, consumed) = codec::decode_socksaddr(&frame.data)?;
                            let session = Session {
                                inbound: cfg.tag.clone(),
                                command: Command::Connect,
                                target,
                            };
                            let outbound = router.dial(&session).await?;
                            debug!(%peer, %username, target = %session.target, "anytls connected");
                            let (read_half, mut write_half) = tokio::io::split(outbound);
                            if consumed < frame.data.len() {
                                write_half.write_all(&frame.data[consumed..]).await?;
                            }
                            streams.insert(frame.stream_id, write_half);
                            if client_v2 {
                                write_frame(&writer, codec::CMD_SYNACK, frame.stream_id, &[])
                                    .await?;
                            }
                            spawn_outbound_reader(frame.stream_id, read_half, writer.clone());
                        }
                        codec::CMD_FIN => {
                            streams.remove(&frame.stream_id);
                        }
                        codec::CMD_WASTE => {}
                        codec::CMD_HEART_REQUEST => {
                            write_frame(&writer, codec::CMD_HEART_RESPONSE, frame.stream_id, &[])
                                .await?;
                        }
                        other => debug!(%other, "ignored anytls frame"),
                    }
                }
            }
            .await;
            if let Err(err) = result {
                debug!(%peer, %err, "anytls session failed");
            }
        });
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

async fn write_alert<W>(writer: &Arc<Mutex<W>>, message: &str) -> anyhow::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write_frame(writer, codec::CMD_ALERT, 0, message.as_bytes()).await
}

fn spawn_outbound_reader(
    stream_id: u32,
    mut read_half: ReadHalf<BoxStream>,
    writer: Arc<Mutex<TlsWriteHalf>>,
) {
    tokio::spawn(async move {
        let mut buf = [0; 16 * 1024];
        loop {
            match read_half.read(&mut buf).await {
                Ok(0) => {
                    let _ = write_frame(&writer, codec::CMD_FIN, stream_id, &[]).await;
                    break;
                }
                Ok(n) => {
                    if write_frame(&writer, codec::CMD_PSH, stream_id, &buf[..n])
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Err(_) => {
                    let _ = write_frame(&writer, codec::CMD_FIN, stream_id, &[]).await;
                    break;
                }
            }
        }
    });
}
