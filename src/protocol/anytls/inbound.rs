use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use anyhow::Context;
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc},
};
use tokio_boring::{SslStream, accept};
use tracing::{debug, info};

use crate::{
    config::InboundConfig,
    protocol::anytls::codec,
    router::Router,
    session::{BoxDatagram, BoxStream, Command, Session, TargetAddr},
    tls,
};

type TlsWriteHalf = WriteHalf<SslStream<TcpStream>>;
const UOT_CHANNEL_CAPACITY: usize = 128;

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
                let mut streams: HashMap<u32, InboundStream> = HashMap::new();
                let mut synacked_streams: HashSet<u32> = HashSet::new();
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
                            if client_v2 && synacked_streams.insert(frame.stream_id) {
                                write_frame(&writer, codec::CMD_SYNACK, frame.stream_id, &[])
                                    .await?;
                            }
                        }
                        codec::CMD_PSH => {
                            if !settings_seen {
                                write_alert(&writer, "cmdSettings is required before cmdPSH")
                                    .await?;
                                anyhow::bail!("anytls data sent before settings");
                            }
                            if let Some(stream) = streams.get_mut(&frame.stream_id) {
                                match stream {
                                    InboundStream::Tcp(stream) => {
                                        stream.write_all(&frame.data).await?;
                                    }
                                    InboundStream::Udp(tx) => {
                                        let _ = tx.send(frame.data).await;
                                    }
                                }
                                continue;
                            }

                            let (target, consumed) = codec::decode_socksaddr(&frame.data)?;
                            if codec::is_uot_v2_magic_target(&target) {
                                let (tx, rx) = mpsc::channel(UOT_CHANNEL_CAPACITY);
                                if consumed < frame.data.len() {
                                    let _ = tx.send(frame.data[consumed..].to_vec()).await;
                                }
                                streams.insert(frame.stream_id, InboundStream::Udp(tx));
                                if client_v2 && synacked_streams.insert(frame.stream_id) {
                                    write_frame(&writer, codec::CMD_SYNACK, frame.stream_id, &[])
                                        .await?;
                                }
                                spawn_uot_reader(
                                    frame.stream_id,
                                    cfg.tag.clone(),
                                    rx,
                                    router.clone(),
                                    writer.clone(),
                                );
                                continue;
                            }

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
                            streams.insert(frame.stream_id, InboundStream::Tcp(write_half));
                            if client_v2 && synacked_streams.insert(frame.stream_id) {
                                write_frame(&writer, codec::CMD_SYNACK, frame.stream_id, &[])
                                    .await?;
                            }
                            spawn_outbound_reader(frame.stream_id, read_half, writer.clone());
                        }
                        codec::CMD_FIN => {
                            streams.remove(&frame.stream_id);
                            synacked_streams.remove(&frame.stream_id);
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

enum InboundStream {
    Tcp(WriteHalf<BoxStream>),
    Udp(mpsc::Sender<Vec<u8>>),
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

fn spawn_uot_reader(
    stream_id: u32,
    inbound: String,
    rx: mpsc::Receiver<Vec<u8>>,
    router: Arc<Router>,
    writer: Arc<Mutex<TlsWriteHalf>>,
) {
    tokio::spawn(async move {
        let result = run_uot_stream(stream_id, inbound, rx, router, writer.clone()).await;
        if let Err(err) = result {
            debug!(%err, "anytls uot stream failed");
        }
        let _ = write_frame(&writer, codec::CMD_FIN, stream_id, &[]).await;
    });
}

async fn run_uot_stream(
    stream_id: u32,
    inbound: String,
    rx: mpsc::Receiver<Vec<u8>>,
    router: Arc<Router>,
    writer: Arc<Mutex<TlsWriteHalf>>,
) -> anyhow::Result<()> {
    let mut input = ChunkReader::new(rx);
    let connect = input.read_u8().await? == 1;
    let request_target = input.read_socks_target().await?;
    let session = Session {
        inbound,
        command: Command::UdpAssociate,
        target: request_target.clone(),
    };
    let outbound = router.dial_udp(&session).await?;
    if connect {
        run_uot_connect_stream(stream_id, request_target, input, outbound, writer).await
    } else {
        run_uot_packet_stream(stream_id, input, outbound, writer).await
    }
}

async fn run_uot_connect_stream(
    stream_id: u32,
    target: TargetAddr,
    mut input: ChunkReader,
    outbound: BoxDatagram,
    writer: Arc<Mutex<TlsWriteHalf>>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            payload = input.read_len_payload() => {
                let payload = payload?;
                outbound.send_to(&target, &payload).await?;
            }
            received = outbound.recv_from() => {
                let (_source, payload) = received?;
                let frame = codec::encode_uot_payload(&payload)?;
                write_frame(&writer, codec::CMD_PSH, stream_id, &frame).await?;
            }
        }
    }
}

async fn run_uot_packet_stream(
    stream_id: u32,
    mut input: ChunkReader,
    outbound: BoxDatagram,
    writer: Arc<Mutex<TlsWriteHalf>>,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            packet = input.read_packet() => {
                let (target, payload) = packet?;
                outbound.send_to(&target, &payload).await?;
            }
            received = outbound.recv_from() => {
                let (source, payload) = received?;
                let frame = codec::encode_uot_packet(&source, &payload)?;
                write_frame(&writer, codec::CMD_PSH, stream_id, &frame).await?;
            }
        }
    }
}

struct ChunkReader {
    rx: mpsc::Receiver<Vec<u8>>,
    chunks: VecDeque<Vec<u8>>,
    front_offset: usize,
    buffered: usize,
}

impl ChunkReader {
    fn new(rx: mpsc::Receiver<Vec<u8>>) -> Self {
        Self {
            rx,
            chunks: VecDeque::new(),
            front_offset: 0,
            buffered: 0,
        }
    }

    async fn read_u8(&mut self) -> anyhow::Result<u8> {
        let bytes = self.read_exact(1).await?;
        Ok(bytes[0])
    }

    async fn read_u16(&mut self) -> anyhow::Result<u16> {
        let bytes = self.read_exact(2).await?;
        Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
    }

    async fn read_len_payload(&mut self) -> anyhow::Result<Vec<u8>> {
        let len = self.read_u16().await? as usize;
        self.read_exact(len).await
    }

    async fn read_packet(&mut self) -> anyhow::Result<(TargetAddr, Vec<u8>)> {
        let target = self.read_uot_packet_target().await?;
        let payload = self.read_len_payload().await?;
        Ok((target, payload))
    }

    async fn read_socks_target(&mut self) -> anyhow::Result<TargetAddr> {
        let atyp = self.read_u8().await?;
        match atyp {
            0x01 => {
                let bytes = self.read_exact(6).await?;
                let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                let port = u16::from_be_bytes([bytes[4], bytes[5]]);
                Ok(TargetAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port)))
            }
            0x02 => {
                let len = self.read_u8().await?;
                let bytes = self.read_exact(len as usize + 2).await?;
                let host = String::from_utf8(bytes[..len as usize].to_vec())?;
                let port = u16::from_be_bytes([bytes[len as usize], bytes[len as usize + 1]]);
                Ok(TargetAddr::Domain { host, port })
            }
            0x03 => {
                let len = self.read_u8().await?;
                let bytes = self.read_exact(len as usize + 2).await?;
                let host = String::from_utf8(bytes[..len as usize].to_vec())?;
                let port = u16::from_be_bytes([bytes[len as usize], bytes[len as usize + 1]]);
                Ok(TargetAddr::Domain { host, port })
            }
            0x04 => {
                let bytes = self.read_exact(18).await?;
                let mut octets = [0; 16];
                octets.copy_from_slice(&bytes[..16]);
                let port = u16::from_be_bytes([bytes[16], bytes[17]]);
                Ok(TargetAddr::Ip(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(octets)),
                    port,
                )))
            }
            other => anyhow::bail!("unsupported uot request address type {other}"),
        }
    }

    async fn read_uot_packet_target(&mut self) -> anyhow::Result<TargetAddr> {
        let atyp = self.read_u8().await?;
        match atyp {
            0x00 => {
                let bytes = self.read_exact(6).await?;
                let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
                let port = u16::from_be_bytes([bytes[4], bytes[5]]);
                Ok(TargetAddr::Ip(SocketAddr::new(IpAddr::V4(ip), port)))
            }
            0x01 => {
                let bytes = self.read_exact(18).await?;
                let mut octets = [0; 16];
                octets.copy_from_slice(&bytes[..16]);
                let port = u16::from_be_bytes([bytes[16], bytes[17]]);
                Ok(TargetAddr::Ip(SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::from(octets)),
                    port,
                )))
            }
            0x02 => {
                let len = self.read_u8().await?;
                let bytes = self.read_exact(len as usize + 2).await?;
                let host = String::from_utf8(bytes[..len as usize].to_vec())?;
                let port = u16::from_be_bytes([bytes[len as usize], bytes[len as usize + 1]]);
                Ok(TargetAddr::Domain { host, port })
            }
            other => anyhow::bail!("unsupported uot packet address type {other}"),
        }
    }

    async fn read_exact(&mut self, len: usize) -> anyhow::Result<Vec<u8>> {
        while self.buffered < len {
            let chunk = self
                .rx
                .recv()
                .await
                .ok_or_else(|| anyhow::anyhow!("uot stream closed"))?;
            self.buffered += chunk.len();
            if !chunk.is_empty() {
                self.chunks.push_back(chunk);
            }
        }

        let mut output = Vec::with_capacity(len);
        let mut remaining = len;
        while remaining > 0 {
            let Some(front) = self.chunks.front() else {
                break;
            };
            let available = front.len() - self.front_offset;
            let take = remaining.min(available);
            output.extend_from_slice(&front[self.front_offset..self.front_offset + take]);
            self.front_offset += take;
            self.buffered -= take;
            remaining -= take;

            if self.front_offset == front.len() {
                self.chunks.pop_front();
                self.front_offset = 0;
            }
        }
        Ok(output)
    }
}
