use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
};

use anyhow::Context;
use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
    sync::{Mutex, mpsc},
    time::{Duration, Instant},
};
use tokio_boring::{SslStream, SslStreamBuilder};

use crate::{
    config::OutboundConfig,
    protocol::anytls::codec,
    router::Outbound,
    session::{BoxDatagram, BoxStream, Command, ProxyDatagram, Session, TargetAddr},
    tls,
};

const UDP_STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const UDP_STREAM_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

pub struct AnytlsOutbound {
    cfg: OutboundConfig,
    state: Arc<Mutex<ClientState>>,
    session: Arc<Mutex<Option<Arc<ClientSession>>>>,
}

#[derive(Default)]
struct ClientState {
    padding_scheme: Vec<String>,
    padding_md5: Option<String>,
}

impl AnytlsOutbound {
    pub fn new(cfg: OutboundConfig) -> anyhow::Result<Self> {
        cfg.require_server()?;
        Ok(Self {
            cfg,
            state: Arc::new(Mutex::new(ClientState::default())),
            session: Arc::new(Mutex::new(None)),
        })
    }

    fn clone_client(&self) -> Self {
        Self {
            cfg: self.cfg.clone(),
            state: self.state.clone(),
            session: self.session.clone(),
        }
    }

    async fn session(&self) -> anyhow::Result<Arc<ClientSession>> {
        let mut slot = self.session.lock().await;
        if let Some(session) = slot.as_ref()
            && !session.is_closed()
        {
            return Ok(session.clone());
        }

        let session = self.connect_session().await?;
        *slot = Some(session.clone());
        Ok(session)
    }

    async fn connect_session(&self) -> anyhow::Result<Arc<ClientSession>> {
        let tcp = TcpStream::connect(self.cfg.require_server()?).await?;
        let connector = tls::chrome_like_connector(self.cfg.insecure)?;
        let server_name = self
            .cfg
            .server_name
            .as_deref()
            .context("anytls outbound requires server_name")?;
        let mut ssl = connector.configure()?.into_ssl(server_name)?;
        tls::configure_chrome_like_ssl(&mut ssl)?;
        let mut stream = SslStreamBuilder::new(ssl, tcp).connect().await?;
        let password = self
            .cfg
            .password
            .as_deref()
            .context("anytls outbound requires password")?;
        let (padding_md5, padding0_len) = {
            let state = self.state.lock().await;
            (
                state
                    .padding_md5
                    .clone()
                    .unwrap_or_else(|| codec::DEFAULT_PADDING_MD5.to_owned()),
                codec::padding0_len(&state.padding_scheme)?,
            )
        };

        codec::write_client_hello_with_padding(&mut stream, password, padding0_len).await?;
        let settings_frame = codec::encode_frame(
            codec::CMD_SETTINGS,
            0,
            &codec::client_settings_with_padding_md5(&padding_md5),
        )?;

        let (tls_reader, tls_writer) = tokio::io::split(stream);
        let session = Arc::new(ClientSession::new(
            tls_writer,
            settings_frame,
            self.state.clone(),
        ));
        tokio::spawn(session.clone().run_reader(tls_reader, self.state.clone()));
        Ok(session)
    }
}

#[async_trait]
impl Outbound for AnytlsOutbound {
    async fn dial(&self, session: &Session) -> anyhow::Result<BoxStream> {
        anyhow::ensure!(
            matches!(session.command, Command::Connect),
            "anytls outbound only supports CONNECT"
        );
        let session_state = self.session().await?;
        let stream_id = session_state.next_stream_id()?;
        let (client_side, relay_side) = tokio::io::duplex(64 * 1024);
        let (mut app_reader, mut app_writer) = tokio::io::split(relay_side);
        let (data_tx, mut data_rx) = mpsc::channel::<Vec<u8>>(32);

        {
            let mut streams = session_state.streams.lock().await;
            streams.insert(stream_id, data_tx);
        }

        if let Err(err) = session_state
            .write_connect(stream_id, &session.target)
            .await
        {
            session_state.close();
            session_state.streams.lock().await.remove(&stream_id);
            return Err(err);
        }

        {
            let session_state = session_state.clone();
            tokio::spawn(async move {
                let mut buf = [0; 16 * 1024];
                loop {
                    match app_reader.read(&mut buf).await {
                        Ok(0) => {
                            let _ = session_state
                                .write_frame(codec::CMD_FIN, stream_id, &[])
                                .await;
                            break;
                        }
                        Ok(n) => {
                            if session_state
                                .write_frame(codec::CMD_PSH, stream_id, &buf[..n])
                                .await
                                .is_err()
                            {
                                session_state.close();
                                break;
                            }
                        }
                        Err(_) => {
                            let _ = session_state
                                .write_frame(codec::CMD_FIN, stream_id, &[])
                                .await;
                            break;
                        }
                    }
                }
            });
        }

        tokio::spawn(async move {
            while let Some(data) = data_rx.recv().await {
                if app_writer.write_all(&data).await.is_err() {
                    break;
                }
            }
        });

        Ok(Box::new(client_side))
    }

    async fn dial_udp(&self, session: &Session) -> anyhow::Result<BoxDatagram> {
        anyhow::ensure!(
            matches!(session.command, Command::UdpAssociate),
            "anytls udp outbound only supports UDP associate"
        );
        let (response_tx, response_rx) = mpsc::unbounded_channel();
        let streams = Arc::new(Mutex::new(HashMap::new()));
        spawn_udp_stream_cleaner(streams.clone());
        Ok(Arc::new(AnytlsUdpSession {
            client: self.clone_client(),
            streams,
            response_tx,
            response_rx: Mutex::new(response_rx),
        }))
    }
}

type TlsReadHalf = ReadHalf<SslStream<TcpStream>>;
type TlsWriteHalf = WriteHalf<SslStream<TcpStream>>;

struct ClientSession {
    writer: Arc<Mutex<ClientWriter<TlsWriteHalf>>>,
    streams: Arc<Mutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>>,
    state: Arc<Mutex<ClientState>>,
    next_stream_id: AtomicU32,
    closed: AtomicBool,
}

impl ClientSession {
    fn new(writer: TlsWriteHalf, initial_buffer: Vec<u8>, state: Arc<Mutex<ClientState>>) -> Self {
        Self {
            writer: Arc::new(Mutex::new(ClientWriter::new(writer, initial_buffer))),
            streams: Arc::new(Mutex::new(HashMap::new())),
            state,
            next_stream_id: AtomicU32::new(1),
            closed: AtomicBool::new(false),
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn close(&self) {
        self.closed.store(true, Ordering::SeqCst);
    }

    fn next_stream_id(&self) -> anyhow::Result<u32> {
        let id = self.next_stream_id.fetch_add(1, Ordering::SeqCst);
        anyhow::ensure!(id != 0, "anytls stream id overflow");
        Ok(id)
    }

    async fn write_connect(
        &self,
        stream_id: u32,
        target: &crate::session::TargetAddr,
    ) -> anyhow::Result<()> {
        self.buffer_frame(codec::CMD_SYN, stream_id, &[]).await?;
        self.write_frame(codec::CMD_PSH, stream_id, &codec::encode_socksaddr(target)?)
            .await?;
        Ok(())
    }

    async fn buffer_frame(&self, command: u8, stream_id: u32, data: &[u8]) -> anyhow::Result<()> {
        let mut writer = self.writer.lock().await;
        writer.buffer_frame(command, stream_id, data)
    }

    async fn write_frame(&self, command: u8, stream_id: u32, data: &[u8]) -> anyhow::Result<()> {
        let plan = {
            let state = self.state.lock().await;
            codec::parse_padding_plan(&state.padding_scheme)?
        };
        let mut writer = self.writer.lock().await;
        writer.write_frame(command, stream_id, data, &plan).await
    }

    async fn run_reader(
        self: Arc<Self>,
        mut tls_reader: TlsReadHalf,
        state: Arc<Mutex<ClientState>>,
    ) {
        loop {
            match codec::read_frame(&mut tls_reader).await {
                Ok(frame) if frame.command == codec::CMD_PSH => {
                    let tx = { self.streams.lock().await.get(&frame.stream_id).cloned() };
                    if let Some(tx) = tx
                        && tx.send(frame.data).await.is_err()
                    {
                        self.streams.lock().await.remove(&frame.stream_id);
                    }
                }
                Ok(frame) if frame.command == codec::CMD_FIN => {
                    self.streams.lock().await.remove(&frame.stream_id);
                }
                Ok(frame) if frame.command == codec::CMD_SYNACK && !frame.data.is_empty() => {
                    tracing::warn!(
                        stream_id = frame.stream_id,
                        message = %String::from_utf8_lossy(&frame.data),
                        "anytls stream open failed"
                    );
                    self.streams.lock().await.remove(&frame.stream_id);
                }
                Ok(frame) if frame.command == codec::CMD_HEART_REQUEST => {
                    let _ = self
                        .write_frame(codec::CMD_HEART_RESPONSE, frame.stream_id, &[])
                        .await;
                }
                Ok(frame) if frame.command == codec::CMD_UPDATE_PADDING_SCHEME => {
                    if let Ok(scheme) = String::from_utf8(frame.data) {
                        let lines = scheme.lines().map(str::to_owned).collect::<Vec<_>>();
                        let mut state = state.lock().await;
                        state.padding_md5 = Some(codec::padding_scheme_md5(&lines));
                        state.padding_scheme = lines;
                    }
                }
                Ok(frame) if frame.command == codec::CMD_ALERT => {
                    tracing::warn!(
                        message = %String::from_utf8_lossy(&frame.data),
                        "anytls server alert"
                    );
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }

        self.close();
        self.streams.lock().await.clear();
    }
}

struct ClientWriter<W> {
    inner: W,
    buffer: Vec<u8>,
    packet_counter: u32,
    send_padding: bool,
}

impl<W> ClientWriter<W>
where
    W: AsyncWrite + Unpin,
{
    fn new(inner: W, initial_buffer: Vec<u8>) -> Self {
        Self {
            inner,
            buffer: initial_buffer,
            packet_counter: 0,
            send_padding: true,
        }
    }

    fn buffer_frame(&mut self, command: u8, stream_id: u32, data: &[u8]) -> anyhow::Result<()> {
        self.buffer
            .extend_from_slice(&codec::encode_frame(command, stream_id, data)?);
        Ok(())
    }

    async fn write_frame(
        &mut self,
        command: u8,
        stream_id: u32,
        data: &[u8],
        padding: &codec::PaddingPlan,
    ) -> anyhow::Result<()> {
        let frame = codec::encode_frame(command, stream_id, data)?;
        self.write_conn(frame, padding).await
    }

    async fn write_conn(
        &mut self,
        mut data: Vec<u8>,
        padding: &codec::PaddingPlan,
    ) -> anyhow::Result<()> {
        if !self.buffer.is_empty() {
            let mut buffered = std::mem::take(&mut self.buffer);
            buffered.extend_from_slice(&data);
            data = buffered;
        }

        if self.send_padding {
            self.packet_counter = self.packet_counter.wrapping_add(1);
            if self.packet_counter < padding.stop {
                for record in codec::shape_packet_payload(data, self.packet_counter, padding)? {
                    self.inner.write_all(&record).await?;
                }
                return Ok(());
            }
            self.send_padding = false;
        }

        self.inner.write_all(&data).await?;
        Ok(())
    }
}

struct AnytlsUdpSession {
    client: AnytlsOutbound,
    streams: Arc<Mutex<HashMap<TargetAddr, AnytlsUdpStream>>>,
    response_tx: mpsc::UnboundedSender<(TargetAddr, Vec<u8>)>,
    response_rx: Mutex<mpsc::UnboundedReceiver<(TargetAddr, Vec<u8>)>>,
}

struct AnytlsUdpStream {
    tx: mpsc::UnboundedSender<Vec<u8>>,
    last_used: Arc<StdMutex<Instant>>,
}

impl AnytlsUdpSession {
    async fn sender_for(
        &self,
        target: &TargetAddr,
    ) -> anyhow::Result<mpsc::UnboundedSender<Vec<u8>>> {
        let now = Instant::now();
        let mut streams = self.streams.lock().await;
        evict_idle_udp_streams(&mut streams, now);
        if let Some(stream) = streams.get(target) {
            touch_udp_activity(&stream.last_used, now);
            return Ok(stream.tx.clone());
        }

        let (tx, rx) = mpsc::unbounded_channel();
        let last_used = Arc::new(StdMutex::new(now));
        streams.insert(
            target.clone(),
            AnytlsUdpStream {
                tx: tx.clone(),
                last_used: last_used.clone(),
            },
        );
        spawn_uot_stream(
            self.client.clone_client(),
            target.clone(),
            rx,
            self.response_tx.clone(),
            last_used,
        );
        Ok(tx)
    }

    async fn remove_stream(&self, target: &TargetAddr) {
        self.streams.lock().await.remove(target);
    }
}

#[async_trait]
impl ProxyDatagram for AnytlsUdpSession {
    async fn send_to(&self, target: &TargetAddr, payload: &[u8]) -> anyhow::Result<()> {
        let mut data = payload.to_vec();
        for retry in 0..2 {
            let tx = self.sender_for(target).await?;
            match tx.send(data) {
                Ok(()) => return Ok(()),
                Err(err) if retry == 0 => {
                    data = err.0;
                    self.remove_stream(target).await;
                }
                Err(err) => {
                    return Err(anyhow::anyhow!(
                        "anytls udp stream for {target} is closed after retry: {} bytes unsent",
                        err.0.len()
                    ));
                }
            }
        }
        unreachable!("retry loop always returns")
    }

    async fn recv_from(&self) -> anyhow::Result<(TargetAddr, Vec<u8>)> {
        let mut rx = self.response_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("anytls udp session closed"))
    }
}

fn spawn_uot_stream(
    client: AnytlsOutbound,
    target: TargetAddr,
    mut payload_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    response_tx: mpsc::UnboundedSender<(TargetAddr, Vec<u8>)>,
    last_used: Arc<StdMutex<Instant>>,
) {
    tokio::spawn(async move {
        let result: anyhow::Result<()> = async {
            let session = Session {
                inbound: "anytls-udp-out".to_owned(),
                command: Command::Connect,
                target: codec::uot_v2_magic_target(),
            };
            let stream = client.dial(&session).await?;
            let (mut reader, mut writer) = tokio::io::split(stream);
            codec::write_uot_v2_request(&mut writer, true, &target).await?;

            loop {
                tokio::select! {
                    payload = payload_rx.recv() => {
                        let Some(payload) = payload else {
                            break;
                        };
                        touch_udp_activity(&last_used, Instant::now());
                        codec::write_uot_payload(&mut writer, &payload).await?;
                    }
                    payload = codec::read_uot_payload(&mut reader) => {
                        let payload = payload?;
                        touch_udp_activity(&last_used, Instant::now());
                        let _ = response_tx.send((target.clone(), payload));
                    }
                }
            }
            Ok(())
        }
        .await;

        if let Err(err) = result {
            tracing::debug!(%err, target = %target, "anytls udp stream failed");
        }
    });
}

fn spawn_udp_stream_cleaner(streams: Arc<Mutex<HashMap<TargetAddr, AnytlsUdpStream>>>) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(UDP_STREAM_CLEANUP_INTERVAL);
        loop {
            interval.tick().await;
            if Arc::strong_count(&streams) == 1 {
                break;
            }
            let evicted = {
                let mut streams = streams.lock().await;
                evict_idle_udp_streams(&mut streams, Instant::now())
            };
            if evicted > 0 {
                tracing::debug!(evicted, "anytls evicted idle udp streams");
            }
        }
    });
}

fn evict_idle_udp_streams(
    streams: &mut HashMap<TargetAddr, AnytlsUdpStream>,
    now: Instant,
) -> usize {
    let before = streams.len();
    streams.retain(|target, stream| {
        let last_used = udp_last_used(&stream.last_used, now);
        let keep = now.saturating_duration_since(last_used) < UDP_STREAM_IDLE_TIMEOUT;
        if !keep {
            tracing::debug!(%target, "anytls udp stream idle timeout");
        }
        keep
    });
    before - streams.len()
}

fn touch_udp_activity(last_used: &StdMutex<Instant>, now: Instant) {
    if let Ok(mut last_used) = last_used.lock() {
        *last_used = now;
    }
}

fn udp_last_used(last_used: &StdMutex<Instant>, fallback: Instant) -> Instant {
    last_used
        .lock()
        .map(|last_used| *last_used)
        .unwrap_or(fallback)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    fn frame_header(data: &[u8], offset: usize) -> (u8, u32, u16) {
        (
            data[offset],
            u32::from_be_bytes(data[offset + 1..offset + 5].try_into().unwrap()),
            u16::from_be_bytes(data[offset + 5..offset + 7].try_into().unwrap()),
        )
    }

    #[tokio::test]
    async fn client_writer_shapes_initial_settings_syn_and_psh_as_one_packet() {
        let (client, mut server) = tokio::io::duplex(1024);
        let initial_buffer = codec::encode_frame(codec::CMD_SETTINGS, 0, b"v=2").unwrap();
        let plan = codec::parse_padding_plan(&["stop=3".to_owned(), "1=64-64".to_owned()]).unwrap();
        let mut writer = ClientWriter::new(client, initial_buffer);

        writer.buffer_frame(codec::CMD_SYN, 1, &[]).unwrap();
        writer
            .write_frame(codec::CMD_PSH, 1, b"target", &plan)
            .await
            .unwrap();

        let mut packet = vec![0; 64];
        server.read_exact(&mut packet).await.unwrap();

        assert_eq!(
            frame_header(&packet, 0),
            (codec::CMD_SETTINGS, 0, b"v=2".len() as u16)
        );
        assert_eq!(frame_header(&packet, 10), (codec::CMD_SYN, 1, 0));
        assert_eq!(
            frame_header(&packet, 17),
            (codec::CMD_PSH, 1, b"target".len() as u16)
        );
        assert_eq!(frame_header(&packet, 30), (codec::CMD_WASTE, 0, 27));
    }

    #[test]
    fn evicts_idle_udp_streams() {
        let now = Instant::now();
        let old = now - UDP_STREAM_IDLE_TIMEOUT - Duration::from_secs(1);
        let (stale_tx, _stale_rx) = mpsc::unbounded_channel();
        let (fresh_tx, _fresh_rx) = mpsc::unbounded_channel();
        let stale = TargetAddr::Domain {
            host: "old.example".to_owned(),
            port: 443,
        };
        let fresh = TargetAddr::Domain {
            host: "fresh.example".to_owned(),
            port: 443,
        };
        let mut streams = HashMap::from([
            (
                stale.clone(),
                AnytlsUdpStream {
                    tx: stale_tx,
                    last_used: Arc::new(StdMutex::new(old)),
                },
            ),
            (
                fresh.clone(),
                AnytlsUdpStream {
                    tx: fresh_tx,
                    last_used: Arc::new(StdMutex::new(now)),
                },
            ),
        ]);

        assert_eq!(evict_idle_udp_streams(&mut streams, now), 1);
        assert!(!streams.contains_key(&stale));
        assert!(streams.contains_key(&fresh));
    }
}
