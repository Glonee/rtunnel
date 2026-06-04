use std::{
    collections::{HashMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
};

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    sync::mpsc,
    time::{Duration, Instant},
};
use tokio_quiche::{
    ApplicationOverQuic, QuicResult,
    quic::{HandshakeInfo, QuicheConnection, connect_with_config},
    quiche,
    settings::{ConnectionParams, Hooks},
    socket::Socket,
};
use tracing::debug;
use uuid::Uuid;

use crate::{
    config::OutboundConfig,
    protocol::tuic::{IDLE_POLL_INTERVAL, codec, quic_settings},
    router::Outbound,
    session::{BoxDatagram, BoxStream, Command, ProxyDatagram, Session, TargetAddr},
};

const CONNECT_STREAM_ID: u64 = 0;
const AUTH_STREAM_ID: u64 = 2;
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);

pub struct TuicOutbound {
    cfg: OutboundConfig,
    uuid: Uuid,
    password: String,
}

impl TuicOutbound {
    pub fn new(cfg: OutboundConfig) -> anyhow::Result<Self> {
        cfg.require_server()?;
        let uuid = cfg
            .uuid
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("tuic outbound requires uuid"))?;
        let uuid = Uuid::parse_str(uuid)?;
        anyhow::ensure!(
            cfg.password
                .as_deref()
                .is_some_and(|password| !password.is_empty()),
            "tuic outbound requires password"
        );
        let password = cfg.password.clone().expect("password checked above");
        Ok(Self {
            cfg,
            uuid,
            password,
        })
    }
}

#[async_trait]
impl Outbound for TuicOutbound {
    async fn dial(&self, session: &Session) -> anyhow::Result<BoxStream> {
        anyhow::ensure!(
            matches!(session.command, Command::Connect),
            "tuic outbound only supports CONNECT"
        );

        let server = self.cfg.require_server()?;
        let server_name = self
            .cfg
            .server_name
            .as_deref()
            .map(str::to_owned)
            .unwrap_or_else(|| server.ip().to_string());
        let socket = UdpSocket::bind(if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        socket.connect(server).await?;
        let socket = Socket::try_from(socket)?;

        let mut settings = quic_settings();
        settings.verify_peer = !self.cfg.insecure;
        let params = ConnectionParams::new_client(settings, None, Hooks::default());

        let (client_side, relay_side) = tokio::io::duplex(64 * 1024);
        let (mut app_reader, mut app_writer) = tokio::io::split(relay_side);
        let (quic_tx, quic_rx) = mpsc::unbounded_channel();
        let (stream_tx, mut stream_rx) = mpsc::unbounded_channel::<Vec<u8>>();
        let target = session.target.clone();

        tokio::spawn({
            let quic_tx = quic_tx.clone();
            async move {
                let mut buf = [0; 16 * 1024];
                loop {
                    match app_reader.read(&mut buf).await {
                        Ok(0) => {
                            let _ = quic_tx.send(QuicWrite::Close);
                            break;
                        }
                        Ok(n) => {
                            let _ = quic_tx.send(QuicWrite::Data(buf[..n].to_vec()));
                        }
                        Err(_) => {
                            let _ = quic_tx.send(QuicWrite::Close);
                            break;
                        }
                    }
                }
            }
        });

        tokio::spawn(async move {
            while let Some(data) = stream_rx.recv().await {
                if app_writer.write_all(&data).await.is_err() {
                    break;
                }
            }
        });

        let app = TuicClientApp::new(self.uuid, self.password.clone(), target, quic_rx, stream_tx);
        connect_with_config(socket, Some(server_name.as_str()), &params, app)
            .await
            .map_err(|err| {
                anyhow::anyhow!("tuic outbound {} handshake failed: {err}", self.cfg.tag)
            })?;
        debug!(
            tag = %self.cfg.tag,
            server = %server,
            "tuic outbound connected"
        );

        Ok(Box::new(client_side))
    }

    async fn dial_udp(&self, session: &Session) -> anyhow::Result<BoxDatagram> {
        anyhow::ensure!(
            matches!(session.command, Command::UdpAssociate),
            "tuic udp outbound only supports UDP associate"
        );

        let server = self.cfg.require_server()?;
        let server_name = self
            .cfg
            .server_name
            .as_deref()
            .map(str::to_owned)
            .unwrap_or_else(|| server.ip().to_string());
        let socket = UdpSocket::bind(if server.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        socket.connect(server).await?;
        let socket = Socket::try_from(socket)?;

        let mut settings = quic_settings();
        settings.verify_peer = !self.cfg.insecure;
        let params = ConnectionParams::new_client(settings, None, Hooks::default());

        let (write_tx, write_rx) = mpsc::unbounded_channel();
        let (response_tx, response_rx) = mpsc::unbounded_channel();
        let app = TuicUdpOutboundApp::new(self.uuid, self.password.clone(), write_rx, response_tx);
        connect_with_config(socket, Some(server_name.as_str()), &params, app)
            .await
            .map_err(|err| {
                anyhow::anyhow!("tuic udp outbound {} handshake failed: {err}", self.cfg.tag)
            })?;

        Ok(Arc::new(TuicUdpSession {
            write_tx,
            response_rx: tokio::sync::Mutex::new(response_rx),
            pkt_id: AtomicU16::new(1),
        }))
    }
}

struct TuicClientApp {
    uuid: Uuid,
    password: String,
    target: TargetAddr,
    outbound_rx: mpsc::UnboundedReceiver<QuicWrite>,
    stream_tx: mpsc::UnboundedSender<Vec<u8>>,
    pending_writes: VecDeque<QuicWrite>,
    next_heartbeat: Instant,
    buffer: [u8; 16 * 1024],
}

enum QuicWrite {
    Data(Vec<u8>),
    Heartbeat,
    Close,
}

impl TuicClientApp {
    fn new(
        uuid: Uuid,
        password: String,
        target: TargetAddr,
        outbound_rx: mpsc::UnboundedReceiver<QuicWrite>,
        stream_tx: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Self {
        Self {
            uuid,
            password,
            target,
            outbound_rx,
            stream_tx,
            pending_writes: VecDeque::new(),
            next_heartbeat: Instant::now() + HEARTBEAT_INTERVAL,
            buffer: [0; 16 * 1024],
        }
    }

    fn send_all_or_queue(
        &mut self,
        qconn: &mut QuicheConnection,
        data: Vec<u8>,
        fin: bool,
    ) -> QuicResult<()> {
        match qconn.stream_send(CONNECT_STREAM_ID, &data, fin) {
            Ok(sent) if sent == data.len() => Ok(()),
            Ok(sent) => {
                self.pending_writes
                    .push_front(QuicWrite::Data(data[sent..].to_vec()));
                Ok(())
            }
            Err(quiche::Error::Done) => {
                self.pending_writes.push_front(QuicWrite::Data(data));
                Ok(())
            }
            Err(err) => Err(Box::new(err)),
        }
    }
}

impl ApplicationOverQuic for TuicClientApp {
    fn on_conn_established(
        &mut self,
        qconn: &mut QuicheConnection,
        _handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        let token = codec::token(qconn.as_mut(), self.uuid, &self.password)?;
        let auth = codec::encode_authenticate(self.uuid, token)?;
        qconn.stream_send(AUTH_STREAM_ID, &auth, true)?;

        let connect = codec::encode_connect(&self.target, &[])?;
        self.send_all_or_queue(qconn, connect, false)
    }

    fn should_act(&self) -> bool {
        true
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    async fn wait_for_data(&mut self, _qconn: &mut QuicheConnection) -> QuicResult<()> {
        if self.pending_writes.is_empty() {
            tokio::select! {
                write = self.outbound_rx.recv() => {
                    if let Some(write) = write {
                        self.pending_writes.push_back(write);
                    }
                }
                _ = tokio::time::sleep_until(self.next_heartbeat) => {
                    self.pending_writes.push_back(QuicWrite::Heartbeat);
                    self.next_heartbeat = Instant::now() + HEARTBEAT_INTERVAL;
                }
                _ = tokio::time::sleep(IDLE_POLL_INTERVAL) => {}
            }
        }
        Ok(())
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        while let Some(stream_id) = qconn.stream_readable_next() {
            loop {
                let mut buf = [0; 16 * 1024];
                match qconn.stream_recv(stream_id, &mut buf) {
                    Ok((read, fin)) => {
                        if stream_id == CONNECT_STREAM_ID && read > 0 {
                            let _ = self.stream_tx.send(buf[..read].to_vec());
                        }
                        if fin {
                            break;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(err) => return Err(Box::new(err)),
                }
            }
        }

        let mut dgram = [0; 1500];
        while let Ok(_read) = qconn.dgram_recv(&mut dgram) {}
        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        while let Ok(write) = self.outbound_rx.try_recv() {
            self.pending_writes.push_back(write);
        }

        while let Some(write) = self.pending_writes.pop_front() {
            match write {
                QuicWrite::Data(data) => match qconn.stream_send(CONNECT_STREAM_ID, &data, false) {
                    Ok(sent) if sent == data.len() => {}
                    Ok(sent) => {
                        self.pending_writes
                            .push_front(QuicWrite::Data(data[sent..].to_vec()));
                        break;
                    }
                    Err(quiche::Error::Done) => {
                        self.pending_writes.push_front(QuicWrite::Data(data));
                        break;
                    }
                    Err(err) => return Err(Box::new(err)),
                },
                QuicWrite::Heartbeat => {
                    let heartbeat = codec::encode_heartbeat()?;
                    match qconn.dgram_send(&heartbeat) {
                        Ok(_) => {}
                        Err(quiche::Error::Done) => {
                            self.pending_writes.push_front(QuicWrite::Heartbeat);
                            break;
                        }
                        Err(err) => return Err(Box::new(err)),
                    }
                }
                QuicWrite::Close => match qconn.stream_send(CONNECT_STREAM_ID, &[], true) {
                    Ok(_) => {}
                    Err(quiche::Error::Done) => {}
                    Err(_) => {}
                },
            }
        }
        Ok(())
    }
}

struct TuicUdpSession {
    write_tx: mpsc::UnboundedSender<TuicUdpWrite>,
    response_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<(TargetAddr, Vec<u8>)>>,
    pkt_id: AtomicU16,
}

#[async_trait]
impl ProxyDatagram for TuicUdpSession {
    async fn send_to(&self, target: &TargetAddr, payload: &[u8]) -> anyhow::Result<()> {
        let packet = codec::Packet {
            assoc_id: 1,
            pkt_id: self.pkt_id.fetch_add(1, Ordering::SeqCst),
            frag_total: 1,
            frag_id: 0,
            target: Some(target.clone()),
            payload: payload.to_vec(),
        };
        self.write_tx.send(TuicUdpWrite::Packet(packet))?;
        Ok(())
    }

    async fn recv_from(&self) -> anyhow::Result<(TargetAddr, Vec<u8>)> {
        let mut rx = self.response_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| anyhow::anyhow!("tuic udp session closed"))
    }
}

enum TuicUdpWrite {
    Packet(codec::Packet),
    Heartbeat,
}

struct TuicUdpOutboundApp {
    uuid: Uuid,
    password: String,
    outbound_rx: mpsc::UnboundedReceiver<TuicUdpWrite>,
    response_tx: mpsc::UnboundedSender<(TargetAddr, Vec<u8>)>,
    pending_writes: VecDeque<TuicUdpWrite>,
    packet_assembler: codec::PacketAssembler,
    stream_buffers: HashMap<u64, Vec<u8>>,
    next_heartbeat: Instant,
    buffer: [u8; 16 * 1024],
}

impl TuicUdpOutboundApp {
    fn new(
        uuid: Uuid,
        password: String,
        outbound_rx: mpsc::UnboundedReceiver<TuicUdpWrite>,
        response_tx: mpsc::UnboundedSender<(TargetAddr, Vec<u8>)>,
    ) -> Self {
        Self {
            uuid,
            password,
            outbound_rx,
            response_tx,
            pending_writes: VecDeque::new(),
            packet_assembler: codec::PacketAssembler::default(),
            stream_buffers: HashMap::new(),
            next_heartbeat: Instant::now() + HEARTBEAT_INTERVAL,
            buffer: [0; 16 * 1024],
        }
    }

    fn handle_packet(&mut self, data: &[u8]) -> QuicResult<()> {
        let packet = codec::parse_packet(data)?;
        if let Some(packet) = self.packet_assembler.push(packet)? {
            let Some(source) = packet.target else {
                return Err(anyhow::anyhow!("tuic udp response missing source").into());
            };
            let _ = self.response_tx.send((source, packet.payload));
        }
        Ok(())
    }
}

impl ApplicationOverQuic for TuicUdpOutboundApp {
    fn on_conn_established(
        &mut self,
        qconn: &mut QuicheConnection,
        _handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        let token = codec::token(qconn.as_mut(), self.uuid, &self.password)?;
        let auth = codec::encode_authenticate(self.uuid, token)?;
        qconn.stream_send(AUTH_STREAM_ID, &auth, true)?;
        Ok(())
    }

    fn should_act(&self) -> bool {
        true
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    async fn wait_for_data(&mut self, _qconn: &mut QuicheConnection) -> QuicResult<()> {
        if self.pending_writes.is_empty() {
            tokio::select! {
                write = self.outbound_rx.recv() => {
                    if let Some(write) = write {
                        self.pending_writes.push_back(write);
                    }
                }
                _ = tokio::time::sleep_until(self.next_heartbeat) => {
                    self.pending_writes.push_back(TuicUdpWrite::Heartbeat);
                    self.next_heartbeat = Instant::now() + HEARTBEAT_INTERVAL;
                }
                _ = tokio::time::sleep(IDLE_POLL_INTERVAL) => {}
            }
        }
        Ok(())
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        let mut dgram = [0; 64 * 1024];
        while let Ok(read) = qconn.dgram_recv(&mut dgram) {
            if read >= 2 && dgram[0] == codec::VERSION && dgram[1] == codec::CMD_PACKET {
                self.handle_packet(&dgram[..read])?;
            }
        }

        while let Some(stream_id) = qconn.stream_readable_next() {
            loop {
                let mut buf = [0; 16 * 1024];
                match qconn.stream_recv(stream_id, &mut buf) {
                    Ok((read, fin)) => {
                        self.stream_buffers
                            .entry(stream_id)
                            .or_default()
                            .extend_from_slice(&buf[..read]);
                        if fin {
                            if let Some(data) = self.stream_buffers.remove(&stream_id) {
                                self.handle_packet(&data)?;
                            }
                            break;
                        }
                    }
                    Err(quiche::Error::Done) => break,
                    Err(err) => return Err(Box::new(err)),
                }
            }
        }
        Ok(())
    }

    fn process_writes(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        while let Ok(write) = self.outbound_rx.try_recv() {
            self.pending_writes.push_back(write);
        }

        while let Some(write) = self.pending_writes.pop_front() {
            match write {
                TuicUdpWrite::Packet(packet) => {
                    let data = codec::encode_packet(&packet)?;
                    match qconn.dgram_send(&data) {
                        Ok(_) => {}
                        Err(quiche::Error::Done) => {
                            self.pending_writes.push_front(TuicUdpWrite::Packet(packet));
                            break;
                        }
                        Err(err) => return Err(Box::new(err)),
                    }
                }
                TuicUdpWrite::Heartbeat => {
                    let heartbeat = codec::encode_heartbeat()?;
                    match qconn.dgram_send(&heartbeat) {
                        Ok(_) => {}
                        Err(quiche::Error::Done) => {
                            self.pending_writes.push_front(TuicUdpWrite::Heartbeat);
                            break;
                        }
                        Err(err) => return Err(Box::new(err)),
                    }
                }
            }
        }
        Ok(())
    }
}
