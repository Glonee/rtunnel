use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
};

use anyhow::Context;
use futures_util::StreamExt;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    sync::mpsc,
};
use tokio_quiche::{
    ApplicationOverQuic, QuicResult,
    metrics::DefaultMetrics,
    quic::{HandshakeInfo, QuicheConnection},
    quiche,
    settings::{CertificateKind, ConnectionParams, Hooks, QuicSettings, TlsCertificatePaths},
};
use tracing::{debug, info};
use uuid::Uuid;

use crate::{
    config::{InboundConfig, UserConfig},
    protocol::tuic::codec,
    router::Router,
    session::{Command, Session, TargetAddr},
};

pub async fn run(cfg: InboundConfig, router: Arc<Router>) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(cfg.listen).await?;
    serve(socket, cfg, router).await
}

pub async fn serve(
    socket: UdpSocket,
    cfg: InboundConfig,
    router: Arc<Router>,
) -> anyhow::Result<()> {
    let tls = cfg
        .tls
        .as_ref()
        .context("tuic inbound requires tls config")?;
    let users = parse_users(cfg.users.as_deref().unwrap_or_default())?;
    let mut settings = QuicSettings::default();
    settings.alpn = vec![b"h3".to_vec()];
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

    let mut listeners = tokio_quiche::listen([socket], params, DefaultMetrics)?;
    let mut connections = listeners.remove(0);
    info!(
        tag = %cfg.tag,
        listen = %cfg.listen,
        users = users.len(),
        "tuic inbound listening with tokio-quiche"
    );

    while let Some(conn) = connections.next().await {
        match conn {
            Ok(conn) => {
                let app = TuicApp::new(cfg.tag.clone(), router.clone(), users.clone());
                debug!("accepted tuic quic connection");
                conn.start(app);
            }
            Err(err) => debug!(%err, "tuic quic accept failed"),
        }
    }
    anyhow::bail!("tuic listener ended")
}

#[derive(Clone)]
struct TuicUser {
    name: String,
    uuid: Uuid,
    password: String,
}

fn parse_users(users: &[UserConfig]) -> anyhow::Result<Vec<TuicUser>> {
    users
        .iter()
        .map(|user| {
            let uuid = user
                .uuid
                .as_deref()
                .ok_or_else(|| anyhow::anyhow!("tuic user {} requires uuid", user.username))?;
            Ok(TuicUser {
                name: user.username.clone(),
                uuid: Uuid::parse_str(uuid)?,
                password: user.password.clone(),
            })
        })
        .collect()
}

struct TuicApp {
    inbound: String,
    router: Arc<Router>,
    users: Vec<TuicUser>,
    authenticated: bool,
    username: Option<String>,
    uni_streams: HashMap<u64, Vec<u8>>,
    pending_uni_commands: Vec<Vec<u8>>,
    pending_datagrams: Vec<Vec<u8>>,
    pending_streams: HashMap<u64, PendingStream>,
    streams: HashMap<u64, StreamState>,
    udp_sessions: HashMap<u16, UdpSession>,
    packet_assembler: codec::PacketAssembler,
    next_uni_stream_id: u64,
    outbound_tx: mpsc::UnboundedSender<QuicWrite>,
    outbound_rx: mpsc::UnboundedReceiver<QuicWrite>,
    pending_writes: VecDeque<QuicWrite>,
    buffer: [u8; 16 * 1024],
}

struct StreamState {
    client_tx: mpsc::UnboundedSender<Vec<u8>>,
}

#[derive(Default)]
struct PendingStream {
    data: Vec<u8>,
    fin: bool,
}

struct UdpSession {
    tx: mpsc::UnboundedSender<UdpRequest>,
    mode: UdpMode,
}

struct UdpRequest {
    target: TargetAddr,
    payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UdpMode {
    Native,
    Quic,
}

enum QuicWrite {
    Data {
        stream_id: u64,
        data: Vec<u8>,
        fin: bool,
    },
    Datagram(Vec<u8>),
    UniStream {
        stream_id: Option<u64>,
        data: Vec<u8>,
    },
    Close {
        stream_id: u64,
    },
}

impl TuicApp {
    fn new(inbound: String, router: Arc<Router>, users: Vec<TuicUser>) -> Self {
        let (outbound_tx, outbound_rx) = mpsc::unbounded_channel();
        Self {
            inbound,
            router,
            users,
            authenticated: false,
            username: None,
            uni_streams: HashMap::new(),
            pending_uni_commands: Vec::new(),
            pending_datagrams: Vec::new(),
            pending_streams: HashMap::new(),
            streams: HashMap::new(),
            udp_sessions: HashMap::new(),
            packet_assembler: codec::PacketAssembler::default(),
            next_uni_stream_id: 3,
            outbound_tx,
            outbound_rx,
            pending_writes: VecDeque::new(),
            buffer: [0; 16 * 1024],
        }
    }

    fn handle_auth_data(&mut self, qconn: &mut QuicheConnection, data: &[u8]) -> QuicResult<()> {
        let (uuid, presented) = codec::parse_authenticate(data)?;
        let Some(user) = self.users.iter().find(|user| user.uuid == uuid) else {
            return Err(anyhow::anyhow!("tuic authentication: unknown uuid {uuid}").into());
        };
        let expected = codec::token(qconn.as_mut(), user.uuid, &user.password)?;
        if expected != presented {
            return Err(anyhow::anyhow!("tuic authentication: token mismatch").into());
        }
        self.authenticated = true;
        self.username = Some(user.name.clone());
        debug!(username = %user.name, "tuic authenticated");

        let pending_uni_commands = std::mem::take(&mut self.pending_uni_commands);
        for command in pending_uni_commands {
            self.handle_unidirectional_command(qconn, &command)?;
        }
        let pending_datagrams = std::mem::take(&mut self.pending_datagrams);
        for datagram in pending_datagrams {
            self.handle_datagram(&datagram)?;
        }
        let pending = std::mem::take(&mut self.pending_streams);
        for (stream_id, pending) in pending {
            if !pending.data.is_empty() {
                self.handle_stream_data(stream_id, &pending.data, pending.fin)?;
            }
        }
        Ok(())
    }

    fn handle_unidirectional_stream(
        &mut self,
        qconn: &mut QuicheConnection,
        stream_id: u64,
        data: &[u8],
        fin: bool,
    ) -> QuicResult<()> {
        self.uni_streams
            .entry(stream_id)
            .or_default()
            .extend_from_slice(data);
        if !fin {
            return Ok(());
        }
        let Some(command) = self.uni_streams.remove(&stream_id) else {
            return Ok(());
        };
        self.handle_unidirectional_command(qconn, &command)
    }

    fn handle_unidirectional_command(
        &mut self,
        qconn: &mut QuicheConnection,
        data: &[u8],
    ) -> QuicResult<()> {
        if data.len() < 2 {
            return Err(anyhow::anyhow!("short tuic command").into());
        }
        match data[1] {
            codec::CMD_AUTHENTICATE => self.handle_auth_data(qconn, data),
            codec::CMD_PACKET if !self.authenticated => {
                self.pending_uni_commands.push(data.to_vec());
                Ok(())
            }
            codec::CMD_PACKET => self.handle_packet(data, UdpMode::Quic),
            codec::CMD_DISSOCIATE if !self.authenticated => {
                self.pending_uni_commands.push(data.to_vec());
                Ok(())
            }
            codec::CMD_DISSOCIATE => {
                let assoc_id = codec::parse_dissociate(data)?;
                self.udp_sessions.remove(&assoc_id);
                Ok(())
            }
            other => Err(anyhow::anyhow!("unsupported tuic unidirectional command {other}").into()),
        }
    }

    fn handle_stream_data(&mut self, stream_id: u64, data: &[u8], fin: bool) -> QuicResult<()> {
        if !self.authenticated {
            let pending = self.pending_streams.entry(stream_id).or_default();
            pending.data.extend_from_slice(data);
            pending.fin |= fin;
            return Ok(());
        }

        if let Some(state) = self.streams.get(&stream_id) {
            if !data.is_empty() {
                let _ = state.client_tx.send(data.to_vec());
            }
            if fin {
                self.streams.remove(&stream_id);
            }
            return Ok(());
        }

        let (target, consumed) = codec::parse_connect(data)?;
        let initial = data[consumed..].to_vec();
        let session = Session {
            inbound: self.inbound.clone(),
            command: Command::Connect,
            target,
        };
        let (client_tx, client_rx) = mpsc::unbounded_channel();
        if !fin {
            self.streams.insert(stream_id, StreamState { client_tx });
        }
        debug!(
            username = self.username.as_deref().unwrap_or(""),
            target = %session.target,
            "tuic connected"
        );
        spawn_relay(
            self.router.clone(),
            session,
            stream_id,
            initial,
            client_rx,
            self.outbound_tx.clone(),
        );
        Ok(())
    }

    fn handle_datagram(&mut self, data: &[u8]) -> QuicResult<()> {
        if data.len() < 2 {
            return Err(anyhow::anyhow!("short tuic datagram").into());
        }
        match data[1] {
            codec::CMD_HEARTBEAT => Ok(()),
            codec::CMD_PACKET if !self.authenticated => {
                self.pending_datagrams.push(data.to_vec());
                Ok(())
            }
            codec::CMD_PACKET => self.handle_packet(data, UdpMode::Native),
            other => Err(anyhow::anyhow!("unsupported tuic datagram command {other}").into()),
        }
    }

    fn handle_packet(&mut self, data: &[u8], mode: UdpMode) -> QuicResult<()> {
        let packet = codec::parse_packet(data)?;
        if let Some(packet) = self.packet_assembler.push(packet)? {
            let Some(target) = packet.target.clone() else {
                return Err(anyhow::anyhow!("tuic packet is missing target").into());
            };
            let session = self.udp_sessions.entry(packet.assoc_id).or_insert_with(|| {
                spawn_udp_session(packet.assoc_id, mode, self.outbound_tx.clone())
            });
            if session.mode != mode {
                return Err(anyhow::anyhow!("tuic udp relay mode changed").into());
            }
            let _ = session.tx.send(UdpRequest {
                target,
                payload: packet.payload,
            });
        }
        Ok(())
    }
}

impl ApplicationOverQuic for TuicApp {
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
        if self.pending_writes.is_empty() {
            if let Some(write) = self.outbound_rx.recv().await {
                self.pending_writes.push_back(write);
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
                        let data = &buf[..read];
                        if is_unidirectional(stream_id) {
                            self.handle_unidirectional_stream(qconn, stream_id, data, fin)?;
                        } else {
                            self.handle_stream_data(stream_id, data, fin)?;
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
        while let Ok(read) = qconn.dgram_recv(&mut dgram) {
            if read >= 2 && dgram[0] == codec::VERSION && dgram[1] == codec::CMD_HEARTBEAT {
                let _ = qconn.dgram_send(&dgram[..2]);
            } else {
                self.handle_datagram(&dgram[..read])?;
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
                QuicWrite::Data {
                    stream_id,
                    data,
                    fin,
                } => match qconn.stream_send(stream_id, &data, fin) {
                    Ok(sent) if sent == data.len() => {}
                    Ok(sent) => {
                        self.pending_writes.push_front(QuicWrite::Data {
                            stream_id,
                            data: data[sent..].to_vec(),
                            fin,
                        });
                        break;
                    }
                    Err(quiche::Error::Done) => {
                        self.pending_writes.push_front(QuicWrite::Data {
                            stream_id,
                            data,
                            fin,
                        });
                        break;
                    }
                    Err(err) => return Err(Box::new(err)),
                },
                QuicWrite::Datagram(data) => match qconn.dgram_send(&data) {
                    Ok(_) => {}
                    Err(quiche::Error::Done) => {
                        self.pending_writes.push_front(QuicWrite::Datagram(data));
                        break;
                    }
                    Err(err) => return Err(Box::new(err)),
                },
                QuicWrite::UniStream {
                    mut stream_id,
                    data,
                } => {
                    let id = *stream_id.get_or_insert_with(|| {
                        let id = self.next_uni_stream_id;
                        self.next_uni_stream_id += 4;
                        id
                    });
                    match qconn.stream_send(id, &data, true) {
                        Ok(sent) if sent == data.len() => {}
                        Ok(sent) => {
                            self.pending_writes.push_front(QuicWrite::UniStream {
                                stream_id: Some(id),
                                data: data[sent..].to_vec(),
                            });
                            break;
                        }
                        Err(quiche::Error::Done) => {
                            self.pending_writes.push_front(QuicWrite::UniStream {
                                stream_id: Some(id),
                                data,
                            });
                            break;
                        }
                        Err(err) => return Err(Box::new(err)),
                    }
                }
                QuicWrite::Close { stream_id } => {
                    match qconn.stream_send(stream_id, &[], true) {
                        Ok(_) => {}
                        Err(quiche::Error::Done) => {
                            self.pending_writes
                                .push_front(QuicWrite::Close { stream_id });
                            break;
                        }
                        Err(_) => {}
                    }
                    self.streams.remove(&stream_id);
                }
            }
        }
        Ok(())
    }
}

fn spawn_relay(
    router: Arc<Router>,
    session: Session,
    stream_id: u64,
    initial: Vec<u8>,
    mut client_rx: mpsc::UnboundedReceiver<Vec<u8>>,
    quic_tx: mpsc::UnboundedSender<QuicWrite>,
) {
    tokio::spawn(async move {
        let result: anyhow::Result<()> = async {
            let mut outbound = router.dial(&session).await?;
            if !initial.is_empty() {
                outbound.write_all(&initial).await?;
            }

            let mut buf = [0; 16 * 1024];
            loop {
                tokio::select! {
                    biased;

                    maybe_data = client_rx.recv() => {
                        match maybe_data {
                            Some(data) => outbound.write_all(&data).await?,
                            None => break,
                        }
                    }
                    read = outbound.read(&mut buf) => {
                        let read = read?;
                        if read == 0 {
                            break;
                        }
                        let _ = quic_tx.send(QuicWrite::Data {
                            stream_id,
                            data: buf[..read].to_vec(),
                            fin: false,
                        });
                    }
                }
            }
            Ok(())
        }
        .await;

        if let Err(err) = result {
            debug!(%err, "tuic relay failed");
        }
        let _ = quic_tx.send(QuicWrite::Close { stream_id });
    });
}

fn spawn_udp_session(
    assoc_id: u16,
    mode: UdpMode,
    quic_tx: mpsc::UnboundedSender<QuicWrite>,
) -> UdpSession {
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        if let Err(err) = run_udp_session(assoc_id, mode, rx, quic_tx).await {
            debug!(%err, %assoc_id, "tuic udp relay failed");
        }
    });
    UdpSession { tx, mode }
}

async fn run_udp_session(
    assoc_id: u16,
    mode: UdpMode,
    mut rx: mpsc::UnboundedReceiver<UdpRequest>,
    quic_tx: mpsc::UnboundedSender<QuicWrite>,
) -> anyhow::Result<()> {
    let Some(first) = rx.recv().await else {
        return Ok(());
    };
    let socket = UdpSocket::bind(bind_addr_for_target(&first.target)).await?;
    send_udp_request(&socket, first).await?;
    let mut pkt_id = 0u16;
    let mut buf = [0; 64 * 1024];

    loop {
        tokio::select! {
            request = rx.recv() => {
                let Some(request) = request else {
                    break;
                };
                send_udp_request(&socket, request).await?;
            }
            received = socket.recv_from(&mut buf) => {
                let (read, source) = received?;
                let packet = codec::Packet {
                    assoc_id,
                    pkt_id,
                    frag_total: 1,
                    frag_id: 0,
                    target: Some(TargetAddr::Ip(source)),
                    payload: buf[..read].to_vec(),
                };
                let encoded = codec::encode_packet(&packet)?;
                let write = match mode {
                    UdpMode::Native => QuicWrite::Datagram(encoded),
                    UdpMode::Quic => QuicWrite::UniStream {
                        stream_id: None,
                        data: encoded,
                    },
                };
                let _ = quic_tx.send(write);
                pkt_id = pkt_id.wrapping_add(1);
            }
        }
    }
    Ok(())
}

async fn send_udp_request(socket: &UdpSocket, request: UdpRequest) -> anyhow::Result<()> {
    socket
        .send_to(&request.payload, request.target.to_string())
        .await?;
    Ok(())
}

fn bind_addr_for_target(target: &TargetAddr) -> &'static str {
    match target {
        TargetAddr::Ip(addr) if addr.is_ipv6() => "[::]:0",
        _ => "0.0.0.0:0",
    }
}

fn is_unidirectional(stream_id: u64) -> bool {
    stream_id & 0x02 != 0
}
