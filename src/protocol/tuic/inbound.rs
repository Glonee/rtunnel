use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    time::{Duration, Instant},
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
    settings::{CertificateKind, ConnectionParams, TlsCertificatePaths},
};
use tracing::{debug, info};
use uuid::Uuid;

use crate::{
    config::{InboundConfig, UserConfig},
    protocol::tuic::{codec, quic_settings},
    router::Router,
    session::{Command, Session, TargetAddr},
    tls,
};

const UDP_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const UDP_SESSION_CLEANUP_INTERVAL: Duration = Duration::from_secs(30);
const CHANNEL_CAPACITY: usize = 32;
const UDP_CHANNEL_CAPACITY: usize = 128;
const AUTHENTICATION_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PRE_AUTH_BYTES: usize = 256 * 1024;
const MAX_PRE_AUTH_ITEMS: usize = 256;

pub async fn run(cfg: InboundConfig, router: Arc<Router>) -> anyhow::Result<()> {
    let socket = UdpSocket::bind(cfg.listen).await?;
    serve(socket, cfg, router).await
}

pub async fn serve(
    socket: UdpSocket,
    cfg: InboundConfig,
    router: Arc<Router>,
) -> anyhow::Result<()> {
    let tls_cfg = cfg
        .tls
        .as_ref()
        .context("tuic inbound requires tls config")?;
    let users = parse_users(cfg.users.as_deref().unwrap_or_default())?;
    let mut settings = quic_settings();
    settings.verify_peer = false;
    settings.disable_client_ip_validation = true;
    let params = ConnectionParams::new_server(
        settings,
        TlsCertificatePaths {
            cert: tls_cfg.certificate_path()?,
            private_key: tls_cfg.private_key_path()?,
            kind: CertificateKind::X509,
        },
        tls::quic_hooks(tls_cfg)?,
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
    authentication_deadline: Instant,
    pre_auth_bytes: usize,
    pre_auth_items: usize,
    username: Option<String>,
    uni_streams: HashMap<u64, Vec<u8>>,
    pending_uni_commands: Vec<Vec<u8>>,
    pending_datagrams: Vec<Vec<u8>>,
    pending_streams: HashMap<u64, PendingStream>,
    streams: HashMap<u64, StreamState>,
    udp_sessions: HashMap<u16, UdpSession>,
    packet_assembler: codec::PacketAssembler,
    next_udp_cleanup: Instant,
    next_uni_stream_id: u64,
    outbound_tx: mpsc::Sender<QuicWrite>,
    outbound_rx: mpsc::Receiver<QuicWrite>,
    pending_writes: VecDeque<QuicWrite>,
}

struct StreamState {
    client_tx: mpsc::Sender<Vec<u8>>,
}

#[derive(Default)]
struct PendingStream {
    data: Vec<u8>,
    fin: bool,
}

struct UdpSession {
    tx: mpsc::Sender<UdpRequest>,
    mode: UdpMode,
    last_used: Instant,
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
    Datagram {
        assoc_id: Option<u16>,
        data: Vec<u8>,
    },
    UniStream {
        assoc_id: Option<u16>,
        stream_id: Option<u64>,
        data: Vec<u8>,
    },
    Close {
        stream_id: u64,
    },
}

impl TuicApp {
    fn new(inbound: String, router: Arc<Router>, users: Vec<TuicUser>) -> Self {
        let (outbound_tx, outbound_rx) = mpsc::channel(CHANNEL_CAPACITY);
        Self {
            inbound,
            router,
            users,
            authenticated: false,
            authentication_deadline: Instant::now() + AUTHENTICATION_TIMEOUT,
            pre_auth_bytes: 0,
            pre_auth_items: 0,
            username: None,
            uni_streams: HashMap::new(),
            pending_uni_commands: Vec::new(),
            pending_datagrams: Vec::new(),
            pending_streams: HashMap::new(),
            streams: HashMap::new(),
            udp_sessions: HashMap::new(),
            packet_assembler: codec::PacketAssembler::default(),
            next_udp_cleanup: Instant::now() + UDP_SESSION_CLEANUP_INTERVAL,
            next_uni_stream_id: 3,
            outbound_tx,
            outbound_rx,
            pending_writes: VecDeque::new(),
        }
    }

    fn check_authentication_deadline(&self) -> QuicResult<()> {
        if !self.authenticated && Instant::now() >= self.authentication_deadline {
            return Err(anyhow::anyhow!("tuic authentication timed out").into());
        }
        Ok(())
    }

    fn reserve_pre_auth(&mut self, bytes: usize, items: usize) -> QuicResult<()> {
        self.check_authentication_deadline()?;
        if self.authenticated {
            return Ok(());
        }
        if bytes > MAX_PRE_AUTH_BYTES - self.pre_auth_bytes
            || items > MAX_PRE_AUTH_ITEMS - self.pre_auth_items
        {
            return Err(anyhow::anyhow!("tuic unauthenticated buffer limit exceeded").into());
        }
        // Count all retained data, including incomplete uni streams and tiny
        // commands/empty streams that could otherwise evade the byte limit.
        self.pre_auth_bytes += bytes;
        self.pre_auth_items += items;
        Ok(())
    }

    fn handle_auth_data(&mut self, qconn: &mut QuicheConnection, data: &[u8]) -> QuicResult<()> {
        self.check_authentication_deadline()?;
        let (uuid, presented) = codec::parse_authenticate(data)?;
        let Some(user) = self.users.iter().find(|user| user.uuid == uuid) else {
            return Err(anyhow::anyhow!("tuic authentication: unknown uuid {uuid}").into());
        };
        let expected = codec::token(qconn.as_mut(), user.uuid, &user.password)?;
        if expected != presented {
            return Err(anyhow::anyhow!("tuic authentication: token mismatch").into());
        }
        self.authenticated = true;
        self.pre_auth_bytes = 0;
        self.pre_auth_items = 0;
        self.username = Some(user.name.clone());
        debug!(username = %user.name, "tuic authenticated");

        let pending_uni_commands = std::mem::take(&mut self.pending_uni_commands);
        for command in pending_uni_commands {
            self.handle_unidirectional_command(qconn, command)?;
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
        self.reserve_pre_auth(
            data.len(),
            usize::from(!self.uni_streams.contains_key(&stream_id)),
        )?;
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
        self.handle_unidirectional_command(qconn, command)
    }

    fn handle_unidirectional_command(
        &mut self,
        qconn: &mut QuicheConnection,
        data: Vec<u8>,
    ) -> QuicResult<()> {
        if data.len() < 2 {
            return Err(anyhow::anyhow!("short tuic command").into());
        }
        match data[1] {
            codec::CMD_AUTHENTICATE => self.handle_auth_data(qconn, &data),
            codec::CMD_PACKET if !self.authenticated => {
                self.pending_uni_commands.push(data);
                Ok(())
            }
            codec::CMD_PACKET => self.handle_packet(&data, UdpMode::Quic),
            codec::CMD_DISSOCIATE if !self.authenticated => {
                self.pending_uni_commands.push(data);
                Ok(())
            }
            codec::CMD_DISSOCIATE => {
                let assoc_id = codec::parse_dissociate(&data)?;
                self.udp_sessions.remove(&assoc_id);
                Ok(())
            }
            other => Err(anyhow::anyhow!("unsupported tuic unidirectional command {other}").into()),
        }
    }

    fn handle_stream_data(&mut self, stream_id: u64, data: &[u8], fin: bool) -> QuicResult<()> {
        if !self.authenticated {
            self.reserve_pre_auth(
                data.len(),
                usize::from(!self.pending_streams.contains_key(&stream_id)),
            )?;
            let pending = self.pending_streams.entry(stream_id).or_default();
            pending.data.extend_from_slice(data);
            pending.fin |= fin;
            return Ok(());
        }

        if let Some(state) = self.streams.get(&stream_id) {
            if !data.is_empty()
                && let Err(err) = state.client_tx.try_send(data.to_vec())
            {
                return Err(
                    anyhow::anyhow!("tuic inbound stream receive backpressure: {err}").into(),
                );
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
        let (client_tx, client_rx) = mpsc::channel(CHANNEL_CAPACITY);
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
        self.check_authentication_deadline()?;
        if data.len() < 2 {
            return Err(anyhow::anyhow!("short tuic datagram").into());
        }
        match data[1] {
            codec::CMD_HEARTBEAT => Ok(()),
            codec::CMD_PACKET if !self.authenticated => {
                self.reserve_pre_auth(data.len(), 1)?;
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
            let now = Instant::now();
            debug!(
                assoc_id = packet.assoc_id,
                mode = ?mode,
                target = %target,
                payload_len = packet.payload.len(),
                "tuic udp packet received"
            );
            let session = self.udp_sessions.entry(packet.assoc_id).or_insert_with(|| {
                spawn_udp_session(
                    self.router.clone(),
                    self.inbound.clone(),
                    packet.assoc_id,
                    mode,
                    self.outbound_tx.clone(),
                    now,
                )
            });
            if session.mode != mode {
                return Err(anyhow::anyhow!("tuic udp relay mode changed").into());
            }
            session.last_used = now;
            if let Err(err) = session.tx.try_send(UdpRequest {
                target,
                payload: packet.payload,
            }) {
                debug!(%err, "dropped tuic udp request due to relay backpressure");
            }
        }
        Ok(())
    }

    fn maybe_cleanup_udp_state(&mut self) {
        let now = Instant::now();
        if now < self.next_udp_cleanup {
            return;
        }
        self.evict_idle_udp_sessions(now);
        let evicted_fragments = self
            .packet_assembler
            .evict_idle(now, codec::FRAGMENT_IDLE_TIMEOUT);
        if evicted_fragments > 0 {
            debug!(evicted_fragments, "tuic evicted idle packet fragments");
        }
        self.next_udp_cleanup = now + UDP_SESSION_CLEANUP_INTERVAL;
    }

    fn evict_idle_udp_sessions(&mut self, now: Instant) {
        self.udp_sessions.retain(|assoc_id, session| {
            let keep = now.saturating_duration_since(session.last_used) < UDP_SESSION_IDLE_TIMEOUT;
            if !keep {
                debug!(assoc_id, "tuic udp association idle timeout");
            }
            keep
        });
    }

    fn touch_udp_session(&mut self, assoc_id: u16) {
        if let Some(session) = self.udp_sessions.get_mut(&assoc_id) {
            session.last_used = Instant::now();
        }
    }
}

impl ApplicationOverQuic for TuicApp {
    fn on_conn_established(
        &mut self,
        _qconn: &mut QuicheConnection,
        _handshake_info: &HandshakeInfo,
    ) -> QuicResult<()> {
        self.authentication_deadline = Instant::now() + AUTHENTICATION_TIMEOUT;
        Ok(())
    }

    fn should_act(&self) -> bool {
        true
    }

    async fn wait_for_data(&mut self, _qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.check_authentication_deadline()?;
        self.maybe_cleanup_udp_state();
        let wake_at = if self.authenticated {
            self.next_udp_cleanup
        } else {
            self.next_udp_cleanup.min(self.authentication_deadline)
        };
        if self.pending_writes.is_empty() {
            tokio::select! {
                write = self.outbound_rx.recv() => {
                    if let Some(write) = write {
                        self.pending_writes.push_back(write);
                    }
                }
                _ = tokio::time::sleep_until(tokio::time::Instant::from_std(wake_at)) => {}
            }
        }
        self.check_authentication_deadline()
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        self.check_authentication_deadline()?;
        self.maybe_cleanup_udp_state();
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
        self.check_authentication_deadline()?;
        self.maybe_cleanup_udp_state();
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
                QuicWrite::Datagram { assoc_id, data } => {
                    if let Some(assoc_id) = assoc_id {
                        self.touch_udp_session(assoc_id);
                    }
                    match qconn.dgram_send(&data) {
                        Ok(_) => {}
                        Err(quiche::Error::Done) => {
                            self.pending_writes
                                .push_front(QuicWrite::Datagram { assoc_id, data });
                            break;
                        }
                        Err(err) => return Err(Box::new(err)),
                    }
                }
                QuicWrite::UniStream {
                    assoc_id,
                    mut stream_id,
                    data,
                } => {
                    if let Some(assoc_id) = assoc_id {
                        self.touch_udp_session(assoc_id);
                    }
                    let id = *stream_id.get_or_insert_with(|| {
                        let id = self.next_uni_stream_id;
                        self.next_uni_stream_id += 4;
                        id
                    });
                    match qconn.stream_send(id, &data, true) {
                        Ok(sent) if sent == data.len() => {}
                        Ok(sent) => {
                            self.pending_writes.push_front(QuicWrite::UniStream {
                                assoc_id,
                                stream_id: Some(id),
                                data: data[sent..].to_vec(),
                            });
                            break;
                        }
                        Err(quiche::Error::Done) => {
                            self.pending_writes.push_front(QuicWrite::UniStream {
                                assoc_id,
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
                        Err(quiche::Error::Done) => {}
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
    mut client_rx: mpsc::Receiver<Vec<u8>>,
    quic_tx: mpsc::Sender<QuicWrite>,
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
                        quic_tx
                            .send(QuicWrite::Data {
                                stream_id,
                                data: buf[..read].to_vec(),
                                fin: false,
                            })
                            .await
                            .map_err(|_| anyhow::anyhow!("tuic connection closed"))?;
                    }
                }
            }
            Ok(())
        }
        .await;

        if let Err(err) = result {
            debug!(%err, "tuic relay failed");
        }
        let _ = quic_tx.send(QuicWrite::Close { stream_id }).await;
    });
}

fn spawn_udp_session(
    router: Arc<Router>,
    inbound: String,
    assoc_id: u16,
    mode: UdpMode,
    quic_tx: mpsc::Sender<QuicWrite>,
    now: Instant,
) -> UdpSession {
    let (tx, rx) = mpsc::channel(UDP_CHANNEL_CAPACITY);
    tokio::spawn(async move {
        if let Err(err) = run_udp_session(router, inbound, assoc_id, mode, rx, quic_tx).await {
            debug!(%err, %assoc_id, "tuic udp relay failed");
        }
    });
    UdpSession {
        tx,
        mode,
        last_used: now,
    }
}

async fn run_udp_session(
    router: Arc<Router>,
    inbound: String,
    assoc_id: u16,
    mode: UdpMode,
    mut rx: mpsc::Receiver<UdpRequest>,
    quic_tx: mpsc::Sender<QuicWrite>,
) -> anyhow::Result<()> {
    let Some(first) = rx.recv().await else {
        return Ok(());
    };
    let session = Session {
        inbound,
        command: Command::UdpAssociate,
        target: first.target.clone(),
    };
    let outbound = router.dial_udp(&session).await?;
    outbound.send_to(&first.target, &first.payload).await?;
    let mut pkt_id = 0u16;

    loop {
        tokio::select! {
            request = rx.recv() => {
                let Some(request) = request else {
                    break;
                };
                outbound.send_to(&request.target, &request.payload).await?;
            }
            received = outbound.recv_from() => {
                let (source, payload) = received?;
                debug!(
                    assoc_id,
                    mode = ?mode,
                    source = %source,
                    payload_len = payload.len(),
                    "tuic udp packet sending response"
                );
                let packet = codec::Packet {
                    assoc_id,
                    pkt_id,
                    frag_total: 1,
                    frag_id: 0,
                    target: Some(source),
                    payload,
                };
                let encoded = codec::encode_packet(&packet)?;
                let write = match mode {
                    UdpMode::Native => QuicWrite::Datagram {
                        assoc_id: Some(assoc_id),
                        data: encoded,
                    },
                    UdpMode::Quic => QuicWrite::UniStream {
                        assoc_id: Some(assoc_id),
                        stream_id: None,
                        data: encoded,
                    },
                };
                if quic_tx.send(write).await.is_err() {
                    break;
                }
                pkt_id = pkt_id.wrapping_add(1);
            }
        }
    }
    Ok(())
}

fn is_unidirectional(stream_id: u64) -> bool {
    stream_id & 0x02 != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    async fn test_app() -> TuicApp {
        let cfg = toml::from_str::<Config>("").unwrap();
        TuicApp::new(
            "tuic-in".into(),
            Arc::new(Router::new(cfg).await.unwrap()),
            vec![],
        )
    }

    fn test_connection() -> QuicheConnection {
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
        quiche::connect_with_buffer_factory(
            None,
            &quiche::ConnectionId::from_ref(&[1; 16]),
            "127.0.0.1:10000".parse().unwrap(),
            "127.0.0.1:10001".parse().unwrap(),
            &mut config,
        )
        .unwrap()
    }

    #[tokio::test]
    async fn rejects_excessive_unauthenticated_tcp_data_before_buffering() {
        let mut app = test_app().await;
        let chunk = [0; 16 * 1024];
        for _ in 0..MAX_PRE_AUTH_BYTES / chunk.len() {
            app.handle_stream_data(0, &chunk, false).unwrap();
        }
        assert!(app.handle_stream_data(0, &[0], false).is_err());
        assert_eq!(app.pending_streams[&0].data.len(), MAX_PRE_AUTH_BYTES);
    }

    #[tokio::test]
    async fn bounds_incomplete_unauthenticated_uni_streams() {
        let mut app = test_app().await;
        let mut qconn = test_connection();
        app.handle_unidirectional_stream(&mut qconn, 2, &vec![0; MAX_PRE_AUTH_BYTES], false)
            .unwrap();
        assert!(
            app.handle_unidirectional_stream(&mut qconn, 2, &[0], false)
                .is_err()
        );
        assert_eq!(app.uni_streams[&2].len(), MAX_PRE_AUTH_BYTES);
    }

    #[tokio::test]
    async fn shares_pre_auth_byte_limit_across_tcp_uni_commands_and_datagrams() {
        let mut app = test_app().await;
        let mut qconn = test_connection();
        app.handle_stream_data(0, &vec![0; MAX_PRE_AUTH_BYTES / 2], false)
            .unwrap();
        let mut command = vec![0; MAX_PRE_AUTH_BYTES / 2];
        command[..2].copy_from_slice(&[codec::VERSION, codec::CMD_PACKET]);
        app.handle_unidirectional_stream(&mut qconn, 2, &command, true)
            .unwrap();
        assert_eq!(app.pending_uni_commands.len(), 1);
        assert!(app.uni_streams.is_empty());
        // Completing a uni stream must not release its budget while the
        // command is still retained for authentication.
        assert!(
            app.handle_datagram(&[codec::VERSION, codec::CMD_PACKET])
                .is_err()
        );
        assert!(app.pending_datagrams.is_empty());
    }

    #[tokio::test]
    async fn bounds_empty_streams_and_shares_item_limit_with_datagrams() {
        let mut app = test_app().await;
        let mut qconn = test_connection();
        for id in 0..MAX_PRE_AUTH_ITEMS as u64 {
            app.handle_stream_data(id * 4, &[], true).unwrap();
        }
        assert!(
            app.handle_unidirectional_stream(&mut qconn, 2, &[], false)
                .is_err()
        );
        assert!(
            app.handle_datagram(&[codec::VERSION, codec::CMD_PACKET])
                .is_err()
        );
        assert_eq!(app.pending_streams.len(), MAX_PRE_AUTH_ITEMS);
        assert!(app.uni_streams.is_empty());
    }

    #[tokio::test]
    async fn bounds_many_small_unauthenticated_datagrams() {
        let mut app = test_app().await;
        for _ in 0..MAX_PRE_AUTH_ITEMS {
            app.handle_datagram(&[codec::VERSION, codec::CMD_PACKET])
                .unwrap();
        }
        assert!(
            app.handle_datagram(&[codec::VERSION, codec::CMD_PACKET])
                .is_err()
        );
        assert_eq!(app.pending_datagrams.len(), MAX_PRE_AUTH_ITEMS);
    }

    #[tokio::test]
    async fn authentication_deadline_wakes_idle_connections_and_rejects_active_ones() {
        let mut app = test_app().await;
        let mut qconn = test_connection();
        app.authentication_deadline = Instant::now() + Duration::from_millis(20);
        let result = tokio::time::timeout(Duration::from_secs(1), app.wait_for_data(&mut qconn))
            .await
            .unwrap();
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("authentication timed out")
        );
        assert!(app.process_reads(&mut qconn).is_err());
        assert!(app.process_writes(&mut qconn).is_err());
        assert!(
            app.handle_datagram(&[codec::VERSION, codec::CMD_HEARTBEAT])
                .is_err()
        );
        assert!(app.handle_stream_data(0, b"late", false).is_err());
        assert!(app.pending_streams.is_empty());
    }

    #[tokio::test]
    async fn authenticated_connections_are_not_subject_to_authentication_deadline() {
        let mut app = test_app().await;
        let mut qconn = test_connection();
        app.authenticated = true;
        app.authentication_deadline = Instant::now() - Duration::from_secs(1);
        app.handle_datagram(&[codec::VERSION, codec::CMD_HEARTBEAT])
            .unwrap();
        app.process_reads(&mut qconn).unwrap();
        app.process_writes(&mut qconn).unwrap();
    }

    #[tokio::test]
    async fn udp_route_failure_never_falls_back_to_direct() {
        // A matching rule must fail closed, even with a working direct default.
        let cfg: Config = toml::from_str(
            r#"
            [[outbounds]]
            tag = "direct"
            protocol = "direct"
            [routing]
            default = "direct"
            [[routing.rules]]
            inbound = "tuic-in"
            outbound = "missing"
        "#,
        )
        .unwrap();
        let router = Arc::new(Router::new(cfg).await.unwrap());
        for mode in [UdpMode::Native, UdpMode::Quic] {
            let (tx, rx) = mpsc::channel(1);
            let (quic_tx, _quic_rx) = mpsc::channel(1);
            tx.send(UdpRequest {
                target: "127.0.0.1:9"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
                    .into(),
                payload: b"must not escape directly".to_vec(),
            })
            .await
            .unwrap();
            drop(tx);
            let result =
                run_udp_session(router.clone(), "tuic-in".into(), 1, mode, rx, quic_tx).await;
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("unknown outbound missing")
            );
        }
    }
}
