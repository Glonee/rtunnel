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
    session::{Command, Session},
};

pub async fn run(cfg: InboundConfig, router: Arc<Router>) -> anyhow::Result<()> {
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

    let socket = UdpSocket::bind(cfg.listen).await?;
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
    auth_streams: HashMap<u64, Vec<u8>>,
    streams: HashMap<u64, StreamState>,
    outbound_tx: mpsc::UnboundedSender<QuicWrite>,
    outbound_rx: mpsc::UnboundedReceiver<QuicWrite>,
    pending_writes: VecDeque<QuicWrite>,
    buffer: [u8; 16 * 1024],
}

struct StreamState {
    client_tx: mpsc::UnboundedSender<Vec<u8>>,
}

enum QuicWrite {
    Data {
        stream_id: u64,
        data: Vec<u8>,
        fin: bool,
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
            auth_streams: HashMap::new(),
            streams: HashMap::new(),
            outbound_tx,
            outbound_rx,
            pending_writes: VecDeque::new(),
            buffer: [0; 16 * 1024],
        }
    }

    fn handle_auth(
        &mut self,
        qconn: &mut QuicheConnection,
        stream_id: u64,
        fin: bool,
    ) -> QuicResult<()> {
        if !fin {
            return Ok(());
        }
        let Some(data) = self.auth_streams.remove(&stream_id) else {
            return Ok(());
        };
        let (uuid, presented) = codec::parse_authenticate(&data)?;
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
        Ok(())
    }

    fn handle_stream_data(&mut self, stream_id: u64, data: &[u8], fin: bool) -> QuicResult<()> {
        if !self.authenticated {
            return Err(anyhow::anyhow!("tuic stream before authentication").into());
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
        if fin {
            drop(client_tx.clone());
        }
        self.streams.insert(stream_id, StreamState { client_tx });
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
                            self.auth_streams
                                .entry(stream_id)
                                .or_default()
                                .extend_from_slice(data);
                            self.handle_auth(qconn, stream_id, fin)?;
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

fn is_unidirectional(stream_id: u64) -> bool {
    stream_id & 0x02 != 0
}
