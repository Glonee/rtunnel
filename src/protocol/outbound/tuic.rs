use std::collections::VecDeque;

use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
    sync::mpsc,
};
use tokio_quiche::{
    ApplicationOverQuic, QuicResult,
    quic::{HandshakeInfo, QuicheConnection, connect_with_config},
    quiche,
    settings::{ConnectionParams, Hooks, QuicSettings},
    socket::Socket,
};
use tracing::debug;
use uuid::Uuid;

use crate::{
    config::OutboundConfig,
    protocol::tuic::codec,
    router::Outbound,
    session::{BoxStream, Command, Session, TargetAddr},
};

const CONNECT_STREAM_ID: u64 = 0;
const AUTH_STREAM_ID: u64 = 2;

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

        let mut settings = QuicSettings::default();
        settings.alpn = vec![b"h3".to_vec()];
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
}

struct TuicClientApp {
    uuid: Uuid,
    password: String,
    target: TargetAddr,
    outbound_rx: mpsc::UnboundedReceiver<QuicWrite>,
    stream_tx: mpsc::UnboundedSender<Vec<u8>>,
    pending_writes: VecDeque<QuicWrite>,
    buffer: [u8; 16 * 1024],
}

enum QuicWrite {
    Data(Vec<u8>),
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
        let mut auth = Vec::with_capacity(codec::AUTHENTICATE_LEN);
        auth.push(codec::VERSION);
        auth.push(codec::CMD_AUTHENTICATE);
        auth.extend_from_slice(self.uuid.as_bytes());
        auth.extend_from_slice(&token);
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
                QuicWrite::Close => match qconn.stream_send(CONNECT_STREAM_ID, &[], true) {
                    Ok(_) => {}
                    Err(quiche::Error::Done) => {
                        self.pending_writes.push_front(QuicWrite::Close);
                        break;
                    }
                    Err(_) => {}
                },
            }
        }
        Ok(())
    }
}
