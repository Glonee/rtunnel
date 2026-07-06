use std::{
    collections::{HashMap, VecDeque},
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose,
};
use rtunnel::{
    config::{
        Config, InboundConfig, OutboundConfig, Protocol, RoutingConfig, TlsServerConfig, UserConfig,
    },
    protocol::{
        anytls::{codec as anytls_codec, inbound as anytls_inbound, outbound::AnytlsOutbound},
        socks5::{inbound as socks5_inbound, outbound::Socks5Outbound},
        tuic::{codec, inbound as tuic_inbound, outbound::TuicOutbound},
    },
    router::{Outbound, Router},
    session::{Command, Session, TargetAddr},
    tls,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
    time::timeout,
};
use tokio_boring::{SslStream, SslStreamBuilder, accept};
use tokio_quiche::{
    ApplicationOverQuic, QuicResult,
    quic::{HandshakeInfo, QuicheConnection, connect_with_config},
    quiche,
    settings::{ConnectionParams, QuicSettings},
    socket::Socket,
};
use uuid::Uuid;

const TUIC_UUID: &str = "00000000-0000-0000-0000-000000000001";
const TUIC_AUTH_STREAM_ID: u64 = 2;

#[tokio::test]
async fn socks5_outbound_reaches_socks5_inbound() -> anyhow::Result<()> {
    let echo_addr = spawn_echo_server().await?;
    let inbound_addr = spawn_socks5_inbound(None).await?;
    let client = Socks5Outbound::new(OutboundConfig {
        tag: "client".to_owned(),
        protocol: Protocol::Socks5,
        server: Some(inbound_addr.into()),
        server_name: None,
        insecure: false,
        ca_certificate: None,
        username: None,
        password: None,
        uuid: None,
    })?;

    assert_echo_roundtrip(client, echo_addr).await
}

#[tokio::test]
async fn socks5_outbound_authenticates_to_socks5_inbound() -> anyhow::Result<()> {
    let echo_addr = spawn_echo_server().await?;
    let inbound_addr = spawn_socks5_inbound(Some(("user", "pass"))).await?;
    let client = Socks5Outbound::new(OutboundConfig {
        tag: "client".to_owned(),
        protocol: Protocol::Socks5,
        server: Some(inbound_addr.into()),
        server_name: None,
        insecure: false,
        ca_certificate: None,
        username: Some("user".to_owned()),
        password: Some("pass".to_owned()),
        uuid: None,
    })?;

    assert_echo_roundtrip(client, echo_addr).await
}

#[tokio::test]
async fn socks5_udp_reaches_socks5_inbound() -> anyhow::Result<()> {
    let echo_addr = spawn_udp_echo_server().await?;
    let inbound_addr = spawn_socks5_inbound(None).await?;
    let client = Socks5Outbound::new(OutboundConfig {
        tag: "client".to_owned(),
        protocol: Protocol::Socks5,
        server: Some(inbound_addr.into()),
        server_name: None,
        insecure: false,
        ca_certificate: None,
        username: None,
        password: None,
        uuid: None,
    })?;

    assert_udp_roundtrip(client, echo_addr).await
}

#[tokio::test]
async fn anytls_outbound_reaches_anytls_inbound() -> anyhow::Result<()> {
    let echo_addr = spawn_echo_server().await?;
    let (inbound_addr, ca_certificate) = spawn_anytls_inbound().await?;
    let client = AnytlsOutbound::new(OutboundConfig {
        tag: "client".to_owned(),
        protocol: Protocol::Anytls,
        server: Some(inbound_addr.into()),
        server_name: Some("localhost".to_owned()),
        insecure: false,
        ca_certificate: Some(ca_certificate),
        username: None,
        password: Some("secret".to_owned()),
        uuid: None,
    })?;

    assert_echo_roundtrip(client, echo_addr).await
}

#[tokio::test]
async fn anytls_udp_reaches_anytls_inbound() -> anyhow::Result<()> {
    let echo_addr = spawn_udp_echo_server().await?;
    let (inbound_addr, ca_certificate) = spawn_anytls_inbound().await?;
    let client = AnytlsOutbound::new(OutboundConfig {
        tag: "client".to_owned(),
        protocol: Protocol::Anytls,
        server: Some(inbound_addr.into()),
        server_name: Some("localhost".to_owned()),
        insecure: false,
        ca_certificate: Some(ca_certificate),
        username: None,
        password: Some("secret".to_owned()),
        uuid: None,
    })?;

    assert_udp_roundtrip(client, echo_addr).await
}

#[tokio::test]
async fn anytls_inbound_requires_settings_before_stream() -> anyhow::Result<()> {
    let (inbound_addr, ca_certificate) = spawn_anytls_inbound().await?;
    let mut stream = connect_anytls_session(inbound_addr, &ca_certificate).await?;

    anytls_codec::write_frame(&mut stream, anytls_codec::CMD_PSH, 1, &[]).await?;
    let alert = timeout(
        Duration::from_secs(5),
        anytls_codec::read_frame(&mut stream),
    )
    .await??;

    assert_eq!(alert.command, anytls_codec::CMD_ALERT);
    assert!(String::from_utf8_lossy(&alert.data).contains("cmdSettings"));
    Ok(())
}

#[tokio::test]
async fn anytls_inbound_sends_padding_scheme_update() -> anyhow::Result<()> {
    let scheme = vec![
        "stop=2".to_owned(),
        "0=12-12".to_owned(),
        "1=64-64".to_owned(),
    ];
    let (inbound_addr, ca_certificate) = spawn_anytls_inbound_with_padding(scheme.clone()).await?;
    let mut stream = connect_anytls_session(inbound_addr, &ca_certificate).await?;

    anytls_codec::write_frame(
        &mut stream,
        anytls_codec::CMD_SETTINGS,
        0,
        &anytls_codec::client_settings(),
    )
    .await?;

    let settings = timeout(
        Duration::from_secs(5),
        anytls_codec::read_frame(&mut stream),
    )
    .await??;
    let update = timeout(
        Duration::from_secs(5),
        anytls_codec::read_frame(&mut stream),
    )
    .await??;

    assert_eq!(settings.command, anytls_codec::CMD_SERVER_SETTINGS);
    assert_eq!(settings.data, anytls_codec::settings());
    assert_eq!(update.command, anytls_codec::CMD_UPDATE_PADDING_SCHEME);
    assert_eq!(update.data, anytls_codec::padding_scheme_payload(&scheme));
    Ok(())
}

#[tokio::test]
async fn anytls_outbound_reuses_tls_session_for_multiple_streams() -> anyhow::Result<()> {
    let (server, ca_certificate, mut opened_streams) = spawn_anytls_reuse_probe_server().await?;
    let client = AnytlsOutbound::new(OutboundConfig {
        tag: "client".to_owned(),
        protocol: Protocol::Anytls,
        server: Some(server.into()),
        server_name: Some("localhost".to_owned()),
        insecure: false,
        ca_certificate: Some(ca_certificate),
        username: None,
        password: Some("secret".to_owned()),
        uuid: None,
    })?;
    let session = Session {
        inbound: "test-client".to_owned(),
        command: Command::Connect,
        target: TargetAddr::Ip(localhost(9)),
    };

    let mut first = timeout(Duration::from_secs(5), client.dial(&session)).await??;
    assert_eq!(
        timeout(Duration::from_secs(5), opened_streams.recv())
            .await?
            .expect("reuse probe closed"),
        1
    );
    let mut first_reply = [0; 2];
    timeout(Duration::from_secs(5), first.read_exact(&mut first_reply)).await??;
    assert_eq!(&first_reply, b"ok");

    let mut second = timeout(Duration::from_secs(5), client.dial(&session)).await??;
    assert_eq!(
        timeout(Duration::from_secs(5), opened_streams.recv())
            .await?
            .expect("reuse probe closed"),
        2
    );
    let mut second_reply = [0; 2];
    timeout(Duration::from_secs(5), second.read_exact(&mut second_reply)).await??;
    assert_eq!(&second_reply, b"ok");

    Ok(())
}

#[tokio::test]
async fn tuic_outbound_reaches_tuic_inbound() -> anyhow::Result<()> {
    let echo_addr = spawn_echo_server().await?;
    let (inbound_addr, ca_certificate) = spawn_tuic_inbound().await?;
    let client = TuicOutbound::new(OutboundConfig {
        tag: "client".to_owned(),
        protocol: Protocol::Tuic,
        server: Some(inbound_addr.into()),
        server_name: Some("localhost".to_owned()),
        insecure: false,
        ca_certificate: Some(ca_certificate),
        username: None,
        password: Some("secret".to_owned()),
        uuid: Some(TUIC_UUID.to_owned()),
    })?;

    assert_echo_roundtrip(client, echo_addr).await
}

#[tokio::test]
async fn tuic_udp_outbound_reaches_tuic_inbound() -> anyhow::Result<()> {
    let echo_addr = spawn_udp_echo_server().await?;
    let (inbound_addr, ca_certificate) = spawn_tuic_inbound().await?;
    let client = TuicOutbound::new(OutboundConfig {
        tag: "client".to_owned(),
        protocol: Protocol::Tuic,
        server: Some(inbound_addr.into()),
        server_name: Some("localhost".to_owned()),
        insecure: false,
        ca_certificate: Some(ca_certificate),
        username: None,
        password: Some("secret".to_owned()),
        uuid: Some(TUIC_UUID.to_owned()),
    })?;

    assert_udp_roundtrip(client, echo_addr).await
}

#[tokio::test]
async fn tuic_native_udp_reaches_udp_echo() -> anyhow::Result<()> {
    let echo_addr = spawn_udp_echo_server().await?;
    let (inbound_addr, ca_certificate) = spawn_tuic_inbound().await?;

    let received = tuic_udp_roundtrip(
        inbound_addr,
        echo_addr,
        &ca_certificate,
        TuicTestUdpMode::Native,
    )
    .await?;

    assert_eq!(received, b"ping");
    Ok(())
}

#[tokio::test]
async fn tuic_quic_udp_reaches_udp_echo() -> anyhow::Result<()> {
    let echo_addr = spawn_udp_echo_server().await?;
    let (inbound_addr, ca_certificate) = spawn_tuic_inbound().await?;

    let received = tuic_udp_roundtrip(
        inbound_addr,
        echo_addr,
        &ca_certificate,
        TuicTestUdpMode::Quic,
    )
    .await?;

    assert_eq!(received, b"ping");
    Ok(())
}

async fn assert_echo_roundtrip<C>(client: C, echo_addr: SocketAddr) -> anyhow::Result<()>
where
    C: Outbound,
{
    let session = Session {
        inbound: "test-client".to_owned(),
        command: Command::Connect,
        target: TargetAddr::Ip(echo_addr),
    };
    let mut stream = timeout(Duration::from_secs(5), client.dial(&session)).await??;

    timeout(Duration::from_secs(5), stream.write_all(b"ping")).await??;
    let mut received = [0; 4];
    timeout(Duration::from_secs(5), stream.read_exact(&mut received)).await??;

    assert_eq!(&received, b"ping");
    Ok(())
}

async fn assert_udp_roundtrip<C>(client: C, echo_addr: SocketAddr) -> anyhow::Result<()>
where
    C: Outbound,
{
    let session = Session {
        inbound: "test-client".to_owned(),
        command: Command::UdpAssociate,
        target: TargetAddr::Ip(echo_addr),
    };
    let udp = timeout(Duration::from_secs(5), client.dial_udp(&session)).await??;

    timeout(
        Duration::from_secs(5),
        udp.send_to(&TargetAddr::Ip(echo_addr), b"ping"),
    )
    .await??;
    let (source, received) = timeout(Duration::from_secs(5), udp.recv_from()).await??;

    assert_eq!(source, TargetAddr::Ip(echo_addr));
    assert_eq!(received, b"ping");
    Ok(())
}

async fn spawn_socks5_inbound(credentials: Option<(&str, &str)>) -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind(localhost(0)).await?;
    let addr = listener.local_addr()?;
    let inbound_cfg = InboundConfig {
        tag: "socks-in".to_owned(),
        listen: addr,
        protocol: Protocol::Socks5,
        users: credentials.map(|(username, password)| {
            vec![UserConfig {
                username: username.to_owned(),
                uuid: None,
                password: password.to_owned(),
            }]
        }),
        padding_scheme: Vec::new(),
        tls: None,
    };
    let router = Arc::new(Router::new(Config {
        log_level: None,
        acme: None,
        inbounds: vec![inbound_cfg.clone()],
        outbounds: vec![OutboundConfig {
            tag: "direct".to_owned(),
            protocol: Protocol::Direct,
            server: None,
            server_name: None,
            insecure: false,
            ca_certificate: None,
            username: None,
            password: None,
            uuid: None,
        }],
        routing: RoutingConfig {
            default: Some("direct".to_owned()),
            rules: Vec::new(),
        },
    })?);
    tokio::spawn(socks5_inbound::serve(listener, inbound_cfg, router));
    Ok(addr)
}

async fn spawn_anytls_inbound() -> anyhow::Result<(SocketAddr, String)> {
    spawn_anytls_inbound_with_padding(Vec::new()).await
}

async fn spawn_anytls_inbound_with_padding(
    padding_scheme: Vec<String>,
) -> anyhow::Result<(SocketAddr, String)> {
    let listener = TcpListener::bind(localhost(0)).await?;
    let addr = listener.local_addr()?;
    let tls = write_test_tls_files()?;
    let ca_certificate = tls.ca_certificate.clone();
    let inbound_cfg = InboundConfig {
        tag: "anytls-in".to_owned(),
        listen: addr,
        protocol: Protocol::Anytls,
        users: Some(vec![UserConfig {
            username: "user".to_owned(),
            uuid: None,
            password: "secret".to_owned(),
        }]),
        padding_scheme,
        tls: Some(tls.server),
    };
    let router = Arc::new(Router::new(Config {
        log_level: None,
        acme: None,
        inbounds: vec![inbound_cfg.clone()],
        outbounds: vec![OutboundConfig {
            tag: "direct".to_owned(),
            protocol: Protocol::Direct,
            server: None,
            server_name: None,
            insecure: false,
            ca_certificate: None,
            username: None,
            password: None,
            uuid: None,
        }],
        routing: RoutingConfig {
            default: Some("direct".to_owned()),
            rules: Vec::new(),
        },
    })?);
    tokio::spawn(anytls_inbound::serve(listener, inbound_cfg, router));
    Ok((addr, ca_certificate))
}

async fn connect_anytls_session(
    server: SocketAddr,
    ca_certificate: &str,
) -> anyhow::Result<SslStream<TcpStream>> {
    let tcp = TcpStream::connect(server).await?;
    let connector = tls::chrome_like_connector(false, Some(ca_certificate))?;
    let mut ssl = connector.configure()?.into_ssl("localhost")?;
    tls::configure_chrome_like_ssl(&mut ssl)?;
    let mut stream = SslStreamBuilder::new(ssl, tcp).connect().await?;
    anytls_codec::write_client_hello(&mut stream, "secret").await?;
    Ok(stream)
}

async fn spawn_anytls_reuse_probe_server()
-> anyhow::Result<(SocketAddr, String, mpsc::UnboundedReceiver<u32>)> {
    let listener = TcpListener::bind(localhost(0)).await?;
    let addr = listener.local_addr()?;
    let tls_cfg = write_test_tls_files()?;
    let ca_certificate = tls_cfg.ca_certificate.clone();
    let acceptor = Arc::new(tls::server_acceptor(&tls_cfg.server)?);
    let (opened_tx, opened_rx) = mpsc::unbounded_channel();

    tokio::spawn(async move {
        let Ok((stream, _peer)) = listener.accept().await else {
            return;
        };
        let Ok(mut stream) = accept(&acceptor, stream).await else {
            return;
        };
        let users = [UserConfig {
            username: "user".to_owned(),
            uuid: None,
            password: "secret".to_owned(),
        }];
        if anytls_codec::read_client_hello(&mut stream, &users)
            .await
            .is_err()
        {
            return;
        }

        let mut opened = 0;
        loop {
            let Ok(frame) = anytls_codec::read_frame(&mut stream).await else {
                return;
            };
            match frame.command {
                anytls_codec::CMD_SETTINGS => {
                    let _ = anytls_codec::write_frame(
                        &mut stream,
                        anytls_codec::CMD_SERVER_SETTINGS,
                        0,
                        anytls_codec::settings(),
                    )
                    .await;
                }
                anytls_codec::CMD_SYN => {}
                anytls_codec::CMD_PSH => {
                    if anytls_codec::decode_socksaddr(&frame.data).is_ok() {
                        opened += 1;
                        let _ = opened_tx.send(frame.stream_id);
                        let _ = anytls_codec::write_frame(
                            &mut stream,
                            anytls_codec::CMD_SYNACK,
                            frame.stream_id,
                            &[],
                        )
                        .await;
                        let _ = anytls_codec::write_frame(
                            &mut stream,
                            anytls_codec::CMD_PSH,
                            frame.stream_id,
                            b"ok",
                        )
                        .await;
                        if opened == 2 {
                            return;
                        }
                    }
                }
                _ => {}
            }
        }
    });

    Ok((addr, ca_certificate, opened_rx))
}

async fn spawn_tuic_inbound() -> anyhow::Result<(SocketAddr, String)> {
    let socket = UdpSocket::bind(localhost(0)).await?;
    let addr = socket.local_addr()?;
    let tls = write_test_tls_files()?;
    let ca_certificate = tls.ca_certificate.clone();
    let inbound_cfg = InboundConfig {
        tag: "tuic-in".to_owned(),
        listen: addr,
        protocol: Protocol::Tuic,
        users: Some(vec![UserConfig {
            username: "user".to_owned(),
            uuid: Some(TUIC_UUID.to_owned()),
            password: "secret".to_owned(),
        }]),
        padding_scheme: Vec::new(),
        tls: Some(tls.server),
    };
    let router = Arc::new(Router::new(Config {
        log_level: None,
        acme: None,
        inbounds: vec![inbound_cfg.clone()],
        outbounds: vec![OutboundConfig {
            tag: "direct".to_owned(),
            protocol: Protocol::Direct,
            server: None,
            server_name: None,
            insecure: false,
            ca_certificate: None,
            username: None,
            password: None,
            uuid: None,
        }],
        routing: RoutingConfig {
            default: Some("direct".to_owned()),
            rules: Vec::new(),
        },
    })?);
    tokio::spawn(tuic_inbound::serve(socket, inbound_cfg, router));
    Ok((addr, ca_certificate))
}

async fn spawn_echo_server() -> anyhow::Result<SocketAddr> {
    let listener = TcpListener::bind(localhost(0)).await?;
    let addr = listener.local_addr()?;
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _peer)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buf = [0; 1024];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(read) => {
                            if stream.write_all(&buf[..read]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    Ok(addr)
}

async fn spawn_udp_echo_server() -> anyhow::Result<SocketAddr> {
    let socket = UdpSocket::bind(localhost(0)).await?;
    let addr = socket.local_addr()?;
    tokio::spawn(async move {
        let mut buf = [0; 2048];
        loop {
            let Ok((read, peer)) = socket.recv_from(&mut buf).await else {
                break;
            };
            if socket.send_to(&buf[..read], peer).await.is_err() {
                break;
            }
        }
    });
    Ok(addr)
}

async fn tuic_udp_roundtrip(
    server: SocketAddr,
    target: SocketAddr,
    ca_certificate: &str,
    mode: TuicTestUdpMode,
) -> anyhow::Result<Vec<u8>> {
    let socket = UdpSocket::bind(localhost(0)).await?;
    socket.connect(server).await?;
    let socket = Socket::try_from(socket)?;

    let mut settings = QuicSettings::default();
    settings.alpn = vec![b"h3".to_vec()];
    settings.verify_peer = true;
    let params = ConnectionParams::new_client(
        settings,
        None,
        tls::chrome_quic_client_hooks(Some(ca_certificate)),
    );

    let (response_tx, mut response_rx) = mpsc::unbounded_channel();
    let app = TuicUdpClientApp::new(TargetAddr::Ip(target), mode, response_tx);
    connect_with_config(socket, Some("localhost"), &params, app)
        .await
        .map_err(|err| anyhow::anyhow!("tuic udp test handshake failed: {err}"))?;

    timeout(Duration::from_secs(5), response_rx.recv())
        .await?
        .ok_or_else(|| anyhow::anyhow!("tuic udp response channel closed"))
}

#[derive(Clone, Copy)]
enum TuicTestUdpMode {
    Native,
    Quic,
}

enum TuicTestUdpWrite {
    Datagram(Vec<u8>),
    UniStream { stream_id: u64, data: Vec<u8> },
}

struct TuicUdpClientApp {
    uuid: Uuid,
    password: String,
    target: TargetAddr,
    mode: TuicTestUdpMode,
    response_tx: mpsc::UnboundedSender<Vec<u8>>,
    pending_writes: VecDeque<TuicTestUdpWrite>,
    response_streams: HashMap<u64, Vec<u8>>,
    buffer: [u8; 16 * 1024],
}

impl TuicUdpClientApp {
    fn new(
        target: TargetAddr,
        mode: TuicTestUdpMode,
        response_tx: mpsc::UnboundedSender<Vec<u8>>,
    ) -> Self {
        Self {
            uuid: Uuid::parse_str(TUIC_UUID).expect("static uuid is valid"),
            password: "secret".to_owned(),
            target,
            mode,
            response_tx,
            pending_writes: VecDeque::new(),
            response_streams: HashMap::new(),
            buffer: [0; 16 * 1024],
        }
    }

    fn send_or_queue(
        &mut self,
        qconn: &mut QuicheConnection,
        write: TuicTestUdpWrite,
    ) -> QuicResult<()> {
        match self.try_send(qconn, write)? {
            Some(write) => self.pending_writes.push_back(write),
            None => {}
        }
        Ok(())
    }

    fn try_send(
        &mut self,
        qconn: &mut QuicheConnection,
        write: TuicTestUdpWrite,
    ) -> QuicResult<Option<TuicTestUdpWrite>> {
        match write {
            TuicTestUdpWrite::Datagram(data) => match qconn.dgram_send(&data) {
                Ok(_) => Ok(None),
                Err(quiche::Error::Done) => Ok(Some(TuicTestUdpWrite::Datagram(data))),
                Err(err) => Err(Box::new(err)),
            },
            TuicTestUdpWrite::UniStream { stream_id, data } => {
                match qconn.stream_send(stream_id, &data, true) {
                    Ok(sent) if sent == data.len() => Ok(None),
                    Ok(sent) => Ok(Some(TuicTestUdpWrite::UniStream {
                        stream_id,
                        data: data[sent..].to_vec(),
                    })),
                    Err(quiche::Error::Done) => {
                        Ok(Some(TuicTestUdpWrite::UniStream { stream_id, data }))
                    }
                    Err(err) => Err(Box::new(err)),
                }
            }
        }
    }

    fn handle_packet(&self, data: &[u8]) {
        if let Ok(packet) = codec::parse_packet(data) {
            let _ = self.response_tx.send(packet.payload);
        }
    }
}

impl ApplicationOverQuic for TuicUdpClientApp {
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
        qconn.stream_send(TUIC_AUTH_STREAM_ID, &auth, true)?;

        let packet = codec::Packet {
            assoc_id: 1,
            pkt_id: 1,
            frag_total: 1,
            frag_id: 0,
            target: Some(self.target.clone()),
            payload: b"ping".to_vec(),
        };
        let encoded = codec::encode_packet(&packet)?;
        let write = match self.mode {
            TuicTestUdpMode::Native => TuicTestUdpWrite::Datagram(encoded),
            TuicTestUdpMode::Quic => TuicTestUdpWrite::UniStream {
                stream_id: 6,
                data: encoded,
            },
        };
        self.send_or_queue(qconn, write)
    }

    fn should_act(&self) -> bool {
        true
    }

    fn buffer(&mut self) -> &mut [u8] {
        &mut self.buffer
    }

    async fn wait_for_data(&mut self, _qconn: &mut QuicheConnection) -> QuicResult<()> {
        if self.pending_writes.is_empty() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        Ok(())
    }

    fn process_reads(&mut self, qconn: &mut QuicheConnection) -> QuicResult<()> {
        let mut dgram = [0; 2048];
        while let Ok(read) = qconn.dgram_recv(&mut dgram) {
            if read >= 2 && dgram[1] == codec::CMD_PACKET {
                self.handle_packet(&dgram[..read]);
            }
        }

        while let Some(stream_id) = qconn.stream_readable_next() {
            loop {
                let mut buf = [0; 2048];
                match qconn.stream_recv(stream_id, &mut buf) {
                    Ok((read, fin)) => {
                        self.response_streams
                            .entry(stream_id)
                            .or_default()
                            .extend_from_slice(&buf[..read]);
                        if fin {
                            if let Some(data) = self.response_streams.remove(&stream_id) {
                                self.handle_packet(&data);
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
        while let Some(write) = self.pending_writes.pop_front() {
            if let Some(write) = self.try_send(qconn, write)? {
                self.pending_writes.push_front(write);
                break;
            }
        }
        Ok(())
    }
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

struct TestTlsFiles {
    server: TlsServerConfig,
    ca_certificate: String,
}

fn write_test_tls_files() -> anyhow::Result<TestTlsFiles> {
    let suffix = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos()
    );
    let cert = std::env::temp_dir().join(format!("rtunnel-{suffix}.crt"));
    let key = std::env::temp_dir().join(format!("rtunnel-{suffix}.key"));
    let ca = std::env::temp_dir().join(format!("rtunnel-{suffix}-ca.crt"));

    let (ca_cert, ca_issuer) = test_ca()?;
    let (server_cert, server_key) = test_server_cert(&ca_issuer)?;
    std::fs::write(&cert, format!("{}{}", server_cert.pem(), ca_cert.pem()))?;
    std::fs::write(&key, server_key.serialize_pem())?;
    std::fs::write(&ca, ca_cert.pem())?;

    Ok(TestTlsFiles {
        server: TlsServerConfig {
            certificate: Some(cert.to_string_lossy().into_owned()),
            private_key: Some(key.to_string_lossy().into_owned()),
            acme: None,
        },
        ca_certificate: ca.to_string_lossy().into_owned(),
    })
}

fn test_ca() -> anyhow::Result<(Certificate, Issuer<'static, KeyPair>)> {
    let mut params = CertificateParams::new(Vec::<String>::new())?;
    params
        .distinguished_name
        .push(DnType::CommonName, "rtunnel loopback test CA");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);

    let key = KeyPair::generate()?;
    let cert = params.self_signed(&key)?;
    Ok((cert, Issuer::new(params, key)))
}

fn test_server_cert(issuer: &Issuer<'static, KeyPair>) -> anyhow::Result<(Certificate, KeyPair)> {
    let mut params = CertificateParams::new(vec!["localhost".to_owned()])?;
    params
        .distinguished_name
        .push(DnType::CommonName, "localhost");
    params.use_authority_key_identifier_extension = true;
    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ServerAuth);

    let key = KeyPair::generate()?;
    let cert = params.signed_by(&key, issuer)?;
    Ok((cert, key))
}
