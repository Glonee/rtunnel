use super::*;
use crate::test_quic as fixture;

async fn app() -> TuicApp {
    let cfg = toml::from_str::<crate::config::Config>("").unwrap();
    let mut app = TuicApp::new(
        "audit".into(),
        Arc::new(Router::new(cfg).await.unwrap()),
        vec![],
    );
    app.authenticated = true;
    app
}

// H: a full per-stream queue pauses reads instead of failing the connection.
#[tokio::test]
async fn tcp_receive_backpressure_preserves_siblings() {
    let mut pair = fixture::pair(65536);
    let mut app = app().await;
    let (tx, mut rx) = mpsc::channel(CHANNEL_CAPACITY);
    let (healthy_tx, mut healthy_rx) = mpsc::channel(CHANNEL_CAPACITY);
    app.streams.insert(
        4,
        StreamState {
            client_tx: healthy_tx,
        },
    );
    for _ in 0..CHANNEL_CAPACITY {
        tx.try_send(vec![0]).unwrap();
    }
    app.streams.insert(0, StreamState { client_tx: tx });
    pair.client.stream_send(0, b"overflow", false).unwrap();
    pair.client.stream_send(4, b"healthy", false).unwrap();
    fixture::transfer(&mut pair.client, &mut pair.server);
    let result = app.process_reads(&mut pair.server);
    eprintln!("TCP queue capacity={CHANNEL_CAPACITY}, production process_reads={result:?}");
    assert!(
        result.is_ok(),
        "normal per-stream backpressure must not fail the QUIC application"
    );
    assert_eq!(healthy_rx.try_recv().unwrap(), b"healthy");
    for _ in 0..CHANNEL_CAPACITY {
        assert_eq!(rx.try_recv().unwrap(), vec![0]);
    }
    // Resume without receiving another network packet. The blocked bytes must
    // still be in QUIC, not silently discarded by the first callback.
    app.process_writes(&mut pair.server).unwrap();
    assert_eq!(rx.try_recv().unwrap(), b"overflow");
}

// H: a blocked peer must propagate the channel's finite backpressure budget.
// This is a bounded 1 MiB experiment, not an OOM/load test.
#[tokio::test]
async fn blocked_sender_respects_retry_budget() {
    let mut pair = fixture::pair(4096);
    pair.client.stream_send(0, b"open", false).unwrap();
    fixture::transfer(&mut pair.client, &mut pair.server);
    let mut app = app().await;
    let (tx, _rx) = mpsc::channel(CHANNEL_CAPACITY);
    app.streams.insert(0, StreamState { client_tx: tx });
    let chunk = 16 * 1024;
    for round in 0..2 {
        for _ in 0..CHANNEL_CAPACITY {
            app.outbound_tx
                .try_send(QuicWrite::Data {
                    stream_id: 0,
                    data: vec![7; chunk],
                    fin: false,
                    permit: None,
                })
                .unwrap();
        }
        app.process_writes(&mut pair.server).unwrap();
        let bytes: usize = app
            .pending_writes
            .iter()
            .map(|w| match w {
                QuicWrite::Data { data, .. } => data.len(),
                _ => 0,
            })
            .sum();
        eprintln!(
            "blocked send round={round} pending_items={} pending_bytes={bytes}",
            app.pending_writes.len()
        );
    }
    assert!(
        app.pending_writes.len() <= CHANNEL_CAPACITY,
        "blocked writes escaped the bounded channel: {} pending items",
        app.pending_writes.len()
    );
}

#[tokio::test]
async fn blocked_stream_does_not_block_writable_sibling() {
    use futures_util::FutureExt;
    let mut pair = fixture::pair_with_stream_window(65536, 4096);
    for id in [0, 4] {
        pair.client.stream_send(id, b"open", false).unwrap();
    }
    fixture::transfer(&mut pair.client, &mut pair.server);
    for id in [0, 4] {
        let mut buf = [0; 4];
        pair.server.stream_recv(id, &mut buf).unwrap();
    }
    let mut app = app().await;
    for (id, data) in [
        (0, vec![1; 8192]),
        (0, vec![2; 16]),
        (4, b"healthy".to_vec()),
    ] {
        app.outbound_tx
            .try_send(QuicWrite::Data {
                stream_id: id,
                data,
                fin: false,
                permit: None,
            })
            .unwrap();
    }
    app.process_writes(&mut pair.server).unwrap();
    fixture::transfer(&mut pair.server, &mut pair.client);
    let mut buf = [0; 16];
    let (read, _) = pair.client.stream_recv(4, &mut buf).unwrap();
    assert_eq!(&buf[..read], b"healthy");
    assert_eq!(app.pending_writes.len(), 2);
    assert!(
        app.wait_for_data(&mut pair.server).now_or_never().is_none(),
        "blocked writes must wait for readiness"
    );
    // Release flow control on stream 0 and check FIFO/data integrity after retry.
    let mut received = Vec::new();
    for _ in 0..10 {
        while let Ok((read, _)) = pair.client.stream_recv(0, &mut buf) {
            received.extend_from_slice(&buf[..read]);
        }
        fixture::transfer(&mut pair.client, &mut pair.server);
        app.process_writes(&mut pair.server).unwrap();
        fixture::transfer(&mut pair.server, &mut pair.client);
        if received.len() == 8192 + 16 {
            break;
        }
    }
    assert_eq!(received, [vec![1; 8192], vec![2; 16]].concat());
}

struct ObservedApp {
    inner: TuicApp,
    events: mpsc::UnboundedSender<&'static str>,
    stop: tokio::sync::broadcast::Receiver<()>,
}
impl Drop for ObservedApp {
    fn drop(&mut self) {
        let _ = self.events.send("closed");
    }
}
impl ApplicationOverQuic for ObservedApp {
    fn on_conn_established(
        &mut self,
        conn: &mut QuicheConnection,
        info: &HandshakeInfo,
    ) -> QuicResult<()> {
        self.inner.on_conn_established(conn, info)
    }
    fn should_act(&self) -> bool {
        self.inner.should_act()
    }
    async fn wait_for_data(&mut self, conn: &mut QuicheConnection) -> QuicResult<()> {
        tokio::select! {
            biased;
            _ = self.stop.recv() => { let _ = conn.close(true, 0, b"audit cleanup"); Ok(()) }
            result = self.inner.wait_for_data(conn) => result,
        }
    }
    fn process_reads(&mut self, conn: &mut QuicheConnection) -> QuicResult<()> {
        let mut head = [0; 2];
        if conn.dgram_recv_peek(&mut head, 2).is_ok()
            && head == [codec::VERSION, codec::CMD_HEARTBEAT]
        {
            let _ = self.events.send("heartbeat");
        }
        self.inner.process_reads(conn)
    }
    fn process_writes(&mut self, conn: &mut QuicheConnection) -> QuicResult<()> {
        self.inner.process_writes(conn)
    }
}
struct OwnerCleanup {
    stop: tokio::sync::broadcast::Sender<()>,
    listener: tokio::task::JoinHandle<()>,
    dir: std::path::PathBuf,
}
impl Drop for OwnerCleanup {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        self.listener.abort();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

// H: after the sole production TCP stream completes both directions and its
// owner drops, the one-stream outbound connection terminates, not heartbeats.
enum OwnerCase {
    CompletedTcp,
    ActiveTcp,
    Udp,
}

#[tokio::test]
async fn tcp_owner_drop_closes_connection() -> anyhow::Result<()> {
    owner_case(OwnerCase::CompletedTcp).await
}
#[tokio::test]
async fn active_tcp_owner_drop_closes_connection() -> anyhow::Result<()> {
    owner_case(OwnerCase::ActiveTcp).await
}
#[tokio::test]
async fn udp_owner_drop_closes_network_connection() -> anyhow::Result<()> {
    owner_case(OwnerCase::Udp).await
}
async fn owner_case(case: OwnerCase) -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(15), async {
        let dir = std::env::temp_dir().join(format!("rtunnel-test-owner-{}", Uuid::new_v4()));
        std::fs::create_dir(&dir)?;
        let key = rcgen::KeyPair::generate()?;
        let cert = rcgen::CertificateParams::new(vec!["localhost".into()])?.self_signed(&key)?;
        let cert_path = dir.join("cert.pem");
        let key_path = dir.join("key.pem");
        std::fs::write(&cert_path, cert.pem())?;
        std::fs::write(&key_path, key.serialize_pem())?;
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        let mut settings = quic_settings();
        settings.verify_peer = false;
        settings.disable_client_ip_validation = true;
        let params = ConnectionParams::new_server(settings, TlsCertificatePaths {
            cert: cert_path.to_str().unwrap(), private_key: key_path.to_str().unwrap(), kind: CertificateKind::X509,
        }, tokio_quiche::settings::Hooks::default());
        let mut listeners = tokio_quiche::listen([socket], params, DefaultMetrics)?;
        let mut connections = listeners.remove(0);
        let (events_tx, mut events_rx) = mpsc::unbounded_channel();
        let (stop, _) = tokio::sync::broadcast::channel(1);
        let cfg = toml::from_str::<crate::config::Config>("[[outbounds]]\ntag='direct'\nprotocol='direct'\n")?;
        let router = Arc::new(Router::new(cfg).await?);
        let listener = tokio::spawn({
            let stop = stop.clone();
            async move {
                while let Some(Ok(conn)) = connections.next().await {
                    let app = TuicApp::new("audit".into(), router.clone(), vec![TuicUser {
                        name: "audit".into(), uuid: Uuid::from_u128(1), password: "secret".into(),
                    }]);
                    conn.start(ObservedApp { inner: app, events: events_tx.clone(), stop: stop.subscribe() });
                }
            }
        });
        let cleanup = OwnerCleanup { stop, listener, dir };
        let cfg: crate::config::OutboundConfig = toml::from_str(&format!(
            "tag='audit'\nprotocol='tuic'\nserver='{addr}'\nserver_name='localhost'\ninsecure=true\nuuid='00000000-0000-0000-0000-000000000001'\npassword='secret'\n"
        ))?;
        let outbound = crate::protocol::tuic::outbound::TuicOutbound::new(cfg)?;
        use crate::router::Outbound;
        match case {
            OwnerCase::Udp => {
                let target = UdpSocket::bind("127.0.0.1:0").await?;
                let address: TargetAddr = target.local_addr()?.into();
                let owner = outbound.dial_udp(&Session { inbound: "test".into(), command: Command::UdpAssociate, target: address.clone() }).await?;
                owner.send_to(&address, b"x").await?;
                let mut byte = [0];
                let (read, _) = target.recv_from(&mut byte).await?;
                assert_eq!(&byte[..read], b"x");
                drop(owner);
            }
            OwnerCase::CompletedTcp | OwnerCase::ActiveTcp => {
                let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
                let mut owner = outbound.dial(&Session { inbound: "test".into(), command: Command::Connect, target: target_listener.local_addr()?.into() }).await?;
                owner.write_all(b"x").await?;
                let (mut target, _) = target_listener.accept().await?;
                let mut byte = [0];
                target.read_exact(&mut byte).await?;
                if matches!(case, OwnerCase::CompletedTcp) {
                    owner.shutdown().await?;
                    assert_eq!(target.read(&mut byte).await?, 0, "fixture did not deliver client EOF");
                    target.shutdown().await?;
                    assert_eq!(owner.read(&mut byte).await?, 0, "fixture did not deliver target EOF");
                }
                drop(owner);
                assert_eq!(target.read(&mut byte).await?, 0, "owner drop did not release the target");
            }
        }
        let event = tokio::time::timeout(Duration::from_secs(12), events_rx.recv()).await?;
        eprintln!("real TUIC owner drop: next server event={event:?}");
        let _ = cleanup.stop.send(());
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(cleanup);
        assert_eq!(event, Some("closed"), "connection kept sending heartbeats after owner drop");
        Ok(())
    }).await?
}

#[tokio::test]
async fn relay_producer_cannot_monopolize_retry_queue() -> anyhow::Result<()> {
    tokio::time::timeout(Duration::from_secs(3), async {
        let target_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let cfg = toml::from_str::<crate::config::Config>(
            "[[outbounds]]\ntag='direct'\nprotocol='direct'\n",
        )?;
        let router = Arc::new(Router::new(cfg).await?);
        let (client_tx, client_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (quic_tx, mut quic_rx) = mpsc::channel(CHANNEL_CAPACITY);
        spawn_relay(
            router,
            Session {
                inbound: "test".into(),
                command: Command::Connect,
                target: target_listener.local_addr()?.into(),
            },
            0,
            vec![],
            client_rx,
            quic_tx,
            Arc::new(Notify::new()),
        );
        let (mut target, _) = target_listener.accept().await?;
        target.write_all(&vec![9; 3 * 16 * 1024]).await?;
        let first = quic_rx.recv().await.unwrap();
        let second = quic_rx.recv().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(100), quic_rx.recv())
                .await
                .is_err(),
            "one flow used more than its two pending chunks"
        );
        drop(first);
        let third = tokio::time::timeout(Duration::from_secs(1), quic_rx.recv())
            .await?
            .unwrap();
        assert!(matches!(third, QuicWrite::Data { ref data, .. } if !data.is_empty()));
        drop((second, third, quic_rx, client_tx));
        let mut byte = [0];
        assert_eq!(target.read(&mut byte).await?, 0);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn native_udp_fragment_expansion_respects_byte_budget() {
    use futures_util::FutureExt;
    let mut pair = fixture::pair(65536);
    // Block the native QUIC datagram queue before asking production code to
    // split maximum-size UDP responses. This remains a bounded ~2 MiB test.
    for _ in 0..32 {
        pair.server.dgram_send(b"occupied").unwrap();
    }
    let mut app = app().await;
    for id in 0..CHANNEL_CAPACITY {
        let packet = codec::Packet {
            assoc_id: 1,
            pkt_id: id as u16,
            frag_total: 1,
            frag_id: 0,
            target: Some(
                "127.0.0.1:9"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
                    .into(),
            ),
            payload: vec![0; 65507],
        };
        app.outbound_tx
            .try_send(QuicWrite::Datagram {
                assoc_id: None,
                data: codec::encode_packet(&packet).unwrap(),
            })
            .unwrap();
    }
    app.process_writes(&mut pair.server).unwrap();
    let bytes: usize = app.pending_writes.iter().map(QuicWrite::len).sum();
    assert!(
        bytes <= MAX_PENDING_BYTES,
        "fragment expansion exceeded byte budget: {bytes}"
    );
    assert!(
        !app.outbound_rx.is_empty(),
        "retry budget failed to backpressure the channel"
    );
    // Consume the single notification for newly generated fragments; subsequent
    // waits must suspend if QUIC remains blocked.
    assert!(app.wait_for_data(&mut pair.server).now_or_never().is_some());
    app.process_writes(&mut pair.server).unwrap();
    assert!(app.wait_for_data(&mut pair.server).now_or_never().is_none());
}
