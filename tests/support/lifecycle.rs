use super::*;

struct Cleanup {
    tasks: Vec<tokio::task::JoinHandle<()>>,
    paths: Vec<std::path::PathBuf>,
}
impl Drop for Cleanup {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
        for path in &self.paths {
            let _ = std::fs::remove_file(path);
        }
    }
}
async fn anytls_close_case(outer_drop: bool) -> anyhow::Result<()> {
    let files = write_test_tls_files()?;
    let mut cleanup = Cleanup {
        tasks: vec![],
        paths: vec![
            files.server.certificate.as_ref().unwrap().into(),
            files.server.private_key.as_ref().unwrap().into(),
            (&files.ca_certificate).into(),
        ],
    };
    let listener = TcpListener::bind(localhost(0)).await?;
    let addr = listener.local_addr()?;
    let cfg = InboundConfig {
        tag: "audit".into(),
        listen: addr,
        protocol: Protocol::Anytls,
        users: Some(vec![UserConfig {
            username: "audit".into(),
            uuid: None,
            password: "secret".into(),
        }]),
        padding_scheme: vec![],
        fallback: None,
        tls: Some(files.server.clone()),
    };
    let router = Arc::new(
        Router::new(toml::from_str::<Config>(
            "[[outbounds]]\ntag='direct'\nprotocol='direct'\n",
        )?)
        .await?,
    );
    cleanup.tasks.push(tokio::spawn(async move {
        let _ = anytls_inbound::serve(listener, cfg, router).await;
    }));
    let target_listener = TcpListener::bind(localhost(0)).await?;
    let mut client = connect_anytls_session(addr, &files.ca_certificate).await?;
    anytls_codec::write_frame(
        &mut client,
        anytls_codec::CMD_SETTINGS,
        0,
        &anytls_codec::client_settings(),
    )
    .await?;
    anytls_codec::write_frame(&mut client, anytls_codec::CMD_SYN, 1, &[]).await?;
    let mut data = anytls_codec::encode_socksaddr(&target_listener.local_addr()?.into())?;
    data.push(b'x');
    anytls_codec::write_frame(&mut client, anytls_codec::CMD_PSH, 1, &data).await?;
    let (mut target, _) = target_listener.accept().await?;
    let mut byte = [0];
    target.read_exact(&mut byte).await?;
    assert_eq!(byte, [b'x']);
    let mut client = Some(client);
    if outer_drop {
        drop(client.take());
    } else {
        let stream = client.as_mut().unwrap();
        anytls_codec::write_frame(stream, anytls_codec::CMD_FIN, 1, &[]).await?;
        anytls_codec::write_frame(stream, anytls_codec::CMD_HEART_REQUEST, 999, &[]).await?;
        loop {
            let frame = anytls_codec::read_frame(stream).await?;
            if frame.command == anytls_codec::CMD_HEART_RESPONSE && frame.stream_id == 999 {
                break;
            }
        }
    }
    let closed = timeout(Duration::from_millis(500), target.read(&mut byte)).await;
    eprintln!("AnyTLS outer_drop={outer_drop}, target EOF within 500ms={closed:?}");
    // Release the quiet target first, so detached production readers can finish.
    drop(target);
    drop(client);
    drop(target_listener);
    sleep(Duration::from_millis(30)).await;
    let reclaimed = matches!(closed, Ok(Ok(0)))
        || matches!(closed, Ok(Err(ref e)) if e.kind() == std::io::ErrorKind::ConnectionReset);
    drop(cleanup);
    assert!(
        reclaimed,
        "quiet target connection survived AnyTLS close (outer_drop={outer_drop})"
    );
    Ok(())
}

// H: a processed AnyTLS FIN releases its quiet target connection.
#[tokio::test]
async fn fin_releases_quiet_target() -> anyhow::Result<()> {
    timeout(Duration::from_secs(4), anytls_close_case(false)).await?
}
// H: dropping the outer TLS connection releases every quiet target connection.
#[tokio::test]
async fn outer_drop_releases_quiet_target() -> anyhow::Result<()> {
    timeout(Duration::from_secs(4), anytls_close_case(true)).await?
}

// H: the production domain-target branch can send to an IPv6-only local endpoint.
#[tokio::test]
async fn direct_udp_sends_to_ipv6_domain_target() -> anyhow::Result<()> {
    timeout(Duration::from_secs(3), async {
        let receiver = UdpSocket::bind("[::1]:0").await?;
        let target = TargetAddr::Domain {
            host: "::1".into(),
            port: receiver.local_addr()?.port(),
        };
        let resolved: Vec<_> = tokio::net::lookup_host(("::1", target.port()))
            .await?
            .collect();
        anyhow::ensure!(
            !resolved.is_empty()
                && resolved
                    .iter()
                    .all(|a| a.ip() == std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)),
            "ENVIRONMENT: alias did not resolve exclusively to ::1: {resolved:?}"
        );
        let direct = rtunnel::protocol::direct::outbound::DirectOutbound;
        let udp = direct
            .dial_udp(&Session {
                inbound: "audit".into(),
                command: Command::UdpAssociate,
                target: target.clone(),
            })
            .await?;
        let result = udp.send_to(&target, b"audit").await;
        eprintln!("Direct UDP resolved={resolved:?}, send_to={result:?}");
        assert!(
            result.is_ok(),
            "IPv6-only local domain could not be sent through Direct UDP"
        );
        let mut buf = [0; 16];
        let (len, _) = timeout(Duration::from_millis(500), receiver.recv_from(&mut buf)).await??;
        assert_eq!(&buf[..len], b"audit");
        Ok(())
    })
    .await?
}

// Real TLS/session dispatch regression. Slow reads exercise cancellation with
// active traffic, while the deterministic AsyncWrite tests prove the exact
// partial-write boundary independently of OS/TLS buffering.
#[tokio::test]
async fn anytls_slow_reader_fin_preserves_sibling_and_heartbeat() -> anyhow::Result<()> {
    timeout(Duration::from_secs(6), async {
        let files = write_test_tls_files()?;
        let mut cleanup = Cleanup {
            tasks: vec![],
            paths: vec![
                files.server.certificate.as_ref().unwrap().into(),
                files.server.private_key.as_ref().unwrap().into(),
                (&files.ca_certificate).into(),
            ],
        };
        let listener = TcpListener::bind(localhost(0)).await?;
        let addr = listener.local_addr()?;
        let cfg = InboundConfig {
            tag: "writer-test".into(),
            listen: addr,
            protocol: Protocol::Anytls,
            users: Some(vec![UserConfig {
                username: "test".into(),
                uuid: None,
                password: "secret".into(),
            }]),
            padding_scheme: vec![],
            fallback: None,
            tls: Some(files.server.clone()),
        };
        let router = Arc::new(
            Router::new(toml::from_str::<Config>(
                "[[outbounds]]\ntag='direct'\nprotocol='direct'\n",
            )?)
            .await?,
        );
        cleanup.tasks.push(tokio::spawn(async move {
            let _ = anytls_inbound::serve(listener, cfg, router).await;
        }));
        let mut client = connect_anytls_session(addr, &files.ca_certificate).await?;
        anytls_codec::write_frame(
            &mut client,
            anytls_codec::CMD_SETTINGS,
            0,
            &anytls_codec::client_settings(),
        )
        .await?;
        let active = TcpListener::bind(localhost(0)).await?;
        let sibling = TcpListener::bind(localhost(0)).await?;
        // Open via PSH without SYN so the ACK must precede target reader output.
        for (id, target) in [(1, active.local_addr()?), (2, sibling.local_addr()?)] {
            anytls_codec::write_frame(
                &mut client,
                anytls_codec::CMD_PSH,
                id,
                &anytls_codec::encode_socksaddr(&target.into())?,
            )
            .await?;
        }
        let (mut active_target, _) = active.accept().await?;
        let (mut sibling_target, _) = sibling.accept().await?;
        let mut acked = [false; 2];
        while !acked.iter().all(|ack| *ack) {
            let frame = anytls_codec::read_frame(&mut client).await?;
            match frame.command {
                anytls_codec::CMD_SYNACK => {
                    assert!((1..=2).contains(&frame.stream_id));
                    acked[(frame.stream_id - 1) as usize] = true;
                }
                anytls_codec::CMD_SERVER_SETTINGS | anytls_codec::CMD_UPDATE_PADDING_SCHEME => {}
                other => panic!("unexpected frame before stream ACKs: {other}"),
            }
        }
        let (closed_tx, closed_rx) = oneshot::channel();
        cleanup.tasks.push(tokio::spawn(async move {
            let sent = active_target.write_all(&vec![42; 256 * 1024]).await;
            let closed = match sent {
                Ok(()) => {
                    let mut byte = [0];
                    match active_target.read(&mut byte).await {
                        Ok(0) => true,
                        Err(err) => err.kind() == std::io::ErrorKind::ConnectionReset,
                        _ => false,
                    }
                }
                Err(err) => matches!(
                    err.kind(),
                    std::io::ErrorKind::BrokenPipe | std::io::ErrorKind::ConnectionReset
                ),
            };
            let _ = closed_tx.send(closed);
        }));
        let first = anytls_codec::read_frame(&mut client).await?;
        assert_eq!(first.command, anytls_codec::CMD_PSH);
        assert_eq!(first.stream_id, 1);
        assert!(!first.data.is_empty() && first.data.iter().all(|byte| *byte == 42));
        sleep(Duration::from_millis(30)).await; // Deliberately stop draining TLS.
        anytls_codec::write_frame(&mut client, anytls_codec::CMD_FIN, 1, &[]).await?;
        assert!(
            timeout(Duration::from_secs(1), closed_rx).await??,
            "active target must close before the slow TLS reader resumes"
        );
        sibling_target.write_all(b"sibling").await?;
        anytls_codec::write_frame(&mut client, anytls_codec::CMD_HEART_REQUEST, 99, &[]).await?;
        let mut sibling_bytes = Vec::new();
        let mut heartbeat = false;
        while sibling_bytes.len() < b"sibling".len() || !heartbeat {
            let frame = anytls_codec::read_frame(&mut client).await?;
            match (frame.command, frame.stream_id) {
                (anytls_codec::CMD_PSH, 1) => assert!(frame.data.iter().all(|byte| *byte == 42)),
                (anytls_codec::CMD_FIN, 1) => assert!(frame.data.is_empty()),
                (anytls_codec::CMD_PSH, 2) => sibling_bytes.extend(frame.data),
                (anytls_codec::CMD_HEART_RESPONSE, 99) => {
                    assert!(frame.data.is_empty());
                    heartbeat = true;
                }
                other => panic!("invalid frame after cancelling active stream: {other:?}"),
            }
        }
        assert_eq!(sibling_bytes, b"sibling");
        // The same sibling remains usable after the first heartbeat as well.
        sibling_target.write_all(b"again").await?;
        assert_eq!(
            anytls_frame(&mut client, anytls_codec::CMD_PSH, 2).await?,
            b"again"
        );
        anytls_codec::write_frame(&mut client, anytls_codec::CMD_FIN, 2, &[]).await?;
        let mut byte = [0];
        assert_eq!(sibling_target.read(&mut byte).await?, 0);
        drop(client);
        Ok(())
    })
    .await?
}
