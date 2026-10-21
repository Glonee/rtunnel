use super::*;
use std::{net::SocketAddr, time::Duration};
use tokio::time::timeout;

fn session() -> Session {
    Session {
        inbound: "direct-test".into(),
        command: Command::UdpAssociate,
        target: TargetAddr::Ip("127.0.0.1:1".parse().unwrap()),
    }
}

#[tokio::test]
async fn single_socket_sends_and_receives_both_families_and_numeric_domains() -> anyhow::Result<()>
{
    timeout(Duration::from_secs(3), async {
        let v4 = UdpSocket::bind("127.0.0.1:0").await?;
        let v6 = UdpSocket::bind("[::1]:0").await?;
        let udp = DirectOutbound.dial_udp(&session()).await?;
        let address4 = v4.local_addr()?;
        let address6 = v6.local_addr()?;
        let mut port = None;
        for domain in [false, true] {
            let target = |address: SocketAddr| {
                if domain {
                    TargetAddr::Domain {
                        host: address.ip().to_string(),
                        port: address.port(),
                    }
                } else {
                    TargetAddr::Ip(address)
                }
            };
            udp.send_to(&target(address4), b"four").await?;
            udp.send_to(&target(address6), b"six").await?;
            let mut buf4 = [0; 32];
            let mut buf6 = [0; 32];
            let ((n4, peer4), (n6, peer6)) =
                tokio::try_join!(v4.recv_from(&mut buf4), v6.recv_from(&mut buf6))?;
            assert_eq!(&buf4[..n4], b"four");
            assert_eq!(&buf6[..n6], b"six");
            eprintln!("domain={domain}, IPv4 peer={peer4}, IPv6 peer={peer6}");
            assert_eq!(
                peer4.port(),
                peer6.port(),
                "one dual-stack socket must use the same source port for IPv4 and IPv6"
            );
            if let Some(port) = port {
                assert_eq!(peer4.port(), port);
            }
            port = Some(peer4.port());
            // Both families are queued before either application receive call.
            v4.send_to(b"reply4", peer4).await?;
            v6.send_to(b"reply6", peer6).await?;
            let mut replies = std::collections::HashMap::new();
            for _ in 0..2 {
                let (source, data) = udp.recv_from().await?;
                replies.insert(source, data);
            }
            assert_eq!(
                replies.remove(&TargetAddr::Ip(address4)).unwrap(),
                b"reply4",
                "IPv4 source must be normalized, never mapped IPv6"
            );
            assert_eq!(
                replies.remove(&TargetAddr::Ip(address6)).unwrap(),
                b"reply6"
            );
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn dual_stack_factory_opens_only_one_socket() -> anyhow::Result<()> {
    timeout(Duration::from_secs(3), async {
        let mut calls = Vec::new();
        let udp = DirectUdpSession::with_socket_factory(|mode| {
            calls.push(mode);
            bind_udp_socket(mode)
        })?;
        assert_eq!(calls, [UdpMode::DualStack]);
        assert!(udp.socket.local_addr()?.is_ipv6());
        assert!(!socket2::SockRef::from(&udp.socket).only_v6()?);
        assert_eq!(udp.recv_buf.lock().await.len(), UDP_BUFFER_SIZE);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn ipv6_unavailable_falls_back_to_one_working_ipv4_socket() -> anyhow::Result<()> {
    timeout(Duration::from_secs(3), async {
        let mut errors = vec![
            io::Error::from(io::ErrorKind::Unsupported),
            io::Error::from(io::ErrorKind::AddrNotAvailable),
        ];
        errors.extend(
            IPV6_UNAVAILABLE_CODES
                .iter()
                .map(|code| io::Error::from_raw_os_error(*code)),
        );
        let target = UdpSocket::bind("127.0.0.1:0").await?;
        let address = target.local_addr()?;
        for error in errors {
            let mut error = Some(error);
            let mut calls = Vec::new();
            let udp = DirectUdpSession::with_socket_factory(|mode| {
                calls.push(mode);
                if mode == UdpMode::DualStack {
                    Err(error.take().unwrap())
                } else {
                    bind_udp_socket(mode)
                }
            })?;
            assert_eq!(calls, [UdpMode::DualStack, UdpMode::Ipv4Only]);
            assert_eq!(udp.mode, UdpMode::Ipv4Only);
            assert!(udp.socket.local_addr()?.is_ipv4());
            let mapped = SocketAddr::new(
                IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
                address.port(),
            );
            for target_addr in [
                TargetAddr::Ip(address),
                TargetAddr::Domain {
                    host: "127.0.0.1".into(),
                    port: address.port(),
                },
                TargetAddr::Ip(mapped),
            ] {
                udp.send_to(&target_addr, b"request").await?;
                let mut buf = [0; 32];
                let (n, peer) = target.recv_from(&mut buf).await?;
                assert_eq!(&buf[..n], b"request");
                assert_eq!(peer.port(), udp.socket.local_addr()?.port());
                target.send_to(b"reply", peer).await?;
                let (source, payload) = udp.recv_from().await?;
                assert_eq!(source, TargetAddr::Ip(address));
                assert_eq!(payload, b"reply");
            }
            // Native IPv6 cannot be silently sent via the IPv4 fallback.
            for target_addr in [
                TargetAddr::Ip("[::1]:9".parse()?),
                TargetAddr::Domain {
                    host: "::1".into(),
                    port: 9,
                },
            ] {
                let error = udp.send_to(&target_addr, b"no").await.unwrap_err();
                assert_eq!(
                    error.downcast_ref::<io::Error>().unwrap().kind(),
                    io::ErrorKind::AddrNotAvailable
                );
            }
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn factory_permission_and_resource_errors_are_not_ipv6_fallback() -> anyhow::Result<()> {
    timeout(Duration::from_secs(3), async {
        let mut errors = vec![
            io::Error::new(io::ErrorKind::PermissionDenied, "denied"),
            io::Error::new(io::ErrorKind::OutOfMemory, "allocation limit"),
            io::Error::new(io::ErrorKind::AddrInUse, "ports exhausted"),
            io::Error::new(io::ErrorKind::InvalidInput, "invalid option"),
            io::Error::other("unclassified failure"),
        ];
        #[cfg(unix)]
        errors.push(io::Error::from_raw_os_error(24)); // EMFILE
        #[cfg(windows)]
        errors.push(io::Error::from_raw_os_error(10024)); // WSAEMFILE
        // ENOBUFS is Uncategorized on this target: a broad kind-based fallback
        // must not accidentally swallow this real resource error either.
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        errors.extend([1, 13, 23, 24, 105].map(io::Error::from_raw_os_error));
        for error in errors {
            let (kind, raw, message) = (error.kind(), error.raw_os_error(), error.to_string());
            let mut error = Some(error);
            let mut calls = Vec::new();
            let result = DirectUdpSession::with_socket_factory(|mode| {
                calls.push(mode);
                Err(error.take().expect("unrelated error retried as IPv4"))
            });
            let error = match result {
                Err(error) => error,
                Ok(_) => panic!("factory failure disappeared"),
            };
            assert_eq!(calls, [UdpMode::DualStack]);
            assert_eq!(error.kind(), kind);
            assert_eq!(error.raw_os_error(), raw);
            assert_eq!(error.to_string(), message);
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn ipv4_fallback_bind_failure_is_propagated() -> anyhow::Result<()> {
    timeout(Duration::from_secs(3), async {
        let mut calls = Vec::new();
        let result = DirectUdpSession::with_socket_factory(|mode| {
            calls.push(mode);
            match mode {
                UdpMode::DualStack => Err(io::Error::from(io::ErrorKind::Unsupported)),
                UdpMode::Ipv4Only => Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "IPv4 bind denied",
                )),
            }
        });
        let error = match result {
            Err(error) => error,
            Ok(_) => panic!("fallback error disappeared"),
        };
        assert_eq!(calls, [UdpMode::DualStack, UdpMode::Ipv4Only]);
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(error.to_string(), "IPv4 bind denied");
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn mapped_ipv4_literal_and_domain_return_normalized_sources() -> anyhow::Result<()> {
    timeout(Duration::from_secs(3), async {
        let target = UdpSocket::bind("127.0.0.1:0").await?;
        let address = target.local_addr()?;
        let udp = DirectOutbound.dial_udp(&session()).await?;
        for destination in [
            TargetAddr::Ip(SocketAddr::new(
                IpAddr::V6(Ipv4Addr::LOCALHOST.to_ipv6_mapped()),
                address.port(),
            )),
            TargetAddr::Domain {
                host: "::ffff:127.0.0.1".into(),
                port: address.port(),
            },
        ] {
            udp.send_to(&destination, b"mapped").await?;
            let mut buf = [0; 32];
            let (n, peer) = target.recv_from(&mut buf).await?;
            assert_eq!(&buf[..n], b"mapped");
            target.send_to(b"normalized", peer).await?;
            let (source, data) = udp.recv_from().await?;
            assert_eq!(source, TargetAddr::Ip(address));
            assert_eq!(data, b"normalized");
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn cancelled_receive_releases_buffer_and_preserves_both_families() -> anyhow::Result<()> {
    timeout(Duration::from_secs(3), async {
        let v4 = UdpSocket::bind("127.0.0.1:0").await?;
        let v6 = UdpSocket::bind("[::1]:0").await?;
        let udp = DirectUdpSession::new()?;
        udp.send_to(&v4.local_addr()?.into(), b"four").await?;
        udp.send_to(&v6.local_addr()?.into(), b"six").await?;
        let mut buf = [0; 32];
        let (_, peer4) = v4.recv_from(&mut buf).await?;
        let (_, peer6) = v6.recv_from(&mut buf).await?;
        let mut first = Box::pin(udp.recv_from());
        assert!(futures_util::poll!(&mut first).is_pending());
        let mut waiting_for_buffer = Box::pin(udp.recv_from());
        assert!(futures_util::poll!(&mut waiting_for_buffer).is_pending());
        drop(first);
        assert!(futures_util::poll!(&mut waiting_for_buffer).is_pending());
        drop(waiting_for_buffer);
        assert!(udp.recv_buf.try_lock().is_ok());
        let mut cancelled_after_arrival = Box::pin(udp.recv_from());
        assert!(futures_util::poll!(&mut cancelled_after_arrival).is_pending());
        v4.send_to(b"reply4", peer4).await?;
        v6.send_to(b"reply6", peer6).await?;
        drop(cancelled_after_arrival);
        let mut replies = std::collections::HashMap::new();
        for _ in 0..2 {
            let (source, payload) = udp.recv_from().await?;
            replies.insert(source, payload);
        }
        assert_eq!(
            replies.remove(&TargetAddr::Ip(v4.local_addr()?)).unwrap(),
            b"reply4"
        );
        assert_eq!(
            replies.remove(&TargetAddr::Ip(v6.local_addr()?)).unwrap(),
            b"reply6"
        );
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn send_io_errors_survive_literal_and_domain_paths() -> anyhow::Result<()> {
    timeout(Duration::from_secs(3), async {
        let target = UdpSocket::bind("127.0.0.1:0").await?;
        let address = target.local_addr()?;
        let udp = DirectUdpSession::new()?;
        let oversized = vec![0; UDP_BUFFER_SIZE];
        for destination in [
            TargetAddr::Ip(address),
            TargetAddr::Domain {
                host: "127.0.0.1".into(),
                port: address.port(),
            },
        ] {
            let error = udp.send_to(&destination, &oversized).await.unwrap_err();
            assert!(
                error
                    .downcast_ref::<io::Error>()
                    .unwrap()
                    .raw_os_error()
                    .is_some()
            );
        }
        // An ordinary send after the failures still uses the original socket.
        udp.send_to(&address.into(), b"ok").await?;
        let mut buf = [0; 32];
        let (n, peer) = target.recv_from(&mut buf).await?;
        assert_eq!(&buf[..n], b"ok");
        assert_eq!(peer.port(), udp.socket.local_addr()?.port());
        Ok(())
    })
    .await?
}
