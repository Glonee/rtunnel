// Test-only transport fixture: real quiche TLS/QUIC, packets passed in memory.
use tokio_quiche::{quic::QuicheConnection, quiche};

pub struct Pair {
    pub client: QuicheConnection,
    pub server: QuicheConnection,
    dir: std::path::PathBuf,
}
impl Drop for Pair {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
pub fn transfer(from: &mut QuicheConnection, to: &mut QuicheConnection) -> usize {
    let mut count = 0;
    for _ in 0..128 {
        let mut packet = [0u8; 65535];
        match from.send(&mut packet) {
            Ok((len, info)) => {
                to.recv(
                    &mut packet[..len],
                    quiche::RecvInfo {
                        from: info.from,
                        to: info.to,
                    },
                )
                .unwrap();
                count += 1;
            }
            Err(quiche::Error::Done) => break,
            Err(e) => panic!("fixture send: {e}"),
        }
    }
    count
}
pub fn pair(receive_window: u64) -> Pair {
    pair_with_stream_window(receive_window, receive_window)
}
pub fn pair_with_stream_window(receive_window: u64, stream_window: u64) -> Pair {
    let dir = std::env::temp_dir().join(format!("rtunnel-test-quic-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir).unwrap();
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".into()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let cert_path = dir.join("cert.pem");
    let key_path = dir.join("key.pem");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key.serialize_pem()).unwrap();
    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();
    config
        .load_cert_chain_from_pem_file(cert_path.to_str().unwrap())
        .unwrap();
    config
        .load_priv_key_from_pem_file(key_path.to_str().unwrap())
        .unwrap();
    config.verify_peer(false);
    config.set_application_protos(&[b"h3"]).unwrap();
    config.set_initial_max_data(receive_window);
    config.set_initial_max_stream_data_bidi_local(stream_window);
    config.set_initial_max_stream_data_bidi_remote(stream_window);
    config.set_initial_max_stream_data_uni(stream_window);
    config.set_initial_max_streams_bidi(32);
    config.set_initial_max_streams_uni(32);
    config.enable_dgram(true, 32, 32);
    let client_addr = "127.0.0.1:10000".parse().unwrap();
    let server_addr = "127.0.0.1:10001".parse().unwrap();
    let mut client = quiche::connect_with_buffer_factory(
        Some("localhost"),
        &quiche::ConnectionId::from_ref(&[1; 16]),
        client_addr,
        server_addr,
        &mut config,
    )
    .unwrap();
    let mut packet = [0u8; 65535];
    let (len, _) = client.send(&mut packet).unwrap();
    let header = quiche::Header::from_slice(&mut packet[..len], quiche::MAX_CONN_ID_LEN).unwrap();
    let mut server =
        quiche::accept_with_buf_factory(&header.dcid, None, server_addr, client_addr, &mut config)
            .unwrap();
    server
        .recv(
            &mut packet[..len],
            quiche::RecvInfo {
                from: client_addr,
                to: server_addr,
            },
        )
        .unwrap();
    for _ in 0..100 {
        transfer(&mut server, &mut client);
        transfer(&mut client, &mut server);
        if client.is_established() && server.is_established() {
            break;
        }
    }
    assert!(
        client.is_established() && server.is_established(),
        "fixture handshake did not finish"
    );
    Pair {
        client,
        server,
        dir,
    }
}
