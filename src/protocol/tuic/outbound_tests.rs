use super::*;
use crate::test_quic as fixture;

// H: dropping the UDP owner terminates its application or leaves a pending wait;
// a closed input must not produce an immediate successful empty wake.
#[tokio::test]
async fn udp_owner_drop_terminates_application() {
    use futures_util::FutureExt;
    let mut pair = fixture::pair(65536);
    let (write_tx, write_rx) = mpsc::channel(UDP_CHANNEL_CAPACITY);
    let (response_tx, response_rx) = mpsc::channel(UDP_CHANNEL_CAPACITY);
    let mut app =
        TuicUdpOutboundApp::new(Uuid::from_u128(1), "secret".into(), write_rx, response_tx);
    let owner = TuicUdpSession {
        write_tx,
        response_rx: tokio::sync::Mutex::new(response_rx),
        pkt_id: AtomicU16::new(1),
    };
    drop(owner);
    let mut empty_wakes = 0;
    for _ in 0..8 {
        match app.wait_for_data(&mut pair.client).now_or_never() {
            Some(Ok(())) if app.pending_writes.is_empty() && !pair.client.is_closed() => {
                empty_wakes += 1
            }
            _ => break,
        }
    }
    eprintln!(
        "UDP owner drop immediate empty wakes={empty_wakes}, quic_closed={}",
        pair.client.is_closed()
    );
    assert_eq!(
        empty_wakes, 0,
        "closed owner repeatedly wakes the real application without work or termination"
    );
}

#[tokio::test]
async fn outbound_receive_resumes_without_losing_tcp_bytes() {
    let mut pair = fixture::pair(65536);
    pair.client
        .stream_send(CONNECT_STREAM_ID, b"open", false)
        .unwrap();
    fixture::transfer(&mut pair.client, &mut pair.server);
    let mut marker = [0; 4];
    pair.server
        .stream_recv(CONNECT_STREAM_ID, &mut marker)
        .unwrap();
    let (_write_tx, write_rx) = mpsc::channel(CHANNEL_CAPACITY);
    let (stream_tx, mut stream_rx) = mpsc::channel(CHANNEL_CAPACITY);
    for _ in 0..CHANNEL_CAPACITY {
        stream_tx.try_send(vec![0]).unwrap();
    }
    let mut app = TuicClientApp::new(
        Uuid::from_u128(1),
        "secret".into(),
        "127.0.0.1:80"
            .parse::<std::net::SocketAddr>()
            .unwrap()
            .into(),
        write_rx,
        stream_tx,
    );
    pair.server
        .stream_send(CONNECT_STREAM_ID, b"retained", false)
        .unwrap();
    fixture::transfer(&mut pair.server, &mut pair.client);
    app.process_reads(&mut pair.client).unwrap();
    for _ in 0..CHANNEL_CAPACITY {
        assert_eq!(stream_rx.try_recv().unwrap(), vec![0]);
    }
    app.process_writes(&mut pair.client).unwrap();
    assert_eq!(stream_rx.try_recv().unwrap(), b"retained");
}
