use super::*;
use std::{sync::Mutex as StdMutex, task::Waker, time::Duration};
use tokio::{
    sync::{Notify, oneshot},
    time::timeout,
};

#[derive(Default)]
struct WriteState {
    bytes: Vec<u8>,
    resumed: bool,
    fail: bool,
    waker: Option<Waker>,
}

#[derive(Clone, Default)]
struct WriteGate {
    state: Arc<StdMutex<WriteState>>,
    pending: Arc<Notify>,
}

impl WriteGate {
    fn resume(&self) {
        let mut state = self.state.lock().unwrap();
        state.resumed = true;
        if let Some(waker) = state.waker.take() {
            waker.wake();
        }
    }
    fn bytes(&self) -> Vec<u8> {
        self.state.lock().unwrap().bytes.clone()
    }
}

// A real AsyncWrite: accepts ten bytes, then suspends write_all mid-frame.
// Unlike a timer/socket-buffer heuristic, the gate proves exactly where cancellation occurs.
struct GatedWriter(WriteGate);
impl AsyncWrite for GatedWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut state = self.0.state.lock().unwrap();
        if state.bytes.is_empty() {
            let n = data.len().min(10);
            state.bytes.extend_from_slice(&data[..n]);
            return Poll::Ready(Ok(n));
        }
        if !state.resumed {
            state.waker = Some(cx.waker().clone());
            self.0.pending.notify_one();
            return Poll::Pending;
        }
        if state.fail {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "injected transport failure",
            )));
        }
        state.bytes.extend_from_slice(data);
        Poll::Ready(Ok(data.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct Dropped(Option<oneshot::Sender<()>>);
impl Drop for Dropped {
    fn drop(&mut self) {
        if let Some(tx) = self.0.take() {
            let _ = tx.send(());
        }
    }
}

#[tokio::test]
async fn cancelling_reader_preserves_in_progress_frame_and_siblings() -> anyhow::Result<()> {
    timeout(Duration::from_secs(2), async {
        let gate = WriteGate::default();
        let (writer, _writer_task) = spawn_frame_writer(GatedWriter(gate.clone()));
        let producer_writer = writer.clone();
        let (dropped_tx, dropped_rx) = oneshot::channel();
        let producer = ReaderTask(tokio::spawn(async move {
            let _dropped = Dropped(Some(dropped_tx));
            write_frame(&producer_writer, codec::CMD_PSH, 1, &[42; 32])
                .await
                .unwrap();
        }));
        gate.pending.notified().await;
        assert_eq!(
            gate.bytes().len(),
            10,
            "must cancel inside a partially written frame"
        );
        drop(producer);
        dropped_rx.await?;
        gate.resume();
        write_frame(&writer, codec::CMD_PSH, 2, b"sibling").await?;
        write_frame(&writer, codec::CMD_HEART_RESPONSE, 99, &[]).await?;
        let mut expected = codec::encode_frame(codec::CMD_PSH, 1, &[42; 32])?;
        expected.extend(codec::encode_frame(codec::CMD_PSH, 2, b"sibling")?);
        expected.extend(codec::encode_frame(codec::CMD_HEART_RESPONSE, 99, &[])?);
        assert_eq!(
            gate.bytes(),
            expected,
            "cancelling one reader truncated its frame before sibling/heartbeat writes"
        );
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn tcp_fin_releases_target_while_frame_writer_is_pending() -> anyhow::Result<()> {
    timeout(Duration::from_secs(3), async {
        let gate = WriteGate::default();
        let (writer, _writer_task) = spawn_frame_writer(GatedWriter(gate.clone()));
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let outbound = TcpStream::connect(listener.local_addr()?).await?;
        let (mut target, _) = listener.accept().await?;
        target.write_all(&[42; 32]).await?;
        // Preload the entire small response before spawning the reader, so
        // frame size does not depend on TCP segmentation or task scheduling.
        let mut peek = [0; 32];
        while outbound.peek(&mut peek).await? != peek.len() {
            tokio::task::yield_now().await;
        }
        let outbound: BoxStream = Box::new(outbound);
        let (read_half, write_half) = tokio::io::split(outbound);
        let stream = InboundStream::Tcp {
            writer: write_half,
            _reader: spawn_outbound_reader(1, read_half, writer.clone()),
        };
        gate.pending.notified().await;
        drop(stream); // Same ownership operation as processing CMD_FIN.
        let mut byte = [0];
        assert_eq!(
            target.read(&mut byte).await?,
            0,
            "target survived reader cancellation"
        );
        assert_eq!(
            gate.bytes().len(),
            10,
            "writer must still be stalled when target closes"
        );
        gate.resume();
        write_frame(&writer, codec::CMD_HEART_RESPONSE, 99, &[]).await?;
        let mut expected = codec::encode_frame(codec::CMD_PSH, 1, &[42; 32])?;
        expected.extend(codec::encode_frame(codec::CMD_HEART_RESPONSE, 99, &[])?);
        assert_eq!(gate.bytes(), expected);
        Ok(())
    })
    .await?
}

struct ObservedDatagram {
    inner: BoxDatagram,
    _dropped: Dropped,
}

#[async_trait::async_trait]
impl crate::session::ProxyDatagram for ObservedDatagram {
    async fn send_to(&self, target: &TargetAddr, payload: &[u8]) -> anyhow::Result<()> {
        self.inner.send_to(target, payload).await
    }
    async fn recv_from(&self) -> anyhow::Result<(TargetAddr, Vec<u8>)> {
        self.inner.recv_from().await
    }
}

// Both real production UoT loops use the same cancellation-safe writer. The
// wrapper only observes release of the real Direct UDP datagram, without
// replacing routing, socket I/O, framing, or the select/read/write loops.
#[tokio::test]
async fn uot_cancellation_releases_datagram_without_truncating_frames() -> anyhow::Result<()> {
    use crate::router::Outbound;
    use tokio::net::UdpSocket;
    timeout(Duration::from_secs(3), async {
        for connect in [true, false] {
            let target = UdpSocket::bind("127.0.0.1:0").await?;
            let address: TargetAddr = target.local_addr()?.into();
            let direct = crate::protocol::direct::outbound::DirectOutbound;
            let inner = direct
                .dial_udp(&Session {
                    inbound: "test".into(),
                    command: Command::UdpAssociate,
                    target: address.clone(),
                })
                .await?;
            inner.send_to(&address, b"request").await?;
            let mut buf = [0; 32];
            let (_, peer) = target.recv_from(&mut buf).await?;
            let (dropped_tx, dropped_rx) = oneshot::channel();
            let datagram: BoxDatagram = Arc::new(ObservedDatagram {
                inner,
                _dropped: Dropped(Some(dropped_tx)),
            });
            let gate = WriteGate::default();
            let (writer, _writer_task) = spawn_frame_writer(GatedWriter(gate.clone()));
            let producer_writer = writer.clone();
            let (_tx, rx) = mpsc::channel(1);
            let producer_address = address.clone();
            let producer = ReaderTask(tokio::spawn(async move {
                let input = ChunkReader::new(rx);
                if connect {
                    run_uot_connect_stream(1, producer_address, input, datagram, producer_writer)
                        .await
                        .unwrap();
                } else {
                    run_uot_packet_stream(1, input, datagram, producer_writer)
                        .await
                        .unwrap();
                }
            }));
            target.send_to(&[42; 32], peer).await?;
            gate.pending.notified().await;
            drop(producer);
            dropped_rx.await?; // Datagram and target resources drop before TLS can progress.
            assert_eq!(gate.bytes().len(), 10);
            gate.resume();
            write_frame(&writer, codec::CMD_PSH, 2, b"sibling").await?;
            write_frame(&writer, codec::CMD_HEART_RESPONSE, 99, &[]).await?;
            let payload = if connect {
                codec::encode_uot_payload(&[42; 32])?
            } else {
                codec::encode_uot_packet(&address, &[42; 32])?
            };
            let mut expected = codec::encode_frame(codec::CMD_PSH, 1, &payload)?;
            expected.extend(codec::encode_frame(codec::CMD_PSH, 2, b"sibling")?);
            expected.extend(codec::encode_frame(codec::CMD_HEART_RESPONSE, 99, &[])?);
            assert_eq!(gate.bytes(), expected, "UoT connect={connect}");
        }
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn frame_writer_queue_applies_backpressure_at_its_capacity() -> anyhow::Result<()> {
    timeout(Duration::from_secs(3), async {
        let gate = WriteGate::default();
        let (writer, _writer_task) = spawn_frame_writer(GatedWriter(gate.clone()));
        let mut producers = Vec::new();
        for stream_id in 0..=FRAME_WRITER_CAPACITY {
            let writer = writer.clone();
            producers.push(ReaderTask(tokio::spawn(async move {
                write_frame(&writer, codec::CMD_PSH, stream_id as u32, &[42; 32])
                    .await
                    .unwrap();
            })));
            if stream_id == 0 {
                gate.pending.notified().await;
            }
        }
        while writer.tx.capacity() != 0 {
            tokio::task::yield_now().await;
        }
        let mut blocked = Box::pin(write_frame(&writer, codec::CMD_HEART_RESPONSE, 99, &[]));
        assert!(futures_util::poll!(&mut blocked).is_pending());
        assert_eq!(writer.tx.capacity(), 0);
        assert_eq!(gate.bytes().len(), 10);
        gate.resume();
        blocked.await?;
        for mut producer in producers {
            (&mut producer.0).await?;
        }
        let bytes = gate.bytes();
        let mut count = 0;
        let mut reader = bytes.as_slice();
        while !reader.is_empty() {
            codec::read_frame(&mut reader).await?;
            count += 1;
        }
        assert_eq!(count, FRAME_WRITER_CAPACITY + 2);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn session_exit_reclaims_pending_frame_writer() -> anyhow::Result<()> {
    timeout(Duration::from_secs(2), async {
        let gate = WriteGate::default();
        let (writer, writer_task) = spawn_frame_writer(GatedWriter(gate.clone()));
        let mut pending = Box::pin(write_frame(&writer, codec::CMD_PSH, 1, &[42; 32]));
        assert!(futures_util::poll!(&mut pending).is_pending());
        gate.pending.notified().await;
        drop(writer_task); // Session owns this guard; relay owners never do.
        writer.tx.closed().await;
        assert!(pending.await.is_err());
        assert!(
            write_frame(&writer, codec::CMD_HEART_RESPONSE, 99, &[])
                .await
                .is_err()
        );
        assert_eq!(gate.bytes().len(), 10);
        Ok(())
    })
    .await?
}

#[tokio::test]
async fn transport_error_closes_writer_before_any_following_frame() -> anyhow::Result<()> {
    timeout(Duration::from_secs(2), async {
        let gate = WriteGate::default();
        let (writer, _writer_task) = spawn_frame_writer(GatedWriter(gate.clone()));
        let mut pending = Box::pin(write_frame(&writer, codec::CMD_PSH, 1, &[42; 32]));
        assert!(futures_util::poll!(&mut pending).is_pending());
        gate.pending.notified().await;
        gate.state.lock().unwrap().fail = true;
        gate.resume();
        assert!(pending.await.is_err());
        writer.tx.closed().await;
        assert!(
            write_frame(&writer, codec::CMD_HEART_RESPONSE, 99, &[])
                .await
                .is_err()
        );
        assert_eq!(
            gate.bytes().len(),
            10,
            "must not write after a partial frame transport error"
        );
        Ok(())
    })
    .await?
}
