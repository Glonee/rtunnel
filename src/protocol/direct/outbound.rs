use std::{net::IpAddr, sync::Arc};

use async_trait::async_trait;
use tokio::{
    net::{TcpStream, UdpSocket, lookup_host},
    sync::Mutex,
};

use crate::{
    router::Outbound,
    session::{BoxDatagram, BoxStream, Command, ProxyDatagram, Session, TargetAddr},
};

const UDP_BUFFER_SIZE: usize = 64 * 1024;

pub struct DirectOutbound;

#[async_trait]
impl Outbound for DirectOutbound {
    async fn dial(&self, session: &Session) -> anyhow::Result<BoxStream> {
        anyhow::ensure!(
            matches!(session.command, Command::Connect),
            "direct outbound only supports CONNECT"
        );
        let stream = match &session.target {
            TargetAddr::Ip(addr) => TcpStream::connect(*addr).await?,
            TargetAddr::Domain { host, port } => TcpStream::connect((host.as_str(), *port)).await?,
        };
        Ok(Box::new(stream))
    }

    async fn dial_udp(&self, session: &Session) -> anyhow::Result<BoxDatagram> {
        anyhow::ensure!(
            matches!(session.command, Command::UdpAssociate),
            "direct udp outbound only supports UDP associate"
        );
        Ok(Arc::new(DirectUdpSession {
            ipv4: UdpSocket::bind("0.0.0.0:0").await?,
            ipv6: UdpSocket::bind("[::]:0").await.ok(),
            ipv4_buf: Mutex::new(vec![0; UDP_BUFFER_SIZE]),
            ipv6_buf: Mutex::new(vec![0; UDP_BUFFER_SIZE]),
        }))
    }
}

struct DirectUdpSession {
    ipv4: UdpSocket,
    ipv6: Option<UdpSocket>,
    ipv4_buf: Mutex<Vec<u8>>,
    ipv6_buf: Mutex<Vec<u8>>,
}

#[async_trait]
impl ProxyDatagram for DirectUdpSession {
    async fn send_to(&self, target: &TargetAddr, payload: &[u8]) -> anyhow::Result<()> {
        match target {
            TargetAddr::Ip(addr) if matches!(addr.ip(), IpAddr::V6(_)) => {
                self.ipv6
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("IPv6 UDP is unavailable"))?
                    .send_to(payload, *addr)
                    .await?;
            }
            TargetAddr::Ip(addr) => {
                self.ipv4.send_to(payload, *addr).await?;
            }
            TargetAddr::Domain { host, port } => {
                let mut last_error = None;
                for addr in lookup_host((host.as_str(), *port)).await? {
                    let result = if addr.is_ipv4() {
                        self.ipv4.send_to(payload, addr).await
                    } else if let Some(socket) = &self.ipv6 {
                        socket.send_to(payload, addr).await
                    } else {
                        continue;
                    };
                    match result {
                        Ok(_) => return Ok(()),
                        Err(err) => last_error = Some(err),
                    }
                }
                return Err(last_error.map(anyhow::Error::from).unwrap_or_else(|| {
                    anyhow::anyhow!("no usable UDP address for {host}:{port}")
                }));
            }
        };
        Ok(())
    }

    async fn recv_from(&self) -> anyhow::Result<(TargetAddr, Vec<u8>)> {
        let mut ipv4_buf = self.ipv4_buf.lock().await;
        let mut ipv6_buf = self.ipv6_buf.lock().await;
        tokio::select! {
            received = self.ipv4.recv_from(ipv4_buf.as_mut_slice()) => {
                let (read, source) = received?;
                Ok((TargetAddr::Ip(source), ipv4_buf[..read].to_vec()))
            }
            received = async {
                match &self.ipv6 {
                    Some(socket) => socket.recv_from(ipv6_buf.as_mut_slice()).await,
                    None => std::future::pending().await,
                }
            } => {
                let (read, source) = received?;
                Ok((TargetAddr::Ip(source), ipv6_buf[..read].to_vec()))
            }
        }
    }
}
