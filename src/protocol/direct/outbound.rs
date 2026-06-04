use async_trait::async_trait;
use std::{net::IpAddr, sync::Arc};
use tokio::net::{TcpStream, UdpSocket};

use crate::{
    router::Outbound,
    session::{BoxDatagram, BoxStream, Command, ProxyDatagram, Session, TargetAddr},
};

pub struct DirectOutbound;

#[async_trait]
impl Outbound for DirectOutbound {
    async fn dial(&self, session: &Session) -> anyhow::Result<BoxStream> {
        anyhow::ensure!(
            matches!(session.command, Command::Connect),
            "direct outbound only supports CONNECT"
        );
        let stream = TcpStream::connect(session.target.to_string()).await?;
        Ok(Box::new(stream))
    }

    async fn dial_udp(&self, session: &Session) -> anyhow::Result<BoxDatagram> {
        anyhow::ensure!(
            matches!(session.command, Command::UdpAssociate),
            "direct udp outbound only supports UDP associate"
        );
        Ok(Arc::new(DirectUdpSession {
            ipv4: UdpSocket::bind("0.0.0.0:0").await?,
            ipv6: UdpSocket::bind("[::]:0").await?,
        }))
    }
}

struct DirectUdpSession {
    ipv4: UdpSocket,
    ipv6: UdpSocket,
}

#[async_trait]
impl ProxyDatagram for DirectUdpSession {
    async fn send_to(&self, target: &TargetAddr, payload: &[u8]) -> anyhow::Result<()> {
        let socket = match target {
            TargetAddr::Ip(addr) if matches!(addr.ip(), IpAddr::V6(_)) => &self.ipv6,
            _ => &self.ipv4,
        };
        socket.send_to(payload, target.to_string()).await?;
        Ok(())
    }

    async fn recv_from(&self) -> anyhow::Result<(TargetAddr, Vec<u8>)> {
        let mut ipv4_buf = vec![0; 64 * 1024];
        let mut ipv6_buf = vec![0; 64 * 1024];
        tokio::select! {
            received = self.ipv4.recv_from(&mut ipv4_buf) => {
                let (read, source) = received?;
                ipv4_buf.truncate(read);
                Ok((TargetAddr::Ip(source), ipv4_buf))
            }
            received = self.ipv6.recv_from(&mut ipv6_buf) => {
                let (read, source) = received?;
                ipv6_buf.truncate(read);
                Ok((TargetAddr::Ip(source), ipv6_buf))
            }
        }
    }
}
