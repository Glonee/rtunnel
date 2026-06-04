use std::{
    fmt,
    net::{IpAddr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use tokio::io::{AsyncRead, AsyncWrite};

pub trait ProxyStream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

pub type BoxStream = Box<dyn ProxyStream>;

#[async_trait]
pub trait ProxyDatagram: Send + Sync {
    async fn send_to(&self, target: &TargetAddr, payload: &[u8]) -> anyhow::Result<()>;

    async fn recv_from(&self) -> anyhow::Result<(TargetAddr, Vec<u8>)>;
}

pub type BoxDatagram = Arc<dyn ProxyDatagram>;

#[derive(Clone, Debug)]
pub struct Session {
    pub inbound: String,
    pub command: Command,
    pub target: TargetAddr,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Command {
    Connect,
    UdpAssociate,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub enum TargetAddr {
    Ip(SocketAddr),
    Domain { host: String, port: u16 },
}

impl TargetAddr {
    pub fn port(&self) -> u16 {
        match self {
            TargetAddr::Ip(addr) => addr.port(),
            TargetAddr::Domain { port, .. } => *port,
        }
    }
}

impl fmt::Display for TargetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TargetAddr::Ip(addr) => write!(f, "{addr}"),
            TargetAddr::Domain { host, port } => write!(f, "{host}:{port}"),
        }
    }
}

impl From<SocketAddr> for TargetAddr {
    fn from(value: SocketAddr) -> Self {
        Self::Ip(value)
    }
}

impl From<(IpAddr, u16)> for TargetAddr {
    fn from((ip, port): (IpAddr, u16)) -> Self {
        Self::Ip(SocketAddr::new(ip, port))
    }
}
