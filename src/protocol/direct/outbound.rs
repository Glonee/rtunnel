use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use socket2::{Domain, Protocol, Socket, Type};
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
        Ok(Arc::new(DirectUdpSession::new()?))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UdpMode {
    DualStack,
    Ipv4Only,
}

fn bind_udp_socket(mode: UdpMode) -> io::Result<Socket> {
    let (domain, address) = match mode {
        UdpMode::DualStack => (Domain::IPV6, SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))),
        UdpMode::Ipv4Only => (Domain::IPV4, SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))),
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
    if mode == UdpMode::DualStack {
        // Set explicitly before bind: the default differs across platforms.
        socket.set_only_v6(false)?;
    }
    socket.bind(&address.into())?;
    Ok(socket)
}

// Native ENOPROTOOPT, EPROTONOSUPPORT and EAFNOSUPPORT. Rust does not map
// these consistently to ErrorKind::Unsupported. Keep a narrow, target-specific
// whitelist; unknown platforms conservatively propagate unclassified errors.
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    not(any(
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6",
        target_arch = "sparc",
        target_arch = "sparc64"
    ))
))]
const IPV6_UNAVAILABLE_CODES: &[i32] = &[92, 93, 97];
#[cfg(all(
    any(target_os = "linux", target_os = "android"),
    any(
        target_arch = "mips",
        target_arch = "mips32r6",
        target_arch = "mips64",
        target_arch = "mips64r6"
    )
))]
const IPV6_UNAVAILABLE_CODES: &[i32] = &[99, 120, 124];
#[cfg(any(
    all(
        any(target_os = "linux", target_os = "android"),
        any(target_arch = "sparc", target_arch = "sparc64")
    ),
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd"
))]
const IPV6_UNAVAILABLE_CODES: &[i32] = &[42, 43, 47];
#[cfg(windows)]
const IPV6_UNAVAILABLE_CODES: &[i32] = &[10042, 10043, 10047];
#[cfg(not(any(
    target_os = "linux",
    target_os = "android",
    target_vendor = "apple",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "netbsd",
    target_os = "openbsd",
    windows
)))]
const IPV6_UNAVAILABLE_CODES: &[i32] = &[];

fn ipv6_unavailable(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::AddrNotAvailable | io::ErrorKind::Unsupported
    ) || error
        .raw_os_error()
        .is_some_and(|code| IPV6_UNAVAILABLE_CODES.contains(&code))
}

struct DirectUdpSession {
    socket: UdpSocket,
    mode: UdpMode,
    recv_buf: Mutex<Vec<u8>>,
}

impl DirectUdpSession {
    fn new() -> io::Result<Self> {
        Self::with_socket_factory(bind_udp_socket)
    }

    fn with_socket_factory(
        mut bind: impl FnMut(UdpMode) -> io::Result<Socket>,
    ) -> io::Result<Self> {
        let (socket, mode) = match bind(UdpMode::DualStack) {
            Ok(socket) => (socket, UdpMode::DualStack),
            Err(error) if ipv6_unavailable(&error) => (bind(UdpMode::Ipv4Only)?, UdpMode::Ipv4Only),
            Err(error) => return Err(error),
        };
        // Nonblocking setup and reactor registration errors must never cause
        // an IPv4 retry. A failed IPv6 attempt has already dropped its socket.
        socket.set_nonblocking(true)?;
        Ok(Self {
            socket: UdpSocket::from_std(socket.into())?,
            mode,
            recv_buf: Mutex::new(vec![0; UDP_BUFFER_SIZE]),
        })
    }

    async fn send_addr(&self, address: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let address = match (self.mode, address) {
            (UdpMode::DualStack, SocketAddr::V4(address)) => {
                SocketAddr::new(IpAddr::V6(address.ip().to_ipv6_mapped()), address.port())
            }
            (UdpMode::Ipv4Only, SocketAddr::V6(address)) => {
                let ip = address.ip().to_ipv4_mapped().ok_or_else(|| {
                    io::Error::new(io::ErrorKind::AddrNotAvailable, "IPv6 UDP is unavailable")
                })?;
                SocketAddr::from((ip, address.port()))
            }
            (_, address) => address,
        };
        self.socket.send_to(payload, address).await?;
        Ok(())
    }
}

#[async_trait]
impl ProxyDatagram for DirectUdpSession {
    async fn send_to(&self, target: &TargetAddr, payload: &[u8]) -> anyhow::Result<()> {
        match target {
            TargetAddr::Ip(address) => self.send_addr(*address, payload).await?,
            TargetAddr::Domain { host, port } => {
                let mut last_error = None;
                for address in lookup_host((host.as_str(), *port)).await? {
                    match self.send_addr(address, payload).await {
                        Ok(()) => return Ok(()),
                        Err(error) => last_error = Some(error),
                    }
                }
                return Err(last_error.map(anyhow::Error::from).unwrap_or_else(|| {
                    anyhow::anyhow!("no usable UDP address for {host}:{port}")
                }));
            }
        }
        Ok(())
    }

    async fn recv_from(&self) -> anyhow::Result<(TargetAddr, Vec<u8>)> {
        let mut buf = self.recv_buf.lock().await;
        // Tokio recv_from is cancellation safe. There is one buffer and no
        // cancellation point after dequeueing a datagram and before returning it.
        let (read, source) = self.socket.recv_from(buf.as_mut_slice()).await?;
        let source = match source {
            SocketAddr::V6(address) => address
                .ip()
                .to_ipv4_mapped()
                .map(|ip| SocketAddr::from((ip, address.port())))
                .unwrap_or(source),
            source => source,
        };
        Ok((TargetAddr::Ip(source), buf[..read].to_vec()))
    }
}

#[cfg(test)]
#[path = "outbound_tests.rs"]
mod tests;
