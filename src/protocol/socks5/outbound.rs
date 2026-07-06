use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, bail};
use async_trait::async_trait;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::Mutex,
};

use crate::{
    config::OutboundConfig,
    protocol::socks5::codec,
    router::Outbound,
    session::{BoxDatagram, BoxStream, Command, ProxyDatagram, Session, TargetAddr},
};

const UDP_BUFFER_SIZE: usize = 64 * 1024;

pub struct Socks5Outbound {
    cfg: OutboundConfig,
}

impl Socks5Outbound {
    pub fn new(cfg: OutboundConfig) -> anyhow::Result<Self> {
        cfg.require_server()?;
        Ok(Self { cfg })
    }
}

#[async_trait]
impl Outbound for Socks5Outbound {
    async fn dial(&self, session: &Session) -> anyhow::Result<BoxStream> {
        anyhow::ensure!(
            matches!(session.command, Command::Connect),
            "socks5 outbound only supports CONNECT"
        );
        let mut stream = self.connect_control().await?;
        write_request(&mut stream, codec::CMD_CONNECT, &session.target).await?;
        let (status, _bind) = read_response(&mut stream).await?;
        if status != 0 {
            bail!("socks5 outbound connect failed with status {status}");
        }
        Ok(Box::new(stream))
    }

    async fn dial_udp(&self, session: &Session) -> anyhow::Result<BoxDatagram> {
        anyhow::ensure!(
            matches!(session.command, Command::UdpAssociate),
            "socks5 outbound udp only supports UDP associate"
        );
        let server = self.cfg.require_server()?;
        let mut control = self.connect_control().await?;
        let bind_target = TargetAddr::Ip(SocketAddr::new(
            if server.is_ipv6() {
                std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)
            } else {
                std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
            },
            0,
        ));
        write_request(&mut control, codec::CMD_UDP_ASSOCIATE, &bind_target).await?;
        let (status, bind) = read_response(&mut control).await?;
        if status != 0 {
            bail!("socks5 outbound udp associate failed with status {status}");
        }
        let relay = relay_addr(server, bind)?;
        let socket = UdpSocket::bind(if server.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        })
        .await?;
        Ok(Arc::new(Socks5UdpSession {
            _control: Mutex::new(control),
            socket,
            relay,
            recv_buf: Mutex::new(vec![0; UDP_BUFFER_SIZE]),
        }))
    }
}

impl Socks5Outbound {
    async fn connect_control(&self) -> anyhow::Result<TcpStream> {
        let mut stream = TcpStream::connect(self.cfg.require_server()?).await?;
        let auth = self.cfg.username.is_some() || self.cfg.password.is_some();
        if auth {
            stream.write_all(&[codec::VERSION, 0x01, 0x02]).await?;
        } else {
            stream.write_all(&[codec::VERSION, 0x01, 0x00]).await?;
        }
        let mut resp = [0; 2];
        stream.read_exact(&mut resp).await?;
        if resp[0] != codec::VERSION || resp[1] == 0xff {
            bail!("socks5 outbound rejected auth method");
        }
        if resp[1] == 0x02 {
            let username = self.cfg.username.as_deref().unwrap_or_default().as_bytes();
            let password = self.cfg.password.as_deref().unwrap_or_default().as_bytes();
            anyhow::ensure!(
                username.len() <= 255 && password.len() <= 255,
                "socks5 credentials are too long"
            );
            stream.write_u8(0x01).await?;
            stream.write_u8(username.len() as u8).await?;
            stream.write_all(username).await?;
            stream.write_u8(password.len() as u8).await?;
            stream.write_all(password).await?;
            stream.read_exact(&mut resp).await?;
            if resp != [0x01, 0x00] {
                bail!("socks5 outbound authentication failed");
            }
        }
        Ok(stream)
    }
}

async fn write_request(
    stream: &mut TcpStream,
    command: u8,
    target: &TargetAddr,
) -> anyhow::Result<()> {
    stream.write_all(&[codec::VERSION, command, 0]).await?;
    stream.write_all(&codec::encode_addr(target)?).await?;
    Ok(())
}

async fn read_response(stream: &mut TcpStream) -> anyhow::Result<(u8, TargetAddr)> {
    let ver = stream.read_u8().await?;
    let status = stream.read_u8().await?;
    let rsv = stream.read_u8().await?;
    if ver != codec::VERSION || rsv != 0 {
        bail!("invalid socks5 outbound response");
    }
    let atyp = stream.read_u8().await?;
    let mut encoded = vec![atyp];
    match atyp {
        codec::ATYP_IPV4 => {
            let mut addr = [0; 4];
            stream.read_exact(&mut addr).await?;
            encoded.extend_from_slice(&addr);
        }
        codec::ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            encoded.push(len as u8);
            let mut host = vec![0; len];
            stream.read_exact(&mut host).await?;
            encoded.extend_from_slice(&host);
        }
        codec::ATYP_IPV6 => {
            let mut addr = [0; 16];
            stream.read_exact(&mut addr).await?;
            encoded.extend_from_slice(&addr);
        }
        other => bail!("unsupported socks5 response address type {other}"),
    }
    let port = stream
        .read_u16()
        .await
        .context("missing socks5 bind port")?;
    encoded.extend_from_slice(&port.to_be_bytes());
    let (target, _consumed) = codec::decode_addr(&encoded)?;
    Ok((status, target))
}

fn relay_addr(server: SocketAddr, bind: TargetAddr) -> anyhow::Result<SocketAddr> {
    match bind {
        TargetAddr::Ip(mut addr) => {
            if addr.ip().is_unspecified() {
                addr.set_ip(server.ip());
            }
            Ok(addr)
        }
        TargetAddr::Domain { .. } => bail!("socks5 udp relay returned a domain address"),
    }
}

struct Socks5UdpSession {
    _control: Mutex<TcpStream>,
    socket: UdpSocket,
    relay: SocketAddr,
    recv_buf: Mutex<Vec<u8>>,
}

#[async_trait]
impl ProxyDatagram for Socks5UdpSession {
    async fn send_to(&self, target: &TargetAddr, payload: &[u8]) -> anyhow::Result<()> {
        let packet = codec::encode_udp_packet(target, payload)?;
        self.socket.send_to(&packet, self.relay).await?;
        Ok(())
    }

    async fn recv_from(&self) -> anyhow::Result<(TargetAddr, Vec<u8>)> {
        let mut buf = self.recv_buf.lock().await;
        loop {
            let (read, source) = self.socket.recv_from(buf.as_mut_slice()).await?;
            if source != self.relay {
                continue;
            }
            return codec::decode_udp_packet(&buf[..read]);
        }
    }
}
