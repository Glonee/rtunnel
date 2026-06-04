use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use anyhow::{Context, bail};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream, UdpSocket},
};
use tracing::{debug, info};

use crate::{
    config::InboundConfig,
    protocol::socks5::codec,
    router::Router,
    session::{BoxDatagram, Command, Session, TargetAddr},
};

const UDP_ASSOCIATE_IDLE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

pub async fn run(cfg: InboundConfig, router: Arc<Router>) -> anyhow::Result<()> {
    let listener = TcpListener::bind(cfg.listen).await?;
    serve(listener, cfg, router).await
}

pub async fn serve(
    listener: TcpListener,
    cfg: InboundConfig,
    router: Arc<Router>,
) -> anyhow::Result<()> {
    info!(tag = %cfg.tag, listen = %cfg.listen, "socks5 inbound listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        let cfg = cfg.clone();
        let router = router.clone();
        tokio::spawn(async move {
            if let Err(err) = handle(stream, peer, cfg, router).await {
                debug!(%peer, %err, "socks5 session failed");
            }
        });
    }
}

async fn handle(
    mut inbound: TcpStream,
    peer: SocketAddr,
    cfg: InboundConfig,
    router: Arc<Router>,
) -> anyhow::Result<()> {
    handshake(&mut inbound, &cfg).await?;
    match read_request(&mut inbound).await? {
        SocksRequest::Connect(target) => {
            let session = Session {
                inbound: cfg.tag,
                command: Command::Connect,
                target,
            };

            let mut outbound = router.dial(&session).await?;
            write_reply(&mut inbound, 0, TargetAddr::Ip(localhost(0))).await?;
            debug!(%peer, target = %session.target, "socks5 connected");
            copy_bidirectional(&mut inbound, &mut outbound).await?;
            Ok(())
        }
        SocksRequest::UdpAssociate(target) => {
            let session = Session {
                inbound: cfg.tag,
                command: Command::UdpAssociate,
                target,
            };
            let outbound = router.dial_udp(&session).await?;
            handle_udp_associate(inbound, peer, session, outbound).await
        }
    }
}

async fn handshake<S>(stream: &mut S, cfg: &InboundConfig) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ver = stream.read_u8().await?;
    if ver != 0x05 {
        bail!("invalid socks version {ver}");
    }
    let nmethods = stream.read_u8().await? as usize;
    let mut methods = vec![0; nmethods];
    stream.read_exact(&mut methods).await?;

    let needs_auth = cfg.users.as_ref().is_some_and(|users| !users.is_empty());
    let method = if needs_auth { 0x02 } else { 0x00 };
    if !methods.contains(&method) {
        stream.write_all(&[0x05, 0xff]).await?;
        bail!("client did not offer required auth method");
    }
    stream.write_all(&[0x05, method]).await?;
    if needs_auth {
        authenticate(stream, cfg).await?;
    }
    Ok(())
}

async fn authenticate<S>(stream: &mut S, cfg: &InboundConfig) -> anyhow::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ver = stream.read_u8().await?;
    if ver != 0x01 {
        bail!("invalid username/password auth version");
    }
    let ulen = stream.read_u8().await? as usize;
    let mut username = vec![0; ulen];
    stream.read_exact(&mut username).await?;
    let plen = stream.read_u8().await? as usize;
    let mut password = vec![0; plen];
    stream.read_exact(&mut password).await?;

    let username = String::from_utf8(username).context("username is not utf-8")?;
    let password = String::from_utf8(password).context("password is not utf-8")?;
    let ok = cfg.users.as_ref().is_some_and(|users| {
        users
            .iter()
            .any(|user| user.username == username && user.password == password)
    });
    stream
        .write_all(&[0x01, if ok { 0x00 } else { 0x01 }])
        .await?;
    if !ok {
        bail!("invalid socks5 credentials");
    }
    Ok(())
}

enum SocksRequest {
    Connect(TargetAddr),
    UdpAssociate(TargetAddr),
}

async fn read_request<S>(stream: &mut S) -> anyhow::Result<SocksRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ver = stream.read_u8().await?;
    let cmd = stream.read_u8().await?;
    let rsv = stream.read_u8().await?;
    if ver != 0x05 || rsv != 0 {
        bail!("invalid socks5 request");
    }

    let atyp = stream.read_u8().await?;
    let target = match atyp {
        codec::ATYP_IPV4 => {
            let mut octets = [0; 4];
            stream.read_exact(&mut octets).await?;
            let port = stream.read_u16().await?;
            TargetAddr::from((IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        codec::ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            let mut host = vec![0; len];
            stream.read_exact(&mut host).await?;
            let port = stream.read_u16().await?;
            TargetAddr::Domain {
                host: String::from_utf8(host).context("domain is not utf-8")?,
                port,
            }
        }
        codec::ATYP_IPV6 => {
            let mut octets = [0; 16];
            stream.read_exact(&mut octets).await?;
            let port = stream.read_u16().await?;
            TargetAddr::from((IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        other => bail!("unsupported address type {other}"),
    };
    match cmd {
        codec::CMD_CONNECT => Ok(SocksRequest::Connect(target)),
        codec::CMD_UDP_ASSOCIATE => Ok(SocksRequest::UdpAssociate(target)),
        other => bail!("unsupported socks5 command {other}"),
    }
}

async fn write_reply<S>(stream: &mut S, status: u8, bind: TargetAddr) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(&[codec::VERSION, status, 0]).await?;
    stream.write_all(&codec::encode_addr(&bind)?).await?;
    Ok(())
}

async fn handle_udp_associate(
    mut control: TcpStream,
    peer: SocketAddr,
    session: Session,
    outbound: BoxDatagram,
) -> anyhow::Result<()> {
    let bind = udp_bind_addr(control.local_addr()?);
    let socket = Arc::new(UdpSocket::bind(bind).await?);
    let reply = TargetAddr::Ip(udp_reply_addr(control.local_addr()?, socket.local_addr()?));
    write_reply(&mut control, 0, reply.clone()).await?;
    debug!(%peer, bind = %reply, "socks5 udp associated");

    let mut client_addr = None;
    let mut last_activity = Instant::now();
    let mut control_buf = [0; 1];
    let mut udp_buf = vec![0; 64 * 1024];
    loop {
        tokio::select! {
            read = control.read(&mut control_buf) => {
                match read {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {}
                }
            }
            received = outbound.recv_from() => {
                let (source, payload) = received?;
                let Some(client) = client_addr else {
                    continue;
                };
                let Ok(packet) = codec::encode_udp_packet(&source, &payload) else {
                    continue;
                };
                socket.send_to(&packet, client).await?;
                last_activity = Instant::now();
            }
            received = socket.recv_from(&mut udp_buf) => {
                let (read, client) = received?;
                if client_addr.is_none() {
                    client_addr = Some(client);
                }
                if client_addr != Some(client) {
                    continue;
                }
                match codec::decode_udp_packet(&udp_buf[..read]) {
                    Ok((target, payload)) => {
                        debug!(target = %target, inbound = %session.inbound, "socks5 udp packet");
                        outbound.send_to(&target, &payload).await?;
                        last_activity = Instant::now();
                    }
                    Err(err) => debug!(%err, "invalid socks5 udp packet"),
                }
            }
            _ = tokio::time::sleep_until(tokio::time::Instant::from_std(last_activity + UDP_ASSOCIATE_IDLE_TIMEOUT)) => {
                debug!(%peer, "socks5 udp associate idle timeout");
                break;
            }
        }
    }
    Ok(())
}

fn localhost(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn udp_bind_addr(control_addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(control_addr.ip(), 0)
}

fn udp_reply_addr(control_addr: SocketAddr, udp_addr: SocketAddr) -> SocketAddr {
    let ip = if udp_addr.ip().is_unspecified() {
        control_addr.ip()
    } else {
        udp_addr.ip()
    };
    SocketAddr::new(ip, udp_addr.port())
}
