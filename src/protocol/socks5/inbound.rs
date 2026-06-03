use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use anyhow::{Context, bail};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
};
use tracing::{debug, info};

use crate::{
    config::InboundConfig,
    router::Router,
    session::{Command, Session, TargetAddr},
};

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
    let target = read_request(&mut inbound).await?;
    let session = Session {
        inbound: cfg.tag,
        command: Command::Connect,
        target,
    };

    let mut outbound = router.dial(&session).await?;
    inbound
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await?;
    debug!(%peer, target = %session.target, "socks5 connected");
    copy_bidirectional(&mut inbound, &mut outbound).await?;
    Ok(())
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

async fn read_request<S>(stream: &mut S) -> anyhow::Result<TargetAddr>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let ver = stream.read_u8().await?;
    let cmd = stream.read_u8().await?;
    let rsv = stream.read_u8().await?;
    if ver != 0x05 || rsv != 0 {
        bail!("invalid socks5 request");
    }
    if cmd != 0x01 {
        bail!("only CONNECT is supported in the MVP");
    }

    let atyp = stream.read_u8().await?;
    let target = match atyp {
        0x01 => {
            let mut octets = [0; 4];
            stream.read_exact(&mut octets).await?;
            let port = stream.read_u16().await?;
            TargetAddr::from((IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        0x03 => {
            let len = stream.read_u8().await? as usize;
            let mut host = vec![0; len];
            stream.read_exact(&mut host).await?;
            let port = stream.read_u16().await?;
            TargetAddr::Domain {
                host: String::from_utf8(host).context("domain is not utf-8")?,
                port,
            }
        }
        0x04 => {
            let mut octets = [0; 16];
            stream.read_exact(&mut octets).await?;
            let port = stream.read_u16().await?;
            TargetAddr::from((IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        other => bail!("unsupported address type {other}"),
    };
    Ok(target)
}
