#![allow(dead_code)]

use boring::ssl::SslRef;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use uuid::Uuid;

use crate::{protocol::addr, session::TargetAddr};

pub const VERSION: u8 = 0x05;
pub const CMD_AUTHENTICATE: u8 = 0x00;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_PACKET: u8 = 0x02;
pub const CMD_DISSOCIATE: u8 = 0x03;
pub const CMD_HEARTBEAT: u8 = 0x04;
const TOKEN_LEN: usize = 32;

pub fn token(ssl: &SslRef, uuid: Uuid, password: &str) -> anyhow::Result<[u8; TOKEN_LEN]> {
    let mut token = [0; TOKEN_LEN];
    ssl.export_keying_material(
        &mut token,
        uuid.hyphenated().to_string().as_str(),
        Some(password.as_bytes()),
    )?;
    Ok(token)
}

pub async fn write_authenticate<S>(
    stream: &mut S,
    uuid: Uuid,
    token: &[u8; TOKEN_LEN],
) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_u8(VERSION).await?;
    stream.write_u8(CMD_AUTHENTICATE).await?;
    stream.write_all(uuid.as_bytes()).await?;
    stream.write_all(token).await?;
    Ok(())
}

pub async fn read_authenticate<S>(stream: &mut S) -> anyhow::Result<(Uuid, [u8; TOKEN_LEN])>
where
    S: AsyncRead + Unpin,
{
    expect_type(stream, CMD_AUTHENTICATE).await?;
    let mut uuid = [0; 16];
    stream.read_exact(&mut uuid).await?;
    let mut token = [0; TOKEN_LEN];
    stream.read_exact(&mut token).await?;
    Ok((Uuid::from_bytes(uuid), token))
}

pub async fn write_connect<S>(stream: &mut S, target: &TargetAddr) -> anyhow::Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_u8(VERSION).await?;
    stream.write_u8(CMD_CONNECT).await?;
    addr::write_addr(stream, target).await?;
    Ok(())
}

pub async fn read_connect<S>(stream: &mut S) -> anyhow::Result<TargetAddr>
where
    S: AsyncRead + Unpin,
{
    expect_type(stream, CMD_CONNECT).await?;
    addr::read_addr(stream).await
}

async fn expect_type<S>(stream: &mut S, expected: u8) -> anyhow::Result<()>
where
    S: AsyncRead + Unpin,
{
    let version = stream.read_u8().await?;
    anyhow::ensure!(version == VERSION, "unsupported tuic version {version}");
    let command = stream.read_u8().await?;
    anyhow::ensure!(command == expected, "unexpected tuic command {command}");
    Ok(())
}
