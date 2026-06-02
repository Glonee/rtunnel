use boring::ssl::SslRef;
use std::{
    io::{Cursor, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use uuid::Uuid;

use crate::session::TargetAddr;

pub const VERSION: u8 = 0x05;
pub const CMD_AUTHENTICATE: u8 = 0x00;
pub const CMD_CONNECT: u8 = 0x01;
#[allow(dead_code)]
pub const CMD_PACKET: u8 = 0x02;
#[allow(dead_code)]
pub const CMD_DISSOCIATE: u8 = 0x03;
pub const CMD_HEARTBEAT: u8 = 0x04;
pub const TOKEN_LEN: usize = 32;
pub const AUTHENTICATE_LEN: usize = 2 + 16 + TOKEN_LEN;

pub fn token(ssl: &SslRef, uuid: Uuid, password: &str) -> anyhow::Result<[u8; TOKEN_LEN]> {
    let mut token = [0; TOKEN_LEN];
    let label = unsafe { std::str::from_utf8_unchecked(uuid.as_bytes()) };
    ssl.export_keying_material(&mut token, label, Some(password.as_bytes()))?;
    Ok(token)
}

pub fn parse_authenticate(data: &[u8]) -> anyhow::Result<(Uuid, [u8; TOKEN_LEN])> {
    anyhow::ensure!(data.len() >= AUTHENTICATE_LEN, "short tuic authenticate");
    anyhow::ensure!(data[0] == VERSION, "unsupported tuic version {}", data[0]);
    anyhow::ensure!(
        data[1] == CMD_AUTHENTICATE,
        "unexpected tuic command {}",
        data[1]
    );
    let mut uuid = [0; 16];
    uuid.copy_from_slice(&data[2..18]);
    let mut token = [0; TOKEN_LEN];
    token.copy_from_slice(&data[18..50]);
    Ok((Uuid::from_bytes(uuid), token))
}

pub fn parse_connect(data: &[u8]) -> anyhow::Result<(TargetAddr, usize)> {
    anyhow::ensure!(data.len() >= 2, "short tuic connect");
    anyhow::ensure!(data[0] == VERSION, "unsupported tuic version {}", data[0]);
    anyhow::ensure!(
        data[1] == CMD_CONNECT,
        "unexpected tuic command {}",
        data[1]
    );
    decode_addr(&data[2..]).map(|(target, consumed)| (target, consumed + 2))
}

#[allow(dead_code)]
pub fn encode_addr(target: &TargetAddr) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::new();
    match target {
        TargetAddr::Domain { host, port } => {
            anyhow::ensure!(host.len() <= 255, "domain is too long");
            output.push(0x00);
            output.push(host.len() as u8);
            output.extend_from_slice(host.as_bytes());
            output.extend_from_slice(&port.to_be_bytes());
        }
        TargetAddr::Ip(addr) if addr.is_ipv4() => {
            output.push(0x01);
            if let IpAddr::V4(ip) = addr.ip() {
                output.extend_from_slice(&ip.octets());
            }
            output.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Ip(addr) => {
            output.push(0x02);
            if let IpAddr::V6(ip) = addr.ip() {
                output.extend_from_slice(&ip.octets());
            }
            output.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    Ok(output)
}

#[allow(dead_code)]
pub fn encode_connect(target: &TargetAddr, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(2 + 259 + payload.len());
    output.push(VERSION);
    output.push(CMD_CONNECT);
    output.extend_from_slice(&encode_addr(target)?);
    output.extend_from_slice(payload);
    Ok(output)
}

pub fn decode_addr(data: &[u8]) -> anyhow::Result<(TargetAddr, usize)> {
    let mut cursor = Cursor::new(data);
    let atyp = read_u8(&mut cursor)?;
    let target = match atyp {
        0x00 => {
            let len = read_u8(&mut cursor)? as usize;
            let mut host = vec![0; len];
            Read::read_exact(&mut cursor, &mut host)?;
            let port = read_u16(&mut cursor)?;
            TargetAddr::Domain {
                host: String::from_utf8(host)?,
                port,
            }
        }
        0x01 => {
            let mut octets = [0; 4];
            Read::read_exact(&mut cursor, &mut octets)?;
            let port = read_u16(&mut cursor)?;
            TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        0x02 => {
            let mut octets = [0; 16];
            Read::read_exact(&mut cursor, &mut octets)?;
            let port = read_u16(&mut cursor)?;
            TargetAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        0xff => anyhow::bail!("empty address is not valid for TCP connect"),
        other => anyhow::bail!("unknown tuic address family {other}"),
    };
    Ok((target, cursor.position() as usize))
}

fn read_u8(cursor: &mut Cursor<&[u8]>) -> anyhow::Result<u8> {
    let mut buf = [0; 1];
    Read::read_exact(cursor, &mut buf)?;
    Ok(buf[0])
}

fn read_u16(cursor: &mut Cursor<&[u8]>) -> anyhow::Result<u16> {
    let mut buf = [0; 2];
    Read::read_exact(cursor, &mut buf)?;
    Ok(u16::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_connect_target() {
        let raw = [VERSION, CMD_CONNECT, 0x01, 127, 0, 0, 1, 0x4a, 0x38];
        let (target, consumed) = parse_connect(&raw).unwrap();

        assert_eq!(target.to_string(), "127.0.0.1:19000");
        assert_eq!(consumed, raw.len());
    }
}
