use std::{
    io::{Cursor, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use crate::session::TargetAddr;

pub const VERSION: u8 = 0x05;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_UDP_ASSOCIATE: u8 = 0x03;
pub const ATYP_IPV4: u8 = 0x01;
pub const ATYP_DOMAIN: u8 = 0x03;
pub const ATYP_IPV6: u8 = 0x04;

pub fn encode_addr(target: &TargetAddr) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::new();
    match target {
        TargetAddr::Ip(addr) if addr.is_ipv4() => {
            output.push(ATYP_IPV4);
            if let IpAddr::V4(ip) = addr.ip() {
                output.extend_from_slice(&ip.octets());
            }
            output.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Ip(addr) => {
            output.push(ATYP_IPV6);
            if let IpAddr::V6(ip) = addr.ip() {
                output.extend_from_slice(&ip.octets());
            }
            output.extend_from_slice(&addr.port().to_be_bytes());
        }
        TargetAddr::Domain { host, port } => {
            anyhow::ensure!(host.len() <= 255, "domain is too long for socks5");
            output.push(ATYP_DOMAIN);
            output.push(host.len() as u8);
            output.extend_from_slice(host.as_bytes());
            output.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(output)
}

pub fn decode_addr(data: &[u8]) -> anyhow::Result<(TargetAddr, usize)> {
    let mut cursor = Cursor::new(data);
    let atyp = read_u8(&mut cursor)?;
    let target = match atyp {
        ATYP_IPV4 => {
            let mut octets = [0; 4];
            Read::read_exact(&mut cursor, &mut octets)?;
            let port = read_u16(&mut cursor)?;
            TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::from(octets)), port))
        }
        ATYP_DOMAIN => {
            let len = read_u8(&mut cursor)? as usize;
            let mut host = vec![0; len];
            Read::read_exact(&mut cursor, &mut host)?;
            let port = read_u16(&mut cursor)?;
            TargetAddr::Domain {
                host: String::from_utf8(host)?,
                port,
            }
        }
        ATYP_IPV6 => {
            let mut octets = [0; 16];
            Read::read_exact(&mut cursor, &mut octets)?;
            let port = read_u16(&mut cursor)?;
            TargetAddr::Ip(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port))
        }
        other => anyhow::bail!("unsupported socks5 address type {other}"),
    };
    Ok((target, cursor.position() as usize))
}

pub fn encode_udp_packet(target: &TargetAddr, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(3 + 259 + payload.len());
    output.extend_from_slice(&[0, 0, 0]);
    output.extend_from_slice(&encode_addr(target)?);
    output.extend_from_slice(payload);
    Ok(output)
}

pub fn decode_udp_packet(data: &[u8]) -> anyhow::Result<(TargetAddr, Vec<u8>)> {
    anyhow::ensure!(data.len() >= 4, "short socks5 udp packet");
    anyhow::ensure!(
        data[0] == 0 && data[1] == 0,
        "invalid socks5 udp reserved bytes"
    );
    anyhow::ensure!(
        data[2] == 0,
        "fragmented socks5 udp packets are not supported"
    );
    let (target, consumed) = decode_addr(&data[3..])?;
    Ok((target, data[3 + consumed..].to_vec()))
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
    fn roundtrips_udp_packet() {
        let target = TargetAddr::Ip(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 53));
        let encoded = encode_udp_packet(&target, b"dns").unwrap();
        let (decoded_target, payload) = decode_udp_packet(&encoded).unwrap();

        assert_eq!(decoded_target, target);
        assert_eq!(payload, b"dns");
    }
}
