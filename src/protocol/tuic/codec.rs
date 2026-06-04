use boring::ssl::SslRef;
use foreign_types::ForeignTypeRef;
use std::{
    collections::BTreeMap,
    io::{Cursor, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::raw::{c_char, c_int, c_uchar},
};
use uuid::Uuid;

use crate::session::TargetAddr;

pub const VERSION: u8 = 0x05;
pub const CMD_AUTHENTICATE: u8 = 0x00;
pub const CMD_CONNECT: u8 = 0x01;
pub const CMD_PACKET: u8 = 0x02;
pub const CMD_DISSOCIATE: u8 = 0x03;
pub const CMD_HEARTBEAT: u8 = 0x04;
pub const TOKEN_LEN: usize = 32;
pub const AUTHENTICATE_LEN: usize = 2 + 16 + TOKEN_LEN;

unsafe extern "C" {
    fn SSL_export_keying_material(
        ssl: *mut boring_sys::SSL,
        out: *mut c_uchar,
        olen: usize,
        label: *const c_char,
        llen: usize,
        context: *const c_uchar,
        contextlen: usize,
        use_context: c_int,
    ) -> c_int;
}

pub fn token(ssl: &SslRef, uuid: Uuid, password: &str) -> anyhow::Result<[u8; TOKEN_LEN]> {
    let mut token = [0; TOKEN_LEN];
    export_keying_material_raw_label(&mut token, ssl, uuid.as_bytes(), password.as_bytes())?;
    Ok(token)
}

fn export_keying_material_raw_label(
    out: &mut [u8],
    ssl: &SslRef,
    label: &[u8],
    context: &[u8],
) -> anyhow::Result<()> {
    let ok = unsafe {
        SSL_export_keying_material(
            ssl.as_ptr(),
            out.as_mut_ptr(),
            out.len(),
            label.as_ptr().cast(),
            label.len(),
            context.as_ptr(),
            context.len(),
            1,
        )
    };
    anyhow::ensure!(ok == 1, "failed to export TUIC token");
    Ok(())
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

pub fn encode_connect(target: &TargetAddr, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(2 + 259 + payload.len());
    output.push(VERSION);
    output.push(CMD_CONNECT);
    output.extend_from_slice(&encode_addr(target)?);
    output.extend_from_slice(payload);
    Ok(output)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Packet {
    pub assoc_id: u16,
    pub pkt_id: u16,
    pub frag_total: u8,
    pub frag_id: u8,
    pub target: Option<TargetAddr>,
    pub payload: Vec<u8>,
}

pub fn encode_packet(packet: &Packet) -> anyhow::Result<Vec<u8>> {
    anyhow::ensure!(
        packet.frag_total > 0,
        "packet fragment total cannot be zero"
    );
    anyhow::ensure!(
        packet.frag_id < packet.frag_total,
        "packet fragment id exceeds fragment total"
    );
    anyhow::ensure!(
        packet.payload.len() <= u16::MAX as usize,
        "tuic packet fragment is too large"
    );

    let mut output = Vec::with_capacity(10 + 259 + packet.payload.len());
    output.push(VERSION);
    output.push(CMD_PACKET);
    output.extend_from_slice(&packet.assoc_id.to_be_bytes());
    output.extend_from_slice(&packet.pkt_id.to_be_bytes());
    output.push(packet.frag_total);
    output.push(packet.frag_id);
    output.extend_from_slice(&(packet.payload.len() as u16).to_be_bytes());
    if let Some(target) = &packet.target {
        output.extend_from_slice(&encode_addr(target)?);
    } else {
        output.push(0xff);
    }
    output.extend_from_slice(&packet.payload);
    Ok(output)
}

pub fn parse_packet(data: &[u8]) -> anyhow::Result<Packet> {
    anyhow::ensure!(data.len() >= 10, "short tuic packet");
    anyhow::ensure!(data[0] == VERSION, "unsupported tuic version {}", data[0]);
    anyhow::ensure!(data[1] == CMD_PACKET, "unexpected tuic command {}", data[1]);
    let mut cursor = Cursor::new(&data[2..]);
    let assoc_id = read_u16(&mut cursor)?;
    let pkt_id = read_u16(&mut cursor)?;
    let frag_total = read_u8(&mut cursor)?;
    let frag_id = read_u8(&mut cursor)?;
    let size = read_u16(&mut cursor)? as usize;
    anyhow::ensure!(frag_total > 0, "packet fragment total cannot be zero");
    anyhow::ensure!(
        frag_id < frag_total,
        "packet fragment id exceeds fragment total"
    );

    let addr_start = 2 + cursor.position() as usize;
    let (target, consumed) = decode_optional_addr(&data[addr_start..])?;
    let payload_start = addr_start + consumed;
    let payload_end = payload_start
        .checked_add(size)
        .ok_or_else(|| anyhow::anyhow!("tuic packet size overflow"))?;
    anyhow::ensure!(payload_end <= data.len(), "short tuic packet payload");
    Ok(Packet {
        assoc_id,
        pkt_id,
        frag_total,
        frag_id,
        target,
        payload: data[payload_start..payload_end].to_vec(),
    })
}

pub fn encode_dissociate(assoc_id: u16) -> Vec<u8> {
    let mut output = Vec::with_capacity(4);
    output.push(VERSION);
    output.push(CMD_DISSOCIATE);
    output.extend_from_slice(&assoc_id.to_be_bytes());
    output
}

pub fn parse_dissociate(data: &[u8]) -> anyhow::Result<u16> {
    anyhow::ensure!(data.len() >= 4, "short tuic dissociate");
    anyhow::ensure!(data[0] == VERSION, "unsupported tuic version {}", data[0]);
    anyhow::ensure!(
        data[1] == CMD_DISSOCIATE,
        "unexpected tuic command {}",
        data[1]
    );
    Ok(u16::from_be_bytes([data[2], data[3]]))
}

#[derive(Default)]
pub struct PacketAssembler {
    fragments: BTreeMap<(u16, u16), FragmentedPacket>,
}

impl PacketAssembler {
    pub fn push(&mut self, packet: Packet) -> anyhow::Result<Option<Packet>> {
        if packet.frag_total == 1 {
            anyhow::ensure!(
                packet.target.is_some(),
                "single-fragment packet missing target"
            );
            return Ok(Some(packet));
        }

        let key = (packet.assoc_id, packet.pkt_id);
        let entry = self
            .fragments
            .entry(key)
            .or_insert_with(|| FragmentedPacket {
                assoc_id: packet.assoc_id,
                pkt_id: packet.pkt_id,
                frag_total: packet.frag_total,
                target: None,
                fragments: BTreeMap::new(),
            });
        anyhow::ensure!(
            entry.frag_total == packet.frag_total,
            "fragment total changed within packet"
        );
        if packet.frag_id == 0 {
            entry.target = packet.target.clone();
        }
        entry.fragments.insert(packet.frag_id, packet.payload);

        if entry.fragments.len() != entry.frag_total as usize {
            return Ok(None);
        }
        let Some(target) = entry.target.clone() else {
            return Ok(None);
        };
        let mut payload = Vec::new();
        for frag_id in 0..entry.frag_total {
            let Some(fragment) = entry.fragments.remove(&frag_id) else {
                return Ok(None);
            };
            payload.extend_from_slice(&fragment);
        }
        let complete = Packet {
            assoc_id: entry.assoc_id,
            pkt_id: entry.pkt_id,
            frag_total: 1,
            frag_id: 0,
            target: Some(target),
            payload,
        };
        self.fragments.remove(&key);
        Ok(Some(complete))
    }
}

struct FragmentedPacket {
    assoc_id: u16,
    pkt_id: u16,
    frag_total: u8,
    target: Option<TargetAddr>,
    fragments: BTreeMap<u8, Vec<u8>>,
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

fn decode_optional_addr(data: &[u8]) -> anyhow::Result<(Option<TargetAddr>, usize)> {
    let Some(atyp) = data.first() else {
        anyhow::bail!("missing tuic address family");
    };
    if *atyp == 0xff {
        return Ok((None, 1));
    }
    decode_addr(data).map(|(target, consumed)| (Some(target), consumed))
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

    #[test]
    fn roundtrips_packet() {
        let packet = Packet {
            assoc_id: 7,
            pkt_id: 9,
            frag_total: 1,
            frag_id: 0,
            target: Some(TargetAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), 19000))),
            payload: b"hello".to_vec(),
        };

        let encoded = encode_packet(&packet).unwrap();
        let decoded = parse_packet(&encoded).unwrap();

        assert_eq!(decoded, packet);
    }

    #[test]
    fn reassembles_packet_fragments() {
        let mut assembler = PacketAssembler::default();
        let target = TargetAddr::from((IpAddr::V4(Ipv4Addr::LOCALHOST), 19000));
        assert!(
            assembler
                .push(Packet {
                    assoc_id: 1,
                    pkt_id: 2,
                    frag_total: 2,
                    frag_id: 1,
                    target: None,
                    payload: b"lo".to_vec(),
                })
                .unwrap()
                .is_none()
        );
        let packet = assembler
            .push(Packet {
                assoc_id: 1,
                pkt_id: 2,
                frag_total: 2,
                frag_id: 0,
                target: Some(target.clone()),
                payload: b"hel".to_vec(),
            })
            .unwrap()
            .unwrap();

        assert_eq!(packet.target, Some(target));
        assert_eq!(packet.payload, b"hello");
    }
}
