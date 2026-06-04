use boring::ssl::SslRef;
use foreign_types::ForeignTypeRef;
use std::{
    collections::BTreeMap,
    io::Cursor,
    os::raw::{c_char, c_int, c_uchar},
};
use tuic_core::{
    Address, Authenticate, Connect, Dissociate, Header, Heartbeat, Packet as CorePacket,
};
use uuid::Uuid;

use crate::session::TargetAddr;

pub const VERSION: u8 = tuic_core::VERSION;
pub const CMD_AUTHENTICATE: u8 = Header::TYPE_CODE_AUTHENTICATE;
pub const CMD_CONNECT: u8 = Header::TYPE_CODE_CONNECT;
pub const CMD_PACKET: u8 = Header::TYPE_CODE_PACKET;
pub const CMD_DISSOCIATE: u8 = Header::TYPE_CODE_DISSOCIATE;
pub const CMD_HEARTBEAT: u8 = Header::TYPE_CODE_HEARTBEAT;
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

pub fn encode_authenticate(uuid: Uuid, token: [u8; TOKEN_LEN]) -> anyhow::Result<Vec<u8>> {
    marshal_header(Header::Authenticate(Authenticate::new(uuid, token)))
}

pub fn parse_authenticate(data: &[u8]) -> anyhow::Result<(Uuid, [u8; TOKEN_LEN])> {
    let (header, _) = parse_header(data)?;
    let Header::Authenticate(auth) = header else {
        anyhow::bail!(
            "unexpected tuic command {}, expected authenticate",
            header.type_code()
        );
    };
    Ok((auth.uuid(), auth.token()))
}

pub fn parse_connect(data: &[u8]) -> anyhow::Result<(TargetAddr, usize)> {
    let (header, consumed) = parse_header(data)?;
    let Header::Connect(connect) = header else {
        anyhow::bail!(
            "unexpected tuic command {}, expected connect",
            header.type_code()
        );
    };
    Ok((address_to_target(connect.addr())?, consumed))
}

pub fn encode_addr(target: &TargetAddr) -> anyhow::Result<Vec<u8>> {
    let encoded = marshal_header(Header::Connect(Connect::new(target_to_address(target)?)))?;
    Ok(encoded[2..].to_vec())
}

pub fn decode_addr(data: &[u8]) -> anyhow::Result<(TargetAddr, usize)> {
    let mut connect = Vec::with_capacity(2 + data.len());
    connect.push(VERSION);
    connect.push(CMD_CONNECT);
    connect.extend_from_slice(data);
    let (target, consumed) = parse_connect(&connect)?;
    Ok((target, consumed - 2))
}

pub fn encode_connect(target: &TargetAddr, payload: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut output = marshal_header(Header::Connect(Connect::new(target_to_address(target)?)))?;
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

    let addr = match packet.target.as_ref() {
        Some(target) => target_to_address(target)?,
        None => Address::None,
    };
    let header = Header::Packet(CorePacket::new(
        packet.assoc_id,
        packet.pkt_id,
        packet.frag_total,
        packet.frag_id,
        packet.payload.len() as u16,
        addr,
    ));
    let mut output = marshal_header(header)?;
    output.extend_from_slice(&packet.payload);
    Ok(output)
}

pub fn parse_packet(data: &[u8]) -> anyhow::Result<Packet> {
    let (header, payload_start) = parse_header(data)?;
    let Header::Packet(packet) = header else {
        anyhow::bail!(
            "unexpected tuic command {}, expected packet",
            header.type_code()
        );
    };
    anyhow::ensure!(
        packet.frag_total() > 0,
        "packet fragment total cannot be zero"
    );
    anyhow::ensure!(
        packet.frag_id() < packet.frag_total(),
        "packet fragment id exceeds fragment total"
    );
    let payload_end = payload_start
        .checked_add(packet.size() as usize)
        .ok_or_else(|| anyhow::anyhow!("tuic packet size overflow"))?;
    anyhow::ensure!(payload_end <= data.len(), "short tuic packet payload");
    Ok(Packet {
        assoc_id: packet.assoc_id(),
        pkt_id: packet.pkt_id(),
        frag_total: packet.frag_total(),
        frag_id: packet.frag_id(),
        target: address_to_optional_target(packet.addr())?,
        payload: data[payload_start..payload_end].to_vec(),
    })
}

pub fn encode_dissociate(assoc_id: u16) -> Vec<u8> {
    marshal_header(Header::Dissociate(Dissociate::new(assoc_id))).unwrap_or_else(|_| {
        let mut output = Vec::with_capacity(4);
        output.push(VERSION);
        output.push(CMD_DISSOCIATE);
        output.extend_from_slice(&assoc_id.to_be_bytes());
        output
    })
}

pub fn parse_dissociate(data: &[u8]) -> anyhow::Result<u16> {
    let (header, _) = parse_header(data)?;
    let Header::Dissociate(dissociate) = header else {
        anyhow::bail!(
            "unexpected tuic command {}, expected dissociate",
            header.type_code()
        );
    };
    Ok(dissociate.assoc_id())
}

pub fn encode_heartbeat() -> anyhow::Result<Vec<u8>> {
    marshal_header(Header::Heartbeat(Heartbeat::new()))
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

fn marshal_header(header: Header) -> anyhow::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(header.len());
    header.marshal(&mut output)?;
    Ok(output)
}

fn parse_header(data: &[u8]) -> anyhow::Result<(Header, usize)> {
    let mut cursor = Cursor::new(data);
    let header = Header::unmarshal(&mut cursor)?;
    Ok((header, cursor.position() as usize))
}

fn target_to_address(target: &TargetAddr) -> anyhow::Result<Address> {
    Ok(match target {
        TargetAddr::Domain { host, port } => {
            anyhow::ensure!(host.len() <= 255, "domain is too long");
            Address::DomainAddress(host.clone(), *port)
        }
        TargetAddr::Ip(addr) => Address::SocketAddress(*addr),
    })
}

fn address_to_target(address: &Address) -> anyhow::Result<TargetAddr> {
    match address {
        Address::DomainAddress(host, port) => Ok(TargetAddr::Domain {
            host: host.clone(),
            port: *port,
        }),
        Address::SocketAddress(addr) => Ok(TargetAddr::Ip(*addr)),
        Address::None => anyhow::bail!("empty address is not valid for TCP connect"),
    }
}

fn address_to_optional_target(address: &Address) -> anyhow::Result<Option<TargetAddr>> {
    match address {
        Address::None => Ok(None),
        other => Ok(Some(address_to_target(other)?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

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
    fn roundtrips_authenticate() {
        let uuid = Uuid::from_u128(1);
        let token = [7; TOKEN_LEN];

        let encoded = encode_authenticate(uuid, token).unwrap();
        let (decoded_uuid, decoded_token) = parse_authenticate(&encoded).unwrap();

        assert_eq!(encoded.len(), AUTHENTICATE_LEN);
        assert_eq!(decoded_uuid, uuid);
        assert_eq!(decoded_token, token);
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
