//! Test helper for tests/netns.sh: inspect a pcap captured at the relay.
//!
//! usage:
//!   pcap_check <relay.pcap> <relay_ip:port> <relay_sk_b64> <dest_sk_b64> [marker_hex]
//!   pcap_check --initiators <any.pcap> <responder_sk_b64>
//!
//! The second form prints (base64, one per line) the static public key of every
//! initiator whose handshake initiation to the responder appears in the capture.
//!
//! The first form checks that (1) forwarded handshake initiations cannot be opened with the
//! relay's key but can with the destination node's key (positive control),
//! (2) forwarded datagrams leave the relay byte-for-byte identical to how they
//! arrived, and (3) an optional plaintext marker never appears on the wire.

use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::{Packet, Tunn};
use std::collections::HashMap;
use std::error::Error as _;
use std::net::{AddrParseError, Ipv4Addr, SocketAddrV4};
use std::path::PathBuf;
use std::process::ExitCode;
use wg_relay::key::{KeyError, PeerKey, PrivateKey};
use wg_relay::packet;
use x25519_dalek::{PublicKey, StaticSecret};

const USAGE: &str = "usage: pcap_check <pcap> <relay_ip:port> <relay_sk_b64> <dest_sk_b64> [marker_hex]\n\
                     \x20      pcap_check --initiators <pcap> <responder_sk_b64>";

#[derive(Debug, thiserror::Error)]
enum CheckError {
    #[error("wrong arguments")]
    Usage,
    #[error("failed to read {path}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("not a little-endian pcap file")]
    NotPcap,
    #[error("unsupported pcap link type {0}")]
    LinkType(u32),
    #[error("invalid {arg} key")]
    Key {
        arg: &'static str,
        #[source]
        source: KeyError,
    },
    #[error("invalid relay address")]
    Addr(#[from] AddrParseError),
    #[error("marker must be an even-length hex string, got {0:?}")]
    Marker(String),
}

struct Udp {
    src: SocketAddrV4,
    dst: SocketAddrV4,
    payload: Vec<u8>,
}

fn read_pcap(path: &str) -> Result<Vec<Udp>, CheckError> {
    let bytes =
        std::fs::read(path).map_err(|source| CheckError::Read { path: path.into(), source })?;
    parse_pcap(&bytes)
}

fn parse_pcap(b: &[u8]) -> Result<Vec<Udp>, CheckError> {
    let u32le = |o: usize| b.get(o..o + 4).and_then(|s| s.try_into().ok()).map(u32::from_le_bytes);
    if !matches!(u32le(0), Some(0xa1b2_c3d4 | 0xa1b2_3c4d)) {
        return Err(CheckError::NotPcap);
    }
    let l2 = match u32le(20).ok_or(CheckError::NotPcap)? {
        1 => 14,   // Ethernet
        113 => 16, // Linux cooked v1
        276 => 20, // Linux cooked v2
        101 => 0,  // raw IP
        t => return Err(CheckError::LinkType(t)),
    };
    let (mut off, mut out) = (24, Vec::new());
    while let Some(caplen) = u32le(off + 8) {
        let caplen = caplen as usize;
        let Some(frame) = b.get(off + 16..off + 16 + caplen) else { break };
        off += 16 + caplen;
        let Some(ip) = frame.get(l2..) else { continue };
        if ip.len() < 28 || ip[0] >> 4 != 4 || ip[9] != 17 {
            continue;
        }
        let ihl = usize::from(ip[0] & 15) * 4;
        let total = usize::from(u16::from_be_bytes([ip[2], ip[3]])).min(ip.len());
        let Some(udp) = ip.get(ihl..total).filter(|u| u.len() >= 8) else { continue };
        let a = |o: usize| Ipv4Addr::new(ip[o], ip[o + 1], ip[o + 2], ip[o + 3]);
        let port = |o: usize| u16::from_be_bytes([udp[o], udp[o + 1]]);
        out.push(Udp {
            src: SocketAddrV4::new(a(12), port(0)),
            dst: SocketAddrV4::new(a(16), port(2)),
            payload: udp[8..].to_vec(),
        });
    }
    Ok(out)
}

fn secret(arg: &'static str, b64: &str) -> Result<StaticSecret, CheckError> {
    b64.parse::<PrivateKey>()
        .map(|k| k.secret().clone())
        .map_err(|source| CheckError::Key { arg, source })
}

fn parse_marker(hex: &str) -> Result<Vec<u8>, CheckError> {
    let byte = |c: &[u8]| std::str::from_utf8(c).ok().and_then(|s| u8::from_str_radix(s, 16).ok());
    let bytes: Option<Vec<u8>> =
        hex.as_bytes().chunks(2).map(|c| byte(c).filter(|_| c.len() == 2)).collect();
    bytes.ok_or_else(|| CheckError::Marker(hex.to_owned()))
}

/// Print the initiator static keys of all initiations the responder can open.
fn initiators(pcap: &str, responder_sk: &str) -> Result<bool, CheckError> {
    let sk = secret("responder", responder_sk)?;
    let pk = PublicKey::from(&sk);
    let mut seen = std::collections::BTreeSet::new();
    for p in read_pcap(pcap)? {
        if let Ok(Packet::HandshakeInit(h)) = Tunn::parse_incoming_packet(&p.payload)
            && let Ok(half) = parse_handshake_anon(&sk, &pk, &h)
        {
            seen.insert(PeerKey::from(half.peer_static_public).to_string());
        }
    }
    seen.iter().for_each(|k| println!("{k}"));
    Ok(true)
}

/// Run the relay capture checks; Ok(false) means a check failed.
fn verify(args: &[String]) -> Result<bool, CheckError> {
    let [pcap, relay, relay_sk, dest_sk, rest @ ..] = args else { return Err(CheckError::Usage) };
    let relay: SocketAddrV4 = relay.parse()?;
    let (relay_sk, dest_sk) = (secret("relay", relay_sk)?, secret("destination", dest_sk)?);
    let (relay_pk, dest_pk) = (PublicKey::from(&relay_sk), PublicKey::from(&dest_sk));
    let relay_mac1 = packet::mac1_key(relay_pk.as_bytes());
    let marker = match rest {
        [] => None,
        [hex] => Some(parse_marker(hex)?),
        _ => return Err(CheckError::Usage),
    };

    let pkts = read_pcap(pcap)?;
    let (mut fwd_inits, mut opened_relay, mut opened_dest, mut marker_hits) = (0, 0, 0, 0);
    // payload -> addresses it arrived at the relay from
    let mut inbound: HashMap<&[u8], Vec<SocketAddrV4>> = HashMap::new();
    for p in &pkts {
        if let Some(m) = &marker {
            marker_hits += p.payload.windows(m.len()).filter(|w| w == m).count();
        }
        if p.dst == relay {
            inbound.entry(&p.payload).or_default().push(p.src);
        }
        let is_fwd_init = p.dst == relay
            && p.payload.first() == Some(&1)
            && !packet::mac1_matches(&relay_mac1, &p.payload);
        if let (true, Ok(Packet::HandshakeInit(h))) =
            (is_fwd_init, Tunn::parse_incoming_packet(&p.payload))
        {
            fwd_inits += 1;
            opened_relay += parse_handshake_anon(&relay_sk, &relay_pk, &h).is_ok() as u32;
            opened_dest += parse_handshake_anon(&dest_sk, &dest_pk, &h).is_ok() as u32;
        }
    }
    let mut identical = [0u32; 5];
    for p in pkts.iter().filter(|p| p.src == relay) {
        let came_from_elsewhere =
            inbound.get(p.payload.as_slice()).is_some_and(|v| v.iter().any(|s| *s != p.dst));
        if came_from_elsewhere {
            identical[usize::from(p.payload[0]).min(4)] += 1;
        }
    }
    println!("udp packets captured:                {}", pkts.len());
    println!("initiations to peers (inbound):      {fwd_inits}");
    println!("  opened with relay key:             {opened_relay}");
    println!("  opened with destination key:       {opened_dest}");
    println!("forwarded byte-identical (init/resp/cookie/data): {:?}", &identical[1..]);
    println!("plaintext marker occurrences:        {marker_hits}");
    let ok = fwd_inits > 0
        && opened_relay == 0
        && opened_dest > 0
        && identical[4] > 0
        && marker_hits == 0;
    println!("{}", if ok { "PCAP CHECK PASSED" } else { "PCAP CHECK FAILED" });
    Ok(ok)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.as_slice() {
        [flag, pcap, sk] if flag == "--initiators" => initiators(pcap, sk),
        args => verify(args),
    };
    match result {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(CheckError::Usage) => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
        Err(e) => {
            eprint!("error: {e}");
            let mut source = e.source();
            while let Some(s) = source {
                eprint!(": {s}");
                source = s.source();
            }
            eprintln!();
            ExitCode::FAILURE
        }
    }
}
