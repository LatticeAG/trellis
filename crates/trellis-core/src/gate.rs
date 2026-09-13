//! Kernel egress gate: the lease-map contract and the packet decision
//! function (spec §3.2).
//!
//! The eBPF program enforces exactly the decision procedure implemented by
//! `GateModel::check_packet` — reject by default when the map is missing,
//! the generation mismatches, denied=true, or boot_now >= lease_until; then
//! admit only IPv4/IHL=5/unfragmented/TCP packets to a permitted endpoint.
//! This is the executable reference model; on a certified host the compiled
//! BPF object (bpf/egress.c) is pinned per run and must agree verdict-for-
//! verdict with this model on the packet corpus.

use crate::schema::Endpoint;
use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop(DropReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// map state missing / generation mismatch / denied latch / expired lease
    Lease,
    NotIpv4,
    Ihl,
    Fragment,
    NotTcp,
    Malformed,
    Endpoint,
}

impl DropReason {
    pub fn metric_label(self) -> &'static str {
        match self {
            Self::Lease => "lease",
            Self::NotIpv4 => "not_ipv4",
            Self::Ihl => "ihl",
            Self::Fragment => "fragment",
            Self::NotTcp => "not_tcp",
            Self::Malformed => "malformed",
            Self::Endpoint => "endpoint",
        }
    }
}

/// Locked map value `{generation:u64, denied:u32, lease_until_ns:u64}` plus
/// the endpoint set, which is immutable for a run.
pub struct GateModel {
    pub generation: u64,
    pub denied: bool,
    pub lease_until_ns: u64,
    pub endpoints: BTreeSet<Endpoint>,
    /// denied-packet statistics map, by bounded reason.
    pub denied_packets: u64,
    /// When the kernel map is missing entirely the verdict is still DROP.
    pub map_present: bool,
}

impl GateModel {
    pub fn new(endpoints: BTreeSet<Endpoint>) -> Self {
        GateModel {
            generation: 1,
            denied: true,
            lease_until_ns: 0,
            endpoints,
            denied_packets: 0,
            map_present: true,
        }
    }

    /// Evaluate one outbound SKB. `boot_now_ns` is sampled before the lock
    /// (bpf_ktime_get_boot_ns); the comparison happens under the map lock.
    pub fn check_packet(&mut self, boot_now_ns: u64, pkt: &[u8]) -> Verdict {
        self.check_packet_gen(boot_now_ns, pkt, self.generation)
    }

    pub fn check_packet_gen(
        &mut self,
        boot_now_ns: u64,
        pkt: &[u8],
        pkt_generation: u64,
    ) -> Verdict {
        // Locked map read first.
        if !self.map_present
            || self.denied
            || pkt_generation != self.generation
            || boot_now_ns >= self.lease_until_ns
        {
            self.deny(DropReason::Lease);
            return Verdict::Drop(DropReason::Lease);
        }
        match classify(pkt) {
            Ok((dst, port)) => {
                if self.endpoints.contains(&Endpoint { ipv4: dst, port }) {
                    Verdict::Accept
                } else {
                    self.deny(DropReason::Endpoint);
                    Verdict::Drop(DropReason::Endpoint)
                }
            }
            Err(r) => {
                self.deny(r);
                Verdict::Drop(r)
            }
        }
    }

    fn deny(&mut self, _r: DropReason) {
        self.denied_packets = self.denied_packets.saturating_add(1);
    }
}

/// Parse an outbound frame: IPv4, IHL=5, unfragmented, TCP, structurally
/// valid. Returns (destination ip, destination port).
pub fn classify(pkt: &[u8]) -> Result<(u32, u16), DropReason> {
    if pkt.len() < 20 {
        return Err(DropReason::Malformed);
    }
    let vihl = pkt[0];
    if vihl >> 4 != 4 {
        return Err(DropReason::NotIpv4);
    }
    let ihl = vihl & 0x0F;
    if ihl != 5 {
        return Err(DropReason::Ihl);
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total_len < 40 || total_len > pkt.len() {
        return Err(DropReason::Malformed);
    }
    let flags_frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    if flags_frag & 0x3FFF != 0 {
        // MF set or nonzero fragment offset
        return Err(DropReason::Fragment);
    }
    if pkt[9] != 6 {
        return Err(DropReason::NotTcp);
    }
    // TCP header: need >= 20 bytes, data offset >= 5 words.
    let tcp = &pkt[20..total_len];
    if tcp.len() < 20 {
        return Err(DropReason::Malformed);
    }
    let data_off = tcp[12] >> 4;
    if data_off < 5 || (data_off as usize) * 4 > tcp.len() {
        return Err(DropReason::Malformed);
    }
    let dst = u32::from_be_bytes([pkt[16], pkt[17], pkt[18], pkt[19]]);
    let port = u16::from_be_bytes([tcp[2], tcp[3]]);
    Ok((dst, port))
}

/// The §13.1 packet() builder, used to produce exact test vectors.
pub fn test_packet(ip: u32, port: u16, proto_tcp: bool, ihl: u8, fragment: bool) -> Vec<u8> {
    let source = [10u8, 200, 0, 2];
    let target = ip.to_be_bytes();
    let mut transport: Vec<u8>;
    if proto_tcp {
        transport = vec![
            0x9C,
            0x40, // src port 40000
            (port >> 8) as u8,
            port as u8, // dst port
            0,
            0,
            0,
            0, // seq
            0,
            0,
            0,
            0, // ack
            0x50,
            0x02, // data offset 5, SYN
            0xFF,
            0xFF, // window
            0,
            0, // checksum
            0,
            0, // urg
        ];
        // checksum over pseudo-header
        let mut pseudo = Vec::new();
        pseudo.extend_from_slice(&source);
        pseudo.extend_from_slice(&target);
        pseudo.extend_from_slice(&[0, 6, (transport.len() >> 8) as u8, transport.len() as u8]);
        let c = checksum(&[pseudo, transport.clone()].concat());
        transport[16] = (c >> 8) as u8;
        transport[17] = c as u8;
    } else {
        transport = vec![0x9C, 0x40, (port >> 8) as u8, port as u8, 0, 8, 0, 0];
    }
    let options = vec![0u8; (ihl.saturating_sub(5) as usize) * 4];
    let mut header = Vec::new();
    header.push(0x40 + ihl);
    header.push(0);
    let tot = (ihl as usize) * 4 + transport.len();
    header.extend_from_slice(&(tot as u16).to_be_bytes());
    header.extend_from_slice(&1u16.to_be_bytes()); // id
    header.extend_from_slice(&(if fragment { 1u16 } else { 0u16 }).to_be_bytes());
    header.push(64); // ttl
    header.push(if proto_tcp { 6 } else { 17 });
    header.extend_from_slice(&0u16.to_be_bytes()); // checksum
    header.extend_from_slice(&source);
    header.extend_from_slice(&target);
    header.extend_from_slice(&options);
    let c = checksum(&header);
    header[10] = (c >> 8) as u8;
    header[11] = c as u8;
    let mut out = header;
    out.extend_from_slice(&transport);
    out
}

fn checksum(data: &[u8]) -> u16 {
    let mut d = data.to_vec();
    if d.len() % 2 == 1 {
        d.push(0);
    }
    let mut total: u32 = 0;
    for w in d.chunks_exact(2) {
        total += u16::from_be_bytes([w[0], w[1]]) as u32;
    }
    while total >> 16 != 0 {
        total = (total & 0xFFFF) + (total >> 16);
    }
    !(total as u16)
}
