use std::collections::HashMap;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::ingest::ParsedPacket;
use crate::models::*;

const FLOW_TIMEOUT_SECS: i64 = 120;

pub struct SessionManager {
    flows: HashMap<FlowKey, FlowState>,
}

struct FlowState {
    id: String,
    key: FlowKey,
    start_time: DateTime<Utc>,
    last_seen: DateTime<Utc>,
    packet_count: u64,
    byte_count: u64,
    fwd_packets: u64,
    rev_packets: u64,
    fwd_bytes: u64,
    rev_bytes: u64,
    flags: FlowFlags,
    detected_protocol: Option<AppProtocol>,
    tcp: Option<TcpState>,
    segments: Vec<StreamSegment>,
}

struct TcpState {
    /// true = the "forward" canonical direction is the actual TCP client (SYN sender)
    /// false = the "reverse" canonical direction is the client
    /// None = not yet determined
    client_is_forward: Option<bool>,
    client_next_seq: u32,
    server_next_seq: u32,
    client_seq_init: bool,
    server_seq_init: bool,
    client_buf: ReorderBuffer,
    server_buf: ReorderBuffer,
    handshake: Handshake,
    retransmits: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Handshake {
    None,
    SynSeen,
    SynAckSeen,
    Established,
    Closing,
}

struct ReorderBuffer {
    segments: Vec<BufSeg>,
}

struct BufSeg {
    seq: u32,
    data: Vec<u8>,
    ts: DateTime<Utc>,
}

impl ReorderBuffer {
    fn new() -> Self { Self { segments: Vec::new() } }

    fn insert(&mut self, seq: u32, data: Vec<u8>, ts: DateTime<Utc>) {
        if self.segments.len() >= 8192 { return; }
        let pos = self.segments.binary_search_by_key(&seq, |s| s.seq).unwrap_or_else(|p| p);
        self.segments.insert(pos, BufSeg { seq, data, ts });
    }

    fn drain(&mut self, next: &mut u32) -> Vec<(Vec<u8>, DateTime<Utc>)> {
        let mut out = Vec::new();
        loop {
            if self.segments.is_empty() { break; }
            let front = self.segments[0].seq;
            if front == *next {
                let s = self.segments.remove(0);
                *next = next.wrapping_add(s.data.len() as u32);
                out.push((s.data, s.ts));
            } else if seq_lt(front, *next) {
                self.segments.remove(0);
            } else {
                break;
            }
        }
        out
    }
}

impl TcpState {
    fn new() -> Self {
        Self {
            client_is_forward: None,
            client_next_seq: 0,
            server_next_seq: 0,
            client_seq_init: false,
            server_seq_init: false,
            client_buf: ReorderBuffer::new(),
            server_buf: ReorderBuffer::new(),
            handshake: Handshake::None,
            retransmits: 0,
        }
    }

    /// Determine if this packet is from the client or server.
    fn is_client(&self, is_fwd: bool) -> bool {
        match self.client_is_forward {
            Some(true) => is_fwd,
            Some(false) => !is_fwd,
            None => is_fwd, // default before determined
        }
    }
}

impl SessionManager {
    pub fn new() -> Self {
        Self { flows: HashMap::new() }
    }

    pub fn process_packets(&mut self, packets: &[ParsedPacket]) {
        for pkt in packets {
            self.ingest(pkt);
        }
    }

    fn ingest(&mut self, pkt: &ParsedPacket) {
        let canonical = pkt.flow_key.canonical();
        let is_fwd = pkt.flow_key == canonical;

        let flow = self.flows.entry(canonical).or_insert_with(|| FlowState {
            id: format!("FL-{}", Uuid::new_v4().as_simple()),
            key: canonical,
            start_time: pkt.timestamp,
            last_seen: pkt.timestamp,
            packet_count: 0,
            byte_count: 0,
            fwd_packets: 0, rev_packets: 0,
            fwd_bytes: 0, rev_bytes: 0,
            flags: FlowFlags::default(),
            detected_protocol: None,
            tcp: if pkt.flow_key.protocol == TransportProtocol::Tcp {
                Some(TcpState::new())
            } else {
                None
            },
            segments: Vec::new(),
        });

        flow.last_seen = pkt.timestamp;
        flow.packet_count += 1;
        flow.byte_count += pkt.raw_packet.len() as u64;

        if is_fwd {
            flow.fwd_packets += 1;
            flow.fwd_bytes += pkt.raw_packet.len() as u64;
        } else {
            flow.rev_packets += 1;
            flow.rev_bytes += pkt.raw_packet.len() as u64;
        }

        if flow.detected_protocol.is_none() {
            flow.detected_protocol = guess_protocol(&pkt.flow_key);
        }

        match pkt.flow_key.protocol {
            TransportProtocol::Tcp => self.handle_tcp(canonical, pkt, is_fwd),
            TransportProtocol::Udp => self.handle_udp(canonical, pkt, is_fwd),
            TransportProtocol::Icmp => self.handle_icmp(canonical, pkt),
            _ => {}
        }
    }

    fn handle_tcp(&mut self, key: FlowKey, pkt: &ParsedPacket, is_fwd: bool) {
        let flow = self.flows.get_mut(&key).unwrap();
        let flags = pkt.tcp_flags.unwrap_or_default();
        let seq = pkt.tcp_seq.unwrap_or(0);

        if flags.syn && !flags.ack { flow.flags.syn = true; }
        if flags.syn && flags.ack { flow.flags.syn_ack = true; }
        if flags.fin { flow.flags.fin = true; }
        if flags.rst { flow.flags.rst = true; }

        let tcp = match flow.tcp.as_mut() {
            Some(t) => t,
            None => return,
        };

        // --- Handshake tracking to determine client/server ---
        match tcp.handshake {
            Handshake::None => {
                if flags.syn && !flags.ack {
                    // SYN: this sender is the CLIENT
                    tcp.client_is_forward = Some(is_fwd);
                    tcp.client_next_seq = seq.wrapping_add(1);
                    tcp.client_seq_init = true;
                    tcp.handshake = Handshake::SynSeen;
                } else if !pkt.payload.is_empty() {
                    // Mid-stream: first data sender is client
                    tcp.client_is_forward = Some(is_fwd);
                    tcp.handshake = Handshake::Established;
                }
            }
            Handshake::SynSeen => {
                if flags.syn && flags.ack {
                    // SYN-ACK: this sender is the SERVER
                    tcp.server_next_seq = seq.wrapping_add(1);
                    tcp.server_seq_init = true;
                    tcp.handshake = Handshake::SynAckSeen;
                }
            }
            Handshake::SynAckSeen => {
                if flags.ack && !flags.syn {
                    tcp.handshake = Handshake::Established;
                }
            }
            Handshake::Established => {
                if flags.fin || flags.rst {
                    tcp.handshake = Handshake::Closing;
                }
            }
            Handshake::Closing => {}
        }

        // --- Reassemble payload ---
        if pkt.payload.is_empty() { return; }

        let from_client = tcp.is_client(is_fwd);
        let direction = if from_client {
            StreamDirection::ClientToServer
        } else {
            StreamDirection::ServerToClient
        };

        if from_client {
            if !tcp.client_seq_init {
                tcp.client_next_seq = seq;
                tcp.client_seq_init = true;
            }

            if seq_lt(seq, tcp.client_next_seq) && seq != tcp.client_next_seq {
                tcp.retransmits += 1;
                flow.flags.has_retransmits = true;
            } else {
                tcp.client_buf.insert(seq, pkt.payload.clone(), pkt.timestamp);
                let drained = tcp.client_buf.drain(&mut tcp.client_next_seq);
                for (data, ts) in drained {
                    flow.segments.push(StreamSegment { direction, data, timestamp: ts });
                }
            }
        } else {
            if !tcp.server_seq_init {
                tcp.server_next_seq = seq;
                tcp.server_seq_init = true;
            }

            if seq_lt(seq, tcp.server_next_seq) && seq != tcp.server_next_seq {
                tcp.retransmits += 1;
                flow.flags.has_retransmits = true;
            } else {
                tcp.server_buf.insert(seq, pkt.payload.clone(), pkt.timestamp);
                let drained = tcp.server_buf.drain(&mut tcp.server_next_seq);
                for (data, ts) in drained {
                    flow.segments.push(StreamSegment { direction, data, timestamp: ts });
                }
            }
        }

        if !tcp.client_buf.segments.is_empty() || !tcp.server_buf.segments.is_empty() {
            flow.flags.has_gaps = true;
        }
    }

    fn handle_udp(&mut self, key: FlowKey, pkt: &ParsedPacket, is_fwd: bool) {
        let flow = self.flows.get_mut(&key).unwrap();
        if !pkt.payload.is_empty() {
            let direction = if is_fwd {
                StreamDirection::ClientToServer
            } else {
                StreamDirection::ServerToClient
            };
            flow.segments.push(StreamSegment {
                direction,
                data: pkt.payload.clone(),
                timestamp: pkt.timestamp,
            });
        }
    }

    fn handle_icmp(&mut self, key: FlowKey, pkt: &ParsedPacket) {
        let flow = self.flows.get_mut(&key).unwrap();
        flow.detected_protocol = Some(AppProtocol::Icmp);
        if !pkt.payload.is_empty() {
            flow.segments.push(StreamSegment {
                direction: StreamDirection::Unknown,
                data: pkt.payload.clone(),
                timestamp: pkt.timestamp,
            });
        }
    }

    pub fn finalize(self) -> (Vec<Flow>, Vec<Stream>) {
        let mut flows = Vec::new();
        let mut streams = Vec::new();

        for (_, state) in self.flows {
            let duration_us = state.last_seen
                .signed_duration_since(state.start_time)
                .num_microseconds()
                .unwrap_or(0)
                .unsigned_abs();

            let mut stream_ids = Vec::new();

            if !state.segments.is_empty() {
                let stream_id = format!("ST-{}", Uuid::new_v4().as_simple());
                stream_ids.push(stream_id.clone());
                let total_bytes: u64 = state.segments.iter().map(|s| s.data.len() as u64).sum();

                streams.push(Stream {
                    id: stream_id,
                    flow_id: state.id.clone(),
                    protocol: state.detected_protocol.unwrap_or(AppProtocol::Unknown),
                    segments: state.segments,
                    total_bytes,
                    summary: None,
                });
            }

            let mut flags = state.flags;
            if state.key.protocol == TransportProtocol::Tcp && !flags.syn && state.packet_count > 0 {
                flags.incomplete = true;
            }

            flows.push(Flow {
                id: state.id,
                key: state.key,
                start_time: state.start_time,
                end_time: state.last_seen,
                duration_us,
                packet_count: state.packet_count,
                byte_count: state.byte_count,
                fwd_packets: state.fwd_packets,
                rev_packets: state.rev_packets,
                fwd_bytes: state.fwd_bytes,
                rev_bytes: state.rev_bytes,
                detected_protocol: state.detected_protocol,
                stream_ids,
                flags,
            });
        }

        flows.sort_by_key(|f| f.start_time);
        streams.sort_by_key(|s| s.segments.first().map(|seg| seg.timestamp).unwrap_or_default());

        (flows, streams)
    }
}

fn guess_protocol(key: &FlowKey) -> Option<AppProtocol> {
    let port = std::cmp::min(key.src_port, key.dst_port);
    match (key.protocol, port) {
        (TransportProtocol::Tcp, 80) => Some(AppProtocol::Http),
        (TransportProtocol::Tcp, 443) => Some(AppProtocol::Tls),
        (TransportProtocol::Tcp, 8080 | 8443 | 8000 | 3000) => Some(AppProtocol::Http),
        (TransportProtocol::Udp, 53) | (TransportProtocol::Tcp, 53) => Some(AppProtocol::Dns),
        (TransportProtocol::Tcp, 21) => Some(AppProtocol::Ftp),
        (TransportProtocol::Tcp, 20) => Some(AppProtocol::FtpData),
        (TransportProtocol::Tcp, 25 | 587 | 465) => Some(AppProtocol::Smtp),
        (TransportProtocol::Tcp, 110 | 995) => Some(AppProtocol::Pop3),
        (TransportProtocol::Tcp, 143 | 993) => Some(AppProtocol::Imap),
        (TransportProtocol::Tcp, 22) => Some(AppProtocol::Ssh),
        (TransportProtocol::Tcp, 23) => Some(AppProtocol::Telnet),
        (TransportProtocol::Tcp, 445 | 139) => Some(AppProtocol::Smb),
        (TransportProtocol::Udp, 67 | 68) => Some(AppProtocol::Dhcp),
        (TransportProtocol::Tcp, 1883) | (TransportProtocol::Udp, 1883) => Some(AppProtocol::Mqtt),
        (TransportProtocol::Icmp, _) => Some(AppProtocol::Icmp),
        _ => None,
    }
}

fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seq_lt_normal() {
        assert!(seq_lt(100, 200));
        assert!(!seq_lt(200, 100));
    }

    #[test]
    fn test_seq_lt_wraparound() {
        assert!(seq_lt(u32::MAX - 5, 5));
        assert!(!seq_lt(5, u32::MAX - 5));
    }

    #[test]
    fn test_guess_protocol() {
        use std::net::{IpAddr, Ipv4Addr};
        let key = FlowKey {
            src_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            dst_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            src_port: 12345, dst_port: 80,
            protocol: TransportProtocol::Tcp,
        };
        assert_eq!(guess_protocol(&key), Some(AppProtocol::Http));
    }
}
