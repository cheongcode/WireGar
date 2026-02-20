use std::fs::File;
use std::io::Read;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use pcap_parser::traits::PcapReaderIterator;
use pcap_parser::*;
use sha2::{Digest, Sha256};

use crate::models::{FlowKey, TransportProtocol};

// ---------------------------------------------------------------------------
// ParsedPacket: the normalized output of the ingest layer
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub index: u64,
    pub timestamp: DateTime<Utc>,
    pub pcap_offset: u64,
    pub caplen: u32,
    pub origlen: u32,
    pub flow_key: FlowKey,
    pub tcp_flags: Option<TcpFlags>,
    pub tcp_seq: Option<u32>,
    pub tcp_ack: Option<u32>,
    pub tcp_window: Option<u16>,
    pub payload: Vec<u8>,
    pub raw_packet: Vec<u8>,
    pub src_mac: Option<[u8; 6]>,
    pub dst_mac: Option<[u8; 6]>,
    pub vlan_id: Option<u16>,
    pub ip_ttl: u8,
    pub ip_id: Option<u16>,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    fn from_u8(flags: u8) -> Self {
        Self {
            fin: flags & 0x01 != 0,
            syn: flags & 0x02 != 0,
            rst: flags & 0x04 != 0,
            psh: flags & 0x08 != 0,
            ack: flags & 0x10 != 0,
            urg: flags & 0x20 != 0,
            ece: flags & 0x40 != 0,
            cwr: flags & 0x80 != 0,
        }
    }

    pub fn is_syn_only(&self) -> bool {
        self.syn && !self.ack
    }

    pub fn is_syn_ack(&self) -> bool {
        self.syn && self.ack
    }
}

// ---------------------------------------------------------------------------
// PcapIngestor: streaming reader for pcap/pcapng files
// ---------------------------------------------------------------------------

pub struct PcapIngestor {
    pub filename: String,
    pub file_sha256: String,
    pub file_size: u64,
    pub total_packets: u64,
    pub first_timestamp: Option<DateTime<Utc>>,
    pub last_timestamp: Option<DateTime<Utc>>,
    pub packets: Vec<ParsedPacket>,
    pub parse_errors: u64,
    pub linktype: Linktype,
}

impl PcapIngestor {
    pub fn from_file(path: &Path) -> Result<Self> {
        let filename = path
            .file_name()
            .map(|f| f.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        let file_size = std::fs::metadata(path)
            .with_context(|| format!("cannot stat {}", path.display()))?
            .len();

        let file_sha256 = compute_file_sha256(path)?;

        tracing::info!(
            file = %filename,
            size = file_size,
            sha256 = %file_sha256,
            "ingesting pcap"
        );

        let mut file = File::open(path)
            .with_context(|| format!("cannot open {}", path.display()))?;

        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .with_context(|| format!("cannot read {}", path.display()))?;

        let mut ingestor = Self {
            filename,
            file_sha256,
            file_size,
            total_packets: 0,
            first_timestamp: None,
            last_timestamp: None,
            packets: Vec::new(),
            parse_errors: 0,
            linktype: Linktype::ETHERNET,
        };

        if buf.len() >= 4 && buf[0] == 0x0a && buf[1] == 0x0d && buf[2] == 0x0d && buf[3] == 0x0a {
            ingestor.read_pcapng(&buf)?;
        } else {
            ingestor.read_pcap(&buf)?;
        }

        tracing::info!(
            packets = ingestor.total_packets,
            errors = ingestor.parse_errors,
            "ingestion complete"
        );

        Ok(ingestor)
    }

    fn read_pcap(&mut self, data: &[u8]) -> Result<()> {
        let mut reader = LegacyPcapReader::new(65536, data)
            .context("failed to create pcap reader")?;
        let mut offset: u64 = 24; // pcap global header size
        let mut pkt_index: u64 = 0;

        loop {
            match reader.next() {
                Ok((consumed, block)) => {
                    match block {
                        PcapBlockOwned::LegacyHeader(header) => {
                            self.linktype = header.network;
                        }
                        PcapBlockOwned::Legacy(packet) => {
                            let ts = pcap_ts_to_datetime(
                                packet.ts_sec as i64,
                                packet.ts_usec as u32,
                            );

                            if let Some(parsed) = self.parse_link_layer(
                                &packet.data,
                                pkt_index,
                                ts,
                                offset,
                                packet.caplen,
                                packet.origlen,
                            ) {
                                self.update_timestamps(ts);
                                self.packets.push(parsed);
                            }

                            pkt_index += 1;
                            self.total_packets += 1;
                        }
                        _ => {}
                    }
                    offset += consumed as u64;
                    reader.consume(consumed);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete(_)) => {
                    // need more data but we loaded everything
                    reader.consume(0);
                    break;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "pcap parse error");
                    self.parse_errors += 1;
                    break;
                }
            }
        }
        Ok(())
    }

    fn read_pcapng(&mut self, data: &[u8]) -> Result<()> {
        let mut reader = PcapNGReader::new(65536, data)
            .context("failed to create pcapng reader")?;
        let mut offset: u64 = 0;
        let mut pkt_index: u64 = 0;
        let mut if_tsresol: u64 = 1_000_000; // default microsecond resolution

        loop {
            match reader.next() {
                Ok((consumed, block)) => {
                    match block {
                        PcapBlockOwned::NG(Block::SectionHeader(_)) => {}
                        PcapBlockOwned::NG(Block::InterfaceDescription(idb)) => {
                            self.linktype = idb.linktype;
                            // Parse timestamp resolution from options
                            for opt in &idb.options {
                                if opt.code == OptionCode::IfTsresol {
                                    if let Some(&val) = opt.value.first() {
                                        if val & 0x80 != 0 {
                                            let exp = (val & 0x7f) as u32;
                                            if_tsresol = 2u64.pow(exp);
                                        } else {
                                            if_tsresol = 10u64.pow(val as u32);
                                        }
                                    }
                                }
                            }
                        }
                        PcapBlockOwned::NG(Block::EnhancedPacket(epb)) => {
                            let ts_raw = ((epb.ts_high as u64) << 32) | (epb.ts_low as u64);
                            let secs = (ts_raw / if_tsresol) as i64;
                            let frac = ts_raw % if_tsresol;
                            let nanos = if if_tsresol > 0 {
                                (frac * 1_000_000_000 / if_tsresol) as u32
                            } else {
                                0
                            };
                            let ts = pcap_ts_to_datetime(secs, nanos / 1000);

                            if let Some(parsed) = self.parse_link_layer(
                                &epb.data,
                                pkt_index,
                                ts,
                                offset,
                                epb.caplen,
                                epb.origlen,
                            ) {
                                self.update_timestamps(ts);
                                self.packets.push(parsed);
                            }

                            pkt_index += 1;
                            self.total_packets += 1;
                        }
                        PcapBlockOwned::NG(Block::SimplePacket(spb)) => {
                            let ts = Utc::now();
                            let len = spb.data.len() as u32;

                            if let Some(parsed) = self.parse_link_layer(
                                &spb.data,
                                pkt_index,
                                ts,
                                offset,
                                len,
                                len,
                            ) {
                                self.packets.push(parsed);
                            }

                            pkt_index += 1;
                            self.total_packets += 1;
                        }
                        _ => {}
                    }
                    offset += consumed as u64;
                    reader.consume(consumed);
                }
                Err(PcapError::Eof) => break,
                Err(PcapError::Incomplete(_)) => {
                    reader.consume(0);
                    break;
                }
                Err(e) => {
                    tracing::warn!(error = %e, "pcapng parse error");
                    self.parse_errors += 1;
                    break;
                }
            }
        }
        Ok(())
    }

    fn update_timestamps(&mut self, ts: DateTime<Utc>) {
        if self.first_timestamp.is_none() || Some(ts) < self.first_timestamp {
            self.first_timestamp = Some(ts);
        }
        if self.last_timestamp.is_none() || Some(ts) > self.last_timestamp {
            self.last_timestamp = Some(ts);
        }
    }

    fn parse_link_layer(
        &mut self,
        data: &[u8],
        index: u64,
        timestamp: DateTime<Utc>,
        pcap_offset: u64,
        caplen: u32,
        origlen: u32,
    ) -> Option<ParsedPacket> {
        let raw = data.to_vec();

        match self.linktype {
            Linktype::ETHERNET => self.parse_ethernet(data, index, timestamp, pcap_offset, caplen, origlen, raw),
            Linktype::RAW | Linktype(12) => {
                // Raw IP (no link-layer header)
                self.parse_ip_packet(data, index, timestamp, pcap_offset, caplen, origlen, raw, None, None, None)
            }
            Linktype::NULL => {
                // BSD loopback: 4-byte header
                if data.len() < 4 {
                    return None;
                }
                self.parse_ip_packet(&data[4..], index, timestamp, pcap_offset, caplen, origlen, raw, None, None, None)
            }
            Linktype::LINUX_SLL => {
                // Linux cooked capture: 16-byte header
                if data.len() < 16 {
                    return None;
                }
                let ethertype = u16::from_be_bytes([data[14], data[15]]);
                if ethertype == 0x0800 || ethertype == 0x86DD {
                    self.parse_ip_packet(&data[16..], index, timestamp, pcap_offset, caplen, origlen, raw, None, None, None)
                } else {
                    None
                }
            }
            _ => {
                self.parse_errors += 1;
                None
            }
        }
    }

    fn parse_ethernet(
        &mut self,
        data: &[u8],
        index: u64,
        timestamp: DateTime<Utc>,
        pcap_offset: u64,
        caplen: u32,
        origlen: u32,
        raw: Vec<u8>,
    ) -> Option<ParsedPacket> {
        if data.len() < 14 {
            self.parse_errors += 1;
            return None;
        }

        let dst_mac: [u8; 6] = data[0..6].try_into().ok()?;
        let src_mac: [u8; 6] = data[6..12].try_into().ok()?;
        let mut ethertype = u16::from_be_bytes([data[12], data[13]]);
        let mut offset = 14usize;
        let mut vlan_id: Option<u16> = None;

        // Handle VLAN tags (802.1Q)
        if ethertype == 0x8100 {
            if data.len() < 18 {
                return None;
            }
            vlan_id = Some(u16::from_be_bytes([data[14], data[15]]) & 0x0FFF);
            ethertype = u16::from_be_bytes([data[16], data[17]]);
            offset = 18;

            // Handle QinQ (double VLAN)
            if ethertype == 0x8100 {
                if data.len() < 22 {
                    return None;
                }
                ethertype = u16::from_be_bytes([data[20], data[21]]);
                offset = 22;
            }
        }

        if ethertype != 0x0800 && ethertype != 0x86DD {
            return None; // not IPv4 or IPv6
        }

        self.parse_ip_packet(
            &data[offset..],
            index,
            timestamp,
            pcap_offset,
            caplen,
            origlen,
            raw,
            Some(src_mac),
            Some(dst_mac),
            vlan_id,
        )
    }

    fn parse_ip_packet(
        &mut self,
        data: &[u8],
        index: u64,
        timestamp: DateTime<Utc>,
        pcap_offset: u64,
        caplen: u32,
        origlen: u32,
        raw: Vec<u8>,
        src_mac: Option<[u8; 6]>,
        dst_mac: Option<[u8; 6]>,
        vlan_id: Option<u16>,
    ) -> Option<ParsedPacket> {
        use etherparse::{NetHeaders, PacketHeaders, TransportHeader};

        let headers = PacketHeaders::from_ip_slice(data).ok()?;

        let (src_ip, dst_ip, ip_ttl, ip_id) = match headers.net {
            Some(NetHeaders::Ipv4(ref h, _)) => (
                IpAddr::V4(Ipv4Addr::from(h.source)),
                IpAddr::V4(Ipv4Addr::from(h.destination)),
                h.time_to_live,
                Some(h.identification),
            ),
            Some(NetHeaders::Ipv6(ref h, _)) => (
                IpAddr::V6(Ipv6Addr::from(h.source)),
                IpAddr::V6(Ipv6Addr::from(h.destination)),
                h.hop_limit,
                None,
            ),
            None => return None,
        };

        let payload_bytes = headers.payload.slice().to_vec();

        let (protocol, src_port, dst_port, tcp_flags, tcp_seq, tcp_ack, tcp_window) =
            match headers.transport {
                Some(TransportHeader::Tcp(ref tcp)) => {
                    let flags = TcpFlags {
                        fin: tcp.fin,
                        syn: tcp.syn,
                        rst: tcp.rst,
                        psh: tcp.psh,
                        ack: tcp.ack,
                        urg: tcp.urg,
                        ece: tcp.ece,
                        cwr: tcp.cwr,
                    };
                    (
                        TransportProtocol::Tcp,
                        tcp.source_port,
                        tcp.destination_port,
                        Some(flags),
                        Some(tcp.sequence_number),
                        Some(tcp.acknowledgment_number),
                        Some(tcp.window_size),
                    )
                }
                Some(TransportHeader::Udp(ref udp)) => (
                    TransportProtocol::Udp,
                    udp.source_port,
                    udp.destination_port,
                    None,
                    None,
                    None,
                    None,
                ),
                Some(TransportHeader::Icmpv4(_)) | Some(TransportHeader::Icmpv6(_)) => (
                    TransportProtocol::Icmp,
                    0,
                    0,
                    None,
                    None,
                    None,
                    None,
                ),
                None => return None,
            };

        let flow_key = FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        };

        Some(ParsedPacket {
            index,
            timestamp,
            pcap_offset,
            caplen,
            origlen,
            flow_key,
            tcp_flags,
            tcp_seq,
            tcp_ack,
            tcp_window,
            payload: payload_bytes,
            raw_packet: raw,
            src_mac,
            dst_mac,
            vlan_id,
            ip_ttl,
            ip_id,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn pcap_ts_to_datetime(secs: i64, usecs: u32) -> DateTime<Utc> {
    DateTime::from_timestamp(secs, usecs * 1000).unwrap_or_default()
}

fn compute_file_sha256(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hex::encode(hasher.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_tcp_flags_from_u8() {
        let flags = TcpFlags::from_u8(0x02); // SYN only
        assert!(flags.syn);
        assert!(!flags.ack);
        assert!(flags.is_syn_only());

        let flags = TcpFlags::from_u8(0x12); // SYN+ACK
        assert!(flags.syn);
        assert!(flags.ack);
        assert!(flags.is_syn_ack());

        let flags = TcpFlags::from_u8(0x18); // PSH+ACK
        assert!(flags.psh);
        assert!(flags.ack);
        assert!(!flags.syn);
    }

    #[test]
    fn test_pcap_ts_to_datetime() {
        let dt = pcap_ts_to_datetime(1_700_000_000, 500_000);
        assert_eq!(dt.timestamp(), 1_700_000_000);
    }
}
