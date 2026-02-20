use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::IpAddr;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Evidence: The foundation. Every finding MUST point to evidence.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceRef {
    pub id: String,
    pub kind: EvidenceKind,
    pub pcap_offset: Option<u64>,
    pub stream_id: Option<String>,
    pub artifact_id: Option<String>,
    pub packet_range: Option<(u64, u64)>,
    pub description: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceKind {
    PcapPacket,
    ReassembledStream,
    ExtractedArtifact,
    DecodedContent,
    ProtocolField,
}

// ---------------------------------------------------------------------------
// Network primitives
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum TransportProtocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: TransportProtocol,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Flow {
    pub id: String,
    pub key: FlowKey,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub duration_us: u64,
    pub packet_count: u64,
    pub byte_count: u64,
    pub fwd_packets: u64,
    pub rev_packets: u64,
    pub fwd_bytes: u64,
    pub rev_bytes: u64,
    pub detected_protocol: Option<AppProtocol>,
    pub stream_ids: Vec<String>,
    pub flags: FlowFlags,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FlowFlags {
    pub syn: bool,
    pub syn_ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub incomplete: bool,
    pub has_retransmits: bool,
    pub has_gaps: bool,
}

// ---------------------------------------------------------------------------
// Application-layer protocol identification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(rename_all = "snake_case")]
pub enum AppProtocol {
    Dns,
    Http,
    Https,
    Tls,
    Ftp,
    FtpData,
    Smtp,
    Pop3,
    Imap,
    Ssh,
    Telnet,
    Smb,
    Dhcp,
    Icmp,
    Mqtt,
    WebSocket,
    Unknown,
}

// ---------------------------------------------------------------------------
// Streams: reassembled byte sequences
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum StreamDirection {
    ClientToServer,
    ServerToClient,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StreamSegment {
    pub direction: StreamDirection,
    pub data: Vec<u8>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Stream {
    pub id: String,
    pub flow_id: String,
    pub protocol: AppProtocol,
    pub segments: Vec<StreamSegment>,
    pub total_bytes: u64,
    pub summary: Option<String>,
}

// ---------------------------------------------------------------------------
// Artifacts: extracted objects (files, credentials, decoded blobs)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactKind {
    File,
    Image,
    Executable,
    Archive,
    Document,
    Certificate,
    Key,
    Credential,
    DecodedBlob,
    Url,
    Email,
    DnsRecord,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Artifact {
    pub id: String,
    pub kind: ArtifactKind,
    pub name: Option<String>,
    pub mime_type: Option<String>,
    pub size_bytes: u64,
    pub sha256: String,
    pub md5: String,
    pub path: Option<String>,
    pub source_stream_id: Option<String>,
    pub source_evidence: EvidenceRef,
    pub metadata: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Credentials: harvested authentication material
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    HttpBasicAuth,
    HttpDigestAuth,
    HttpFormLogin,
    FtpLogin,
    TelnetLogin,
    SmtpAuth,
    Pop3Login,
    ImapLogin,
    NtlmHash,
    KerberosTicket,
    Jwt,
    ApiKey,
    SshPrivateKey,
    SessionCookie,
    OauthToken,
    BearerToken,
    Other,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub id: String,
    pub kind: CredentialKind,
    pub username: Option<String>,
    pub secret: String,
    pub service: Option<String>,
    pub host: Option<String>,
    pub evidence: EvidenceRef,
    pub metadata: HashMap<String, serde_json::Value>,
}

// ---------------------------------------------------------------------------
// Findings: detection results with evidence and suggested pivots
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingCategory {
    CtfFlag,
    Credential,
    Exfiltration,
    C2Communication,
    Anomaly,
    MaliciousFile,
    SuspiciousDns,
    ClearTextProtocol,
    CertificateIssue,
    ProtocolAnomaly,
    DataLeak,
    ReconActivity,
    LateralMovement,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub title: String,
    pub description: String,
    pub severity: Severity,
    pub confidence: f64,
    pub category: FindingCategory,
    pub evidence: Vec<EvidenceRef>,
    pub pivots: Vec<Pivot>,
    pub mitre_attack: Vec<String>,
    pub tags: Vec<String>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pivot {
    pub description: String,
    pub query: Option<String>,
    pub command: Option<String>,
}

// ---------------------------------------------------------------------------
// IOC: Indicators of Compromise
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IocKind {
    IpAddress,
    Domain,
    Url,
    FileHash,
    Ja3Fingerprint,
    Ja3sFingerprint,
    UserAgent,
    EmailAddress,
    Mutex,
    Registry,
    Custom(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ioc {
    pub id: String,
    pub kind: IocKind,
    pub value: String,
    pub description: Option<String>,
    pub source: Option<String>,
    pub confidence: f64,
    pub evidence: Vec<EvidenceRef>,
    pub mitre_attack: Vec<String>,
}

// ---------------------------------------------------------------------------
// Protocol-specific parsed data
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsRecord {
    pub query_name: String,
    pub record_type: String,
    pub response_data: Vec<String>,
    pub ttl: Option<u32>,
    pub is_response: bool,
    pub response_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpTransaction {
    pub method: String,
    pub uri: String,
    pub host: Option<String>,
    pub status_code: Option<u16>,
    pub request_headers: HashMap<String, String>,
    pub response_headers: HashMap<String, String>,
    pub request_body_size: u64,
    pub response_body_size: u64,
    pub content_type: Option<String>,
    pub user_agent: Option<String>,
    pub cookies: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub version: String,
    pub sni: Option<String>,
    pub alpn: Vec<String>,
    pub cipher_suite: Option<String>,
    pub ja3_hash: Option<String>,
    pub ja3s_hash: Option<String>,
    pub cert_subject: Option<String>,
    pub cert_issuer: Option<String>,
    pub cert_not_before: Option<DateTime<Utc>>,
    pub cert_not_after: Option<DateTime<Utc>>,
    pub cert_fingerprint_sha256: Option<String>,
    pub is_self_signed: Option<bool>,
}

// ---------------------------------------------------------------------------
// Host profile
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostProfile {
    pub ip: IpAddr,
    pub hostnames: Vec<String>,
    pub mac_address: Option<String>,
    pub os_guess: Option<String>,
    pub services: Vec<ServiceInfo>,
    pub total_bytes_sent: u64,
    pub total_bytes_received: u64,
    pub total_flows: u64,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub port: u16,
    pub protocol: TransportProtocol,
    pub app_protocol: Option<AppProtocol>,
    pub banner: Option<String>,
}

// ---------------------------------------------------------------------------
// Timeline
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub timestamp: DateTime<Utc>,
    pub event_type: String,
    pub summary: String,
    pub severity: Severity,
    pub evidence_id: Option<String>,
    pub source_ip: Option<IpAddr>,
    pub dest_ip: Option<IpAddr>,
    pub protocol: Option<AppProtocol>,
}

// ---------------------------------------------------------------------------
// The Report: top-level container, primary API contract
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportMetadata {
    pub wirehunt_version: String,
    pub generated_at: DateTime<Utc>,
    pub pcap_filename: String,
    pub pcap_sha256: String,
    pub pcap_size_bytes: u64,
    pub total_packets: u64,
    pub capture_start: Option<DateTime<Utc>>,
    pub capture_end: Option<DateTime<Utc>>,
    pub capture_duration_secs: f64,
    pub profile: AnalysisProfile,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisProfile {
    Ctf,
    IncidentResponse,
    Forensics,
    ThreatHunt,
    Quick,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Report {
    pub metadata: ReportMetadata,
    pub executive_summary: Option<String>,
    pub findings: Vec<Finding>,
    pub flows: Vec<Flow>,
    pub streams: Vec<Stream>,
    pub artifacts: Vec<Artifact>,
    pub credentials: Vec<Credential>,
    pub iocs: Vec<Ioc>,
    pub dns_records: Vec<DnsRecord>,
    pub http_transactions: Vec<HttpTransaction>,
    pub tls_sessions: Vec<TlsInfo>,
    pub ftp_sessions: Vec<crate::protocols::ftp::FtpSession>,
    pub ssh_sessions: Vec<crate::protocols::ssh::SshSession>,
    pub telnet_sessions: Vec<crate::protocols::telnet::TelnetSession>,
    pub dhcp_leases: Vec<crate::protocols::dhcp::DhcpLease>,
    pub smb_sessions: Vec<crate::protocols::smb::SmbSession>,
    pub host_profiles: Vec<HostProfile>,
    pub timeline: Vec<TimelineEvent>,
    pub statistics: AnalysisStatistics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisStatistics {
    pub protocol_breakdown: HashMap<String, u64>,
    pub top_talkers: Vec<(IpAddr, u64)>,
    pub top_ports: Vec<(u16, u64)>,
    pub total_findings: u64,
    pub total_artifacts: u64,
    pub total_credentials: u64,
    pub analysis_duration_ms: u64,
}

// ---------------------------------------------------------------------------
// IOC Enrichment (threat intelligence)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IocEnrichment {
    pub ioc_id: String,
    pub ioc_value: String,
    pub reputation_score: Option<i32>,
    pub is_malicious: Option<bool>,
    pub tags: Vec<String>,
    pub geo: Option<GeoInfo>,
    pub whois: Option<WhoisInfo>,
    pub sources: Vec<EnrichmentSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeoInfo {
    pub country: Option<String>,
    pub country_code: Option<String>,
    pub city: Option<String>,
    pub region: Option<String>,
    pub asn: Option<String>,
    pub org: Option<String>,
    pub lat: Option<f64>,
    pub lon: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WhoisInfo {
    pub name: Option<String>,
    pub org: Option<String>,
    pub country: Option<String>,
    pub range: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentSource {
    pub provider: String,
    pub score: Option<i32>,
    pub details: String,
    pub link: Option<String>,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

impl Finding {
    pub fn new(
        title: impl Into<String>,
        description: impl Into<String>,
        severity: Severity,
        confidence: f64,
        category: FindingCategory,
    ) -> Self {
        Self {
            id: format!("F-{}", Uuid::new_v4().as_simple()),
            title: title.into(),
            description: description.into(),
            severity,
            confidence,
            category,
            evidence: Vec::new(),
            pivots: Vec::new(),
            mitre_attack: Vec::new(),
            tags: Vec::new(),
            timestamp: Utc::now(),
        }
    }

    pub fn with_evidence(mut self, evidence: EvidenceRef) -> Self {
        self.evidence.push(evidence);
        self
    }

    pub fn with_pivot(mut self, pivot: Pivot) -> Self {
        self.pivots.push(pivot);
        self
    }

    pub fn with_mitre(mut self, technique: impl Into<String>) -> Self {
        self.mitre_attack.push(technique.into());
        self
    }
}

impl EvidenceRef {
    pub fn from_packet(offset: u64, description: impl Into<String>) -> Self {
        Self {
            id: format!("E-{}", Uuid::new_v4().as_simple()),
            kind: EvidenceKind::PcapPacket,
            pcap_offset: Some(offset),
            stream_id: None,
            artifact_id: None,
            packet_range: None,
            description: description.into(),
        }
    }

    pub fn from_stream(stream_id: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            id: format!("E-{}", Uuid::new_v4().as_simple()),
            kind: EvidenceKind::ReassembledStream,
            pcap_offset: None,
            stream_id: Some(stream_id.into()),
            artifact_id: None,
            packet_range: None,
            description: description.into(),
        }
    }

    pub fn from_artifact(artifact_id: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            id: format!("E-{}", Uuid::new_v4().as_simple()),
            kind: EvidenceKind::ExtractedArtifact,
            pcap_offset: None,
            stream_id: None,
            artifact_id: Some(artifact_id.into()),
            packet_range: None,
            description: description.into(),
        }
    }
}

impl FlowKey {
    pub fn reversed(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
            protocol: self.protocol,
        }
    }

    pub fn canonical(&self) -> Self {
        if (self.src_ip, self.src_port) <= (self.dst_ip, self.dst_port) {
            *self
        } else {
            self.reversed()
        }
    }
}
