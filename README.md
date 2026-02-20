# WireHunt

<p align="center">
  <img src="WIREHUNT.gif" alt="WireHunt" width="400"/>
</p>

**All-in-one network forensic engine** for CTF competitions, incident response, IOC detection, credential harvesting, and protocol analysis. Built from scratch in Rust for maximum performance, memory safety, and cross-platform deployment.

WireHunt replaces the need to manually use Wireshark, tshark, NetworkMiner, and other tools. Drop any pcap or pcapng file in -- malware traffic, CTF challenges, network forensic cases, red team captures -- and WireHunt does the rest. It reassembles TCP streams, parses protocols, extracts files, finds flags, harvests credentials, detects IOCs, maps MITRE ATT&CK techniques, profiles hosts, and scores findings with confidence levels.

> **Origin Story:** WireHunt started life as **WireGar**, a university final year project built 6 years ago. It has since been completely rewritten from the ground up in Rust -- zero legacy code remains. The original Python prototype could barely handle small pcaps; WireHunt now processes hundreds of megabytes in seconds with full protocol dissection, credential harvesting, IOC extraction, AI-powered analysis, and three professional interfaces (Web GUI, TUI, CLI).

```
 ██╗    ██╗██╗██████╗ ███████╗██╗  ██╗██╗   ██╗███╗   ██╗████████╗
 ██║    ██║██║██╔══██╗██╔════╝██║  ██║██║   ██║████╗  ██║╚══██╔══╝
 ██║ █╗ ██║██║██████╔╝█████╗  ███████║██║   ██║██╔██╗ ██║   ██║
 ██║███╗██║██║██╔══██╗██╔══╝  ██╔══██║██║   ██║██║╚██╗██║   ██║
 ╚███╔███╔╝██║██║  ██║███████╗██║  ██║╚██████╔╝██║ ╚████║   ██║
  ╚══╝╚══╝ ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝
```

---

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Code Walkthrough](#code-walkthrough)
- [How the Analysis Pipeline Works](#how-the-analysis-pipeline-works)
- [Report Format](#report-format)
- [Current Status](#current-status)
- [Development](#development)
- [License](#license)

---

## Features

**Packet Ingestion**
- Reads pcap and pcapng formats via streaming zero-copy parser
- Supports Ethernet, 802.1Q VLAN (including QinQ), Raw IP, BSD Loopback, Linux Cooked Capture link types
- Computes file SHA256 hash and tracks capture timestamps

**TCP Reassembly**
- Full bidirectional stream reconstruction with proper client/server direction tracking
- Handles out-of-order segments via sequence-number-sorted reorder buffers
- Mid-stream pickup: works correctly even when the capture starts after the TCP handshake
- Retransmit detection and gap tracking
- UDP conversation grouping by 5-tuple

**Protocol Dissectors (10 protocols)**
- DNS: query/response parsing, name decompression (pointer support), A/AAAA/CNAME/NS/PTR/MX/TXT/SOA record types, response codes
- HTTP/1.0 and HTTP/1.1: request/response parsing, header extraction, cookie extraction, user-agent, chunked transfer-encoding support
- TLS: ClientHello/ServerHello parsing, SNI extraction, ALPN, cipher suites, JA3 and JA3S fingerprint computation, GREASE filtering
- ICMP: type/code parsing with human-readable names, embedded payload collection for covert channel detection
- FTP: command parsing, USER/PASS credential extraction, RETR/STOR file transfer tracking, PASV/EPSV/PORT data channel port extraction, AUTH TLS (FTPS) detection
- SMTP: session parsing, MAIL FROM/RCPT TO extraction, AUTH LOGIN and AUTH PLAIN credential decoding, email body and subject extraction
- SSH: banner extraction (client + server), version detection, key exchange algorithm and cipher enumeration
- Telnet: IAC negotiation option parsing, login prompt credential extraction, session content capture
- DHCP: Discover/Offer/Request/ACK parsing, hostname, MAC address, assigned IP, gateway, DNS servers, lease time
- SMB/CIFS: SMB1 and SMB2+ protocol detection, command extraction (negotiate, session setup, tree connect), NTLM domain/user extraction, share access detection
- Heuristic protocol detection on non-standard ports by inspecting first bytes of stream data

**CTF Flag Detection**
- 12 flag patterns including flag{}, CTF{}, ctfa{}, picoCTF{}, htb{}, thm{}, and a catch-all pattern for custom formats
- Scans reassembled stream content, extracted artifacts, and decoded strings
- Multi-layer automatic decoding tries all combinations: base64, base32, hex, URL-decode, ROT13, gzip, zlib, XOR single-byte brute-force
- Flags found through decode chains report the chain used (e.g., "base64 | xor:0x42")
- Deduplication across streams: same flag value found in multiple streams counts once

**Credential Harvesting**
- HTTP Basic Auth (base64-decoded to user:pass)
- HTTP Bearer tokens
- FTP USER/PASS plaintext credentials
- SMTP AUTH LOGIN (base64) and AUTH PLAIN credentials
- JWT token detection (eyJ... pattern)
- AWS access keys (AKIA...)
- GitHub tokens (ghp_, gho_, ghs_, ghu_, ghr_)
- Slack tokens (xoxb-, xoxp-, xoxa-, xoxs-, xoxr-)
- Generic API key patterns (api_key=, secret_key=, access_token=, etc.)
- SSH private key block detection
- Password form field extraction from POST data
- Session cookie detection

**Artifact Extraction**
- Carves files from HTTP response bodies
- MIME type detection by magic bytes (PNG, JPEG, GIF, ZIP, ELF, PE, PDF, gzip)
- SHA256 and MD5 hashing of all extracted artifacts
- Deduplication by SHA256 hash

**Detection Engine (18 rule categories)**
- Generates scored findings with severity (Critical/High/Medium/Low/Info) and confidence (0-100%)
- MITRE ATT&CK technique tags on all findings
- Data exfiltration analysis (bytes out per external IP, asymmetric flow detection)
- C2 beaconing detection (periodic connection analysis with coefficient of variation)
- Known malware JA3 fingerprints (25+ hashes: CobaltStrike, Metasploit, Sliver, AgentTesla, FormBook, SnakeKeylogger, Emotet, QakBot, IcedID, Dridex, RedLine, Raccoon, AsyncRAT, NjRAT, DarkComet)
- Malware HTTP patterns: C2 URI patterns, known malware user-agents, POST to raw IP detection
- FTPS exfiltration detection (port 990, FTP-related SNI in TLS handshakes, AUTH TLS commands)
- TLS anomalies: no-SNI, self-signed certificates, deprecated TLS versions (1.0/SSL)
- DNS anomalies: NXDOMAIN counts (DGA indicator), high query volume, fast-flux detection, long domain names
- Cleartext protocol warnings with malware context (FTP, Telnet, SMTP)
- Lateral movement detection (internal connections to SMB/RDP/SSH/WinRM)
- Port scanning detection (>15 unique destination ports from one source)
- Short-lived encrypted connection patterns (C2 heartbeats)
- Findings sorted by severity then confidence

**IOC Extraction + Threat Intelligence Enrichment**
- Automatic extraction of Indicators of Compromise from all analysis data
- External IP addresses with flow counts
- Domain names with DGA (Domain Generation Algorithm) detection
- URLs with path traversal and suspicious endpoint detection
- File hashes (SHA256) from extracted artifacts
- JA3 and JA3S TLS fingerprints
- User-Agent strings with tool/scanner identification (curl, wget, nikto, sqlmap, nmap)
- MITRE ATT&CK technique tagging on all IOCs
- Confidence scoring per IOC
- Async threat intelligence enrichment via 4 APIs:
  - VirusTotal: IP/domain/hash reputation and detection ratios
  - AbuseIPDB: IP abuse confidence scoring
  - Shodan: open ports, services, vulnerabilities
  - AlienVault OTX: pulse counts, community threat intel
- GeoIP lookup (ip-api.com, free, no key needed): country, city, ASN, org
- WHOIS lookup (RDAP, free, no key needed): registration info

**Auto Executive Summary**
- Rule-based narrative generated from report data (no AI required)
- Plain English description of what happened in the capture
- Highlights exfiltration indicators, C2 patterns, credential exposure
- Covers both CTF and incident response scenarios
- MITRE ATT&CK technique coverage summary

**Host Profiling**
- Automatic per-host profile generation from flow data
- Tracks bytes sent/received, flow counts, active time ranges
- Service discovery (port/protocol/application mapping)
- DNS-based hostname resolution
- Sorted by traffic volume for quick identification of top talkers

**Timeline Generation**
- Chronological event timeline built from flows, findings, HTTP transactions, and credential harvests
- Severity-colored event markers
- Protocol and IP attribution per event

**Entropy Analysis**
- Shannon entropy calculation on all stream content
- Classification: encrypted (>7.5), compressed (>6.5), mixed, structured, repetitive

**Search Index and Query DSL**
- SQLite FTS5 full-text search across all analysis data
- Scoped queries: `dns:evil.com`, `http:admin`, `findings:critical`
- Free text search across streams, DNS, HTTP, credentials, artifacts, findings, TLS
- Output as table, JSON, or CSV

**Report Export**
- Self-contained HTML report with Catppuccin dark theme and interactive tabs
- JSON export
- STIX 2.1 bundle export for integration with threat intelligence platforms

**Live Network Capture**
- Real-time packet capture from network interfaces (feature-gated, requires libpcap/Npcap)
- BPF filter support, duration limits, packet count limits
- Real-time regex pattern alerts (e.g., `--alert "flag{"`)
- Full analysis pipeline on Ctrl+C with automatic report generation
- Interface listing with `--list`

**AI-Powered Analysis**
- Multi-provider support: OpenAI (GPT-4o), Anthropic (Claude), Ollama (local models)
- `ai explain`: narrative forensic analysis of capture
- `ai solve`: CTF-focused flag-solving assistance
- `ai decode`: encoding identification and decode chain suggestions
- `ai generate-rule`: Suricata/Sigma rule generation from findings
- `ai suggest-queries`: recommended search queries based on report
- Configuration via `~/.wirehunt/config.toml` or environment variables

**Three Professional Interfaces**
- Web GUI: drag-and-drop browser dashboard at localhost:8888 with executive summary, MITRE ATT&CK kill chain, interactive network graph, threat intel enrichment (VT/AbuseIPDB/Shodan/OTX), GeoIP country flags, IOC reputation scoring, host profiles, timeline, TLS details, finding drill-down with evidence, stream viewer with Follow/Copy/Hex, top talkers, 11 tabbed data sections, PDF export
- Terminal TUI: interactive ratatui-based interface with 7 tabs and Vim keybindings
- CLI: scriptable command-line interface with JSON output for automation and pipeline integration

---

## Installation

### Quick Install (Recommended)

Linux/macOS:
```bash
git clone https://github.com/cheongcode/WireGar.git && cd WireGar && bash install.sh
```

Windows PowerShell:
```powershell
git clone https://github.com/cheongcode/WireGar.git; cd WireGar; .\install.ps1
```

That's it. The install script handles everything: installs Rust if needed, builds optimized release binaries, and installs them to your PATH. Then just run `wirehunt serve` and drop your pcap.

### Prerequisites

- [Rust toolchain](https://rustup.rs/) version 1.80 or later (install script handles this automatically)
- Git

### Optional: Threat Intelligence API Keys

For IOC enrichment with VirusTotal, AbuseIPDB, and Shodan (all free tiers):

```bash
export VIRUSTOTAL_API_KEY="your-key-here"    # https://virustotal.com (free: 4 req/min)
export ABUSEIPDB_API_KEY="your-key-here"     # https://abuseipdb.com (free: 1000 req/day)
export SHODAN_API_KEY="your-key-here"         # https://shodan.io (free tier)
```

GeoIP and WHOIS lookups work automatically with no API keys needed.

### Build from Source (Manual)

```bash
git clone https://github.com/cheongcode/WireGar.git
cd WireGar
cargo build --release
```

The binaries will be at `target/release/wirehunt` and `target/release/wirehunt-tui`.

### Install to PATH

```bash
cargo install --path crates/wirehunt-cli
cargo install --path crates/wirehunt-tui
```

### Install Scripts (Alternative)

Linux/macOS:
```bash
bash install.sh
```

Windows PowerShell:
```powershell
.\install.ps1
```

These scripts install the Rust toolchain if needed, build release binaries, and install them to your PATH.

---

## Usage

### Web GUI (Recommended for First-Time Users)

```bash
wirehunt serve
```

This starts a local web server at `http://localhost:8888` and opens your browser. Drag and drop any `.pcap` or `.pcapng` file onto the page. WireHunt analyzes it and displays a professional forensic dashboard with:
- Auto-generated executive summary (plain English narrative of what happened)
- MITRE ATT&CK kill chain visualization (13 phases with matched technique badges)
- Flag detection banner (pulsing red when CTF flags are found)
- Findings panel with severity badges, confidence scores, and MITRE ATT&CK tags (click for evidence drill-down)
- File metadata, stat cards, protocol breakdown bar chart, top talkers chart
- Interactive network graph (force-directed, hosts as nodes, flows as edges)
- Dynamic protocol tabs: Flows, Streams, HTTP, DNS, TLS, FTP, SSH, Telnet, DHCP, SMB, Credentials, Artifacts, IOCs, Hosts, Timeline
- IOC panel with async threat intelligence enrichment (VT, AbuseIPDB, Shodan, OTX, GeoIP country flags)
- Stream viewer with Follow Stream from Flows table, Copy to clipboard, Hex view toggle
- Search bar to filter all tables
- Flag highlighting throughout all views
- JSON export + PDF export (print-friendly)

Options:
```bash
wirehunt serve --port 9999      # custom port
wirehunt serve --no-open        # don't auto-open browser
```

### CLI Analysis

```bash
wirehunt analyze capture.pcap --out case/ --profile ctf
```

This runs the full 8-step pipeline and writes `case/report.json`. Profiles: `ctf`, `ir`, `forensics`, `threat-hunt`, `quick`.

### Terminal TUI

```bash
wirehunt-tui case/
```

Keyboard: `1-7` switch tabs, `j/k` scroll, `Enter` detail view, `Esc` back, `?` help, `q` quit.

### All CLI Subcommands

```bash
wirehunt analyze <pcap> --out <dir> --profile <profile>
wirehunt hunt <case-dir> --ctf --creds --files --anomalies --exfil
wirehunt query <case-dir> '<dsl-query>'
wirehunt extract <case-dir> --decode "base64 | xor:0x42 | gunzip"
wirehunt export <case-dir> --html --json --stix
wirehunt live <interface> --profile ctf --alert "flag{"
wirehunt ai explain <case-dir>
wirehunt ai solve <case-dir>
wirehunt serve --port 8888
```

### Search Index and Query DSL

```bash
# Analyze with index building enabled
wirehunt analyze capture.pcap --out case/ --profile ctf --index

# Free text search across all data
wirehunt query case/ 'evil.com'

# Scoped search by data type
wirehunt query case/ 'dns:evil.com'
wirehunt query case/ 'http:admin'
wirehunt query case/ 'credentials:password'
wirehunt query case/ 'findings:critical'

# Output formats
wirehunt query case/ 'flag' --format json
wirehunt query case/ 'flag' --format csv
```

### Export Reports

```bash
# Generate standalone HTML report (self-contained, dark theme)
wirehunt export case/ --html

# Export as JSON
wirehunt export case/ --json

# Export as STIX 2.1 bundle
wirehunt export case/ --stix

# Custom output path
wirehunt export case/ --html --output report.html
```

### Live Capture

Requires the `live` feature flag and libpcap/Npcap:

```bash
# Build with live capture support
cargo install --path crates/wirehunt-cli --features live

# List available network interfaces
wirehunt live --list

# Capture on an interface with CTF profile
wirehunt live eth0 --profile ctf

# Capture with pattern alerts
wirehunt live eth0 --alert "flag{" --alert "password"

# Capture with BPF filter and duration limit
wirehunt live eth0 --filter "tcp port 80" --duration 60 --out case/
```

### AI-Powered Analysis

Requires an API key (OpenAI, Anthropic) or local Ollama:

```bash
# Configure AI provider
wirehunt ai login

# Get AI narrative of what happened in the capture
wirehunt ai explain case/
wirehunt ai explain case/ --allow-raw    # include stream excerpts

# CTF-focused solving assistance
wirehunt ai solve case/

# AI-suggested search queries
wirehunt ai suggest-queries case/

# Generate detection rules from a finding
wirehunt ai generate-rule case/ --from-finding first

# AI-assisted decode of a stream or artifact
wirehunt ai decode case/ --id abc123
```

Set API keys via environment variables:
```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
```

Or create `~/.wirehunt/config.toml`:
```toml
provider = "openai"
api_key = "sk-..."
model = "gpt-4o"
max_tokens = 4096
temperature = 0.3
```

---

## Project Structure

```
WireGar/
  Cargo.toml                         # Workspace root
  Cargo.lock                         # Dependency lock file
  install.sh                         # Linux/macOS install script
  install.ps1                        # Windows install script
  .gitignore
  crates/
    wirehunt-core/                   # Core engine library
      Cargo.toml
      src/
        lib.rs                       # Crate root, re-exports all modules
        models.rs                    # All data types (30+ structs/enums)
        schema.rs                    # JSON schema generator
        ingest.rs                    # Pcap/pcapng reader
        session.rs                   # TCP reassembly + flow sessionization
        protocols/
          mod.rs                     # Protocol orchestrator + heuristic detection
          dns.rs                     # DNS parser
          http.rs                    # HTTP/1.x parser
          tls.rs                     # TLS handshake + JA3/JA3S
          icmp.rs                    # ICMP parser
          ftp.rs                     # FTP command + PASV/FTPS parser
          smtp.rs                    # SMTP session parser
          ssh.rs                     # SSH banner + kex parser
          telnet.rs                  # Telnet IAC + credential parser
          dhcp.rs                    # DHCP lease parser
          smb.rs                     # SMB/CIFS + NTLM parser
        extract.rs                   # Artifact extraction + flag detection + string sweep
        detect.rs                    # Detection rule engine (18 categories, 25+ malware signatures)
        crypto.rs                    # Decode pipeline (base64, hex, xor, gzip, etc.)
        credentials.rs               # Credential harvester
        entropy.rs                   # Shannon entropy analysis
        index.rs                     # SQLite FTS5 search index + query DSL
        iocextract.rs                # IOC extraction + DGA detection
        threatintel.rs               # Threat intel API client (VT, AbuseIPDB, Shodan, OTX, GeoIP, WHOIS)
        narrative.rs                 # Auto executive summary generator
        timeline.rs                  # Timeline event builder
        hostprofile.rs               # Host profiler (traffic analysis, service discovery)
      benches/
        parse_bench.rs               # Criterion benchmarks (stub)
    wirehunt-cli/                    # CLI binary
      Cargo.toml
      src/
        main.rs                      # Entry point, tracing setup, banner
        banner.rs                    # ASCII art banner
        commands/
          mod.rs                     # Clap command definitions + routing
          analyze.rs                 # Full 8-step analysis pipeline
          serve.rs                   # Web GUI server (axum + embedded HTML)
          hunt.rs                    # Rule pack runner (stub)
          query.rs                   # Search index query with table/JSON/CSV output
          extract.rs                 # Extraction subcommand (stub)
          export.rs                  # HTML, JSON, STIX 2.1 report export
          live.rs                    # Live capture with alerts (feature-gated)
          ai.rs                      # AI subcommands (explain, solve, decode, rulegen, login)
      static/
        index.html                   # Embedded web GUI dashboard (single-page app)
    wirehunt-tui/                    # Interactive TUI binary
      Cargo.toml
      src/
        main.rs                      # Entry point, terminal setup, event loop
        app.rs                       # Application state, tab management, keybindings
        ui.rs                        # Layout renderer, header, status bar, help overlay
        views/
          mod.rs                     # View module exports
          dashboard.rs               # Dashboard tab (file info, stats, protocol chart)
          flows.rs                   # Flows table tab
          streams.rs                 # Streams list + detail viewer
          artifacts.rs               # Artifacts table tab
          credentials.rs             # Credentials table tab
          dns.rs                     # DNS records tab
          http.rs                    # HTTP transactions tab
    wirehunt-ai/                     # AI-powered analysis layer
      Cargo.toml
      src/
        lib.rs                       # Re-exports and crate root
        provider.rs                  # Multi-provider AI client (OpenAI, Anthropic, Ollama)
        copilot.rs                   # Analyst copilot + report summarizer
        decoder.rs                   # AI decode assistant
        rulegen.rs                   # AI rule generator (Suricata, Sigma)
    wirehunt-rules/                  # Detection rules engine
      Cargo.toml
      src/
        lib.rs                       # Module exports
        ctf.rs                       # CTF rule pack (stub)
        creds.rs                     # Credential rule pack (stub)
        ioc.rs                       # IOC rule pack (stub)
        anomaly.rs                   # Anomaly rule pack (stub)
        exfil.rs                     # Exfiltration rule pack (stub)
  tests/
    fixtures/
      test_http.pcap                 # Test pcap with HTTP + DNS + flag
  schemas/                           # JSON schema output directory
  docs/                              # Documentation directory
```

---

## Code Walkthrough

### Core Engine (wirehunt-core)

**models.rs** -- Defines every data type used throughout the engine. The `Report` struct is the primary API contract between all components. Key types:
- `FlowKey`: 5-tuple (src_ip, dst_ip, src_port, dst_port, protocol) for flow identification
- `Flow`: A network flow with metadata, packet/byte counts, detected protocol, TCP flags
- `Stream`: Reassembled byte content with ordered segments and client/server direction markers
- `StreamSegment`: A chunk of data within a stream with direction and timestamp
- `Artifact`: An extracted file with MIME type, SHA256/MD5 hashes, and source evidence
- `Credential`: A harvested authentication credential with type, username, secret, and evidence
- `Finding`: A detection result with severity, confidence, MITRE ATT&CK tags, evidence references, and suggested pivots
- `EvidenceRef`: Links any finding back to a specific pcap offset, stream, or artifact
- `Report`: Top-level container holding all analysis results

**ingest.rs** -- Reads pcap and pcapng files. Uses `pcap-parser` for zero-copy file parsing and `etherparse` for packet header parsing. Handles Ethernet (with VLAN tag stripping), Raw IP, BSD Loopback, and Linux Cooked Capture link types. Produces a `Vec<ParsedPacket>` with normalized IP addresses, transport layer info (TCP flags, sequence numbers, ports), and payload bytes.

**session.rs** -- Groups packets into flows and reassembles TCP streams. The `TcpState` struct tracks the handshake and maps which canonical direction is the actual TCP client (the SYN sender). This is critical because the canonical key ordering (used for HashMap lookup) does not necessarily correspond to client/server. Each direction has its own reorder buffer and expected sequence number. Mid-stream pickup is supported: if no SYN is seen, the first data packet's sequence number becomes the starting point.

**protocols/mod.rs** -- Orchestrates protocol dissection across 10 protocols. Routes each stream to the appropriate parser based on port-guessed protocol. Falls back to heuristic detection (inspecting first bytes) for streams on non-standard ports. Returns a `DissectionResults` struct containing parsed DNS records, HTTP transactions, TLS sessions, ICMP summaries, FTP sessions, SMTP sessions, SSH sessions, Telnet sessions, DHCP leases, and SMB sessions.

**protocols/dns.rs** -- Full DNS message parser. Handles the recursive name compression pointer algorithm. Parses question and answer sections. Supports A, AAAA, CNAME, NS, PTR, MX, TXT, SOA, SRV, DNSKEY, and other record types.

**protocols/http.rs** -- Parses HTTP/1.0 and HTTP/1.1 request/response pairs from reassembled TCP streams. Extracts method, URI, host, status code, all headers, cookies, user-agent, content-type. Supports chunked transfer-encoding. Handles pipelined requests (multiple request/response pairs in one stream).

**protocols/tls.rs** -- Parses TLS ClientHello and ServerHello messages. Extracts version, SNI, ALPN, cipher suites, extensions, elliptic curves, EC point formats. Computes JA3 (client fingerprint) and JA3S (server fingerprint) MD5 hashes per the original spec. Filters GREASE values.

**protocols/icmp.rs** -- Parses ICMP type and code with human-readable names. Collects Echo Request/Reply payloads for covert channel and CTF exfiltration detection.

**protocols/ftp.rs** -- Parses FTP control channel commands. Extracts USER/PASS credentials, RETR/STOR file transfer filenames, PASV/EPSV/PORT data channel ports, and AUTH TLS (FTPS) detection. Tracks transfer bytes per session.

**protocols/smtp.rs** -- Parses SMTP session flow. Extracts EHLO domain, MAIL FROM, RCPT TO, email subject, DATA body content. Decodes AUTH LOGIN (base64 line-by-line) and AUTH PLAIN (base64 null-delimited) credentials.

**extract.rs** -- Runs four extraction passes: (1) string sweep for URLs, emails, base64 blobs, hex blobs via regex; (2) auto-decode of interesting strings up to 3 layers deep; (3) HTTP response body carving with MIME detection and hashing; (4) flag pattern sweep across all content including decoded strings. Deduplicates flags by value and artifacts by SHA256.

**crypto.rs** -- Multi-layer decode pipeline. `auto_decode()` recursively tries all single-layer decodings (base64, base32, hex, URL, ROT13, gzip, zlib, XOR brute-force) up to a configurable depth. `apply_chain()` executes a named pipeline string like `"base64 | xor:0x42 | gunzip"`. XOR brute-force (all 255 single-byte keys) only reports results where the output becomes mostly printable ASCII.

**credentials.rs** -- Scans all dissected protocol data and raw stream content for credentials. Uses lazy-initialized compiled regexes for JWT, AWS keys, GitHub tokens, Slack tokens, API key patterns, private key blocks, and password form fields.

**detect.rs** -- Professional-grade detection engine with 18 rule categories. Data exfiltration analysis (bytes out per external IP, asymmetric flows), C2 beaconing detection (periodic connection timing analysis), 25+ known malware JA3 fingerprints (CobaltStrike, AgentTesla, Emotet, etc.), C2 URI pattern matching, FTPS exfiltration detection, TLS anomalies (no-SNI, self-signed, deprecated versions), DNS anomalies (DGA, fast-flux, NXDOMAIN), lateral movement, port scanning, short-lived encrypted connections. All findings include MITRE ATT&CK technique IDs. Results sorted by severity then confidence.

**entropy.rs** -- Computes Shannon entropy (0-8 bits per byte) on byte slices. Classifies data as encrypted (>7.5), compressed (>6.5), mixed, structured, or repetitive.

**index.rs** -- SQLite FTS5 full-text search index. Creates virtual tables for streams, DNS records, HTTP transactions, credentials, artifacts, findings, and TLS sessions. `SearchIndex::build_from_report()` populates all tables from a Report struct. `SearchIndex::query()` parses a simple DSL (free text or `table:term` scoped searches) and returns ranked results. Uses FTS5's built-in BM25 ranking.

### CLI (wirehunt-cli)

**commands/analyze.rs** -- The main analysis pipeline. Runs 8 sequential steps: ingest, sessionize, dissect protocols, extract artifacts and credentials, flow summary, entropy analysis, detection rules, and report writing. Optional step 9 builds the SQLite FTS5 search index when `--index` is passed. Prints colored output at each step showing what was found.

**commands/serve.rs** -- Starts an axum web server with three endpoints: `GET /` serves the embedded HTML dashboard, `POST /api/analyze` accepts multipart file upload and runs the full analysis pipeline returning JSON, `GET /api/report` returns the last analysis result. Supports files up to 500MB. Auto-opens the browser on startup.

**commands/query.rs** -- Reads the SQLite FTS5 index from a case directory and executes queries. Supports free text search (searches all tables) and scoped search (e.g., `dns:evil.com` searches only DNS records). Output formats: colored table (default), JSON, or CSV.

**commands/export.rs** -- Generates reports in multiple formats. `--html` produces a self-contained single-file HTML report with the Catppuccin Mocha dark theme, tabbed data sections, severity badges, MITRE ATT&CK tags, protocol breakdown, search/filter, and embedded JSON for client-side interaction. `--json` copies the report. `--stix` generates a STIX 2.1 bundle with indicators for findings and observed-data for credentials.

**commands/live.rs** -- Live packet capture from a network interface using the `pcap` crate (feature-gated behind `--features live`). Opens a promiscuous capture, applies optional BPF filter, parses packets through the existing ingest/session/dissect pipeline, and alerts in real-time when user-specified regex patterns match. On Ctrl+C, finalizes analysis and writes a full report. Lists available interfaces with `--list`.

**commands/ai.rs** -- AI-powered analysis subcommands. `explain` sends a compressed report summary to an LLM for narrative analysis. `solve` is CTF-focused, asking the LLM for flag-solving strategies. `decode` sends stream/artifact data for encoding identification. `generate-rule` produces Suricata/Sigma rules from findings. `suggest-queries` generates useful search queries. `login` configures the AI provider and API key.

**static/index.html** -- Self-contained single-page web application (no external dependencies). Catppuccin Mocha dark theme. Features: auto executive summary, MITRE ATT&CK kill chain visualization, interactive Canvas-based network graph, drag-and-drop file upload, threat intel enrichment (VT/AbuseIPDB/Shodan/OTX/GeoIP), flag detection banner, findings drill-down with evidence, stat cards, protocol breakdown, top talkers chart, search/filter, dynamic protocol tabs (Flows, Streams, HTTP, DNS, TLS, FTP, SSH, Telnet, DHCP, SMB, Credentials, Artifacts, IOCs, Hosts, Network Graph, Timeline), stream viewer with Follow/Copy/Hex, flag highlighting, JSON + PDF export.

### AI Layer (wirehunt-ai)

**provider.rs** -- Multi-provider AI client abstraction. Supports OpenAI (GPT-4o), Anthropic (Claude), and Ollama (local models). Unified `chat()` async API that routes to the correct provider's API endpoint. Configuration loaded from `~/.wirehunt/config.toml` with environment variable overrides (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `OLLAMA_URL`).

**copilot.rs** -- Analyst copilot with three modes: `explain` (narrative forensic analysis), `solve` (CTF flag solving), and `suggest_queries` (search recommendations). Includes `summarize_report()` which compresses a full Report into an LLM-safe text summary under token limits, including metadata, findings, credentials, DNS/HTTP/TLS highlights, and optionally raw stream excerpts.

**decoder.rs** -- AI decode assistant. Sends encoded data to an LLM with context about its source, asking for encoding identification and suggesting WireHunt decode chains.

**rulegen.rs** -- AI rule generator. Takes a finding and asks the LLM to produce detection rules in Suricata, Sigma, and WireHunt query formats.

### TUI (wirehunt-tui)

**app.rs** -- Application state management. 7 tabs (Dashboard, Flows, Streams, Artifacts, Credentials, DNS, HTTP). Vim-style navigation: j/k scroll, g/G top/bottom, d/u page up/down, Enter for detail, Esc to go back, 1-7 tab switch, Tab/Shift-Tab cycle, ? help.

**ui.rs** -- Main renderer using ratatui. Three-section layout: header (logo + tabs), content area, status bar. Catppuccin color scheme with cyan accent, RGB colors for protocol badges and severity indicators. Help overlay popup.

**views/*.rs** -- Each tab has its own render function. Dashboard shows file info, stat boxes, and protocol bar chart. Flows table has color-coded protocol badges and TCP flag display. Streams list has a detail view showing each segment with client/server coloring and data content. Credentials table highlights secrets in red.

---

## How the Analysis Pipeline Works

```
1. INGEST         Read pcap/pcapng, parse link/IP/transport headers
                  Output: Vec<ParsedPacket>

2. SESSIONIZE     Group by 5-tuple, track TCP handshake, reassemble streams
                  Output: Vec<Flow>, Vec<Stream>

3. DISSECT        Route streams to protocol parsers (DNS, HTTP, TLS, etc.)
                  Output: DissectionResults

4. EXTRACT        Carve files from HTTP, sweep for strings/flags, auto-decode
                  Output: ExtractionResults (artifacts, flags, decoded strings)

5. CREDENTIALS    Scan dissected data + raw streams for passwords/tokens/keys
                  Output: Vec<Credential>

6. DETECT         Run rules against all data, score findings, tag MITRE ATT&CK
                  Output: Vec<Finding>

7. REPORT         Assemble everything into Report struct, serialize to JSON
                  Output: report.json
```

---

## Report Format

The `report.json` file is the primary output. It contains:

- `metadata` -- WireHunt version, generation timestamp, pcap filename, SHA256, file size, packet count, capture start/end times, duration, analysis profile
- `executive_summary` -- Auto-generated plain English narrative of the capture
- `findings` -- Array of scored detections, each with id, title, description, severity, confidence, category, evidence references, suggested pivots, MITRE ATT&CK technique IDs
- `flows` -- Array of network flows with 5-tuple key, timestamps, packet/byte counts per direction, detected application protocol, TCP flags, stream IDs
- `streams` -- Array of reassembled streams with ordered segments, each segment having direction (client_to_server/server_to_client) and byte data
- `artifacts` -- Array of extracted files with kind, name, MIME type, size, SHA256, MD5
- `credentials` -- Array of harvested credentials with kind, username, secret, service, host, evidence
- `iocs` -- Array of extracted IOCs with kind, value, confidence, MITRE tags
- `dns_records` -- Array of parsed DNS queries and responses with query name, record type, response data, TTL
- `http_transactions` -- Array of HTTP request/response pairs with method, URI, host, status code, headers, cookies, user-agent, content-type, body sizes
- `tls_sessions` -- Array of TLS handshake metadata with version, SNI, ALPN, cipher suite, JA3/JA3S hashes
- `ftp_sessions` -- Array of FTP sessions with user/pass, files transferred, PASV ports, AUTH TLS status
- `ssh_sessions` -- Array of SSH sessions with client/server banners, versions, kex algorithms, ciphers
- `telnet_sessions` -- Array of Telnet sessions with credentials, IAC negotiation options, content
- `dhcp_leases` -- Array of DHCP messages with MAC, assigned IP, hostname, gateway, DNS servers, lease time
- `smb_sessions` -- Array of SMB sessions with version, commands, shares, NTLM domains/users
- `host_profiles` -- Array of per-host profiles with IP, hostnames, services, traffic stats
- `timeline` -- Array of chronological events with timestamp, type, severity, summary
- `statistics` -- Protocol breakdown counts, top talkers, top ports, totals, analysis duration

---

## Current Status

### Completed

- Phase 0: Project scaffold, Rust toolchain, Cargo workspace
- Phase 1: Data models (30+ types), JSON schema generation
- Phase 2: Pcap/pcapng ingestion, TCP reassembly, UDP grouping, flow sessionization
- Phase 3: Protocol dissectors (DNS, HTTP, TLS/JA3, ICMP, FTP, SMTP, SSH, Telnet, DHCP, SMB) with heuristic detection
- Phase 4: Artifact extraction, string sweep, multi-layer decode pipeline, credential harvester, entropy analysis
- Phase 5: Detection engine with MITRE ATT&CK tagging and confidence scoring
- Phase 5b: IOC extraction (IPs, domains, URLs, file hashes, JA3/JA3S, user-agents, DGA detection)
- Phase 5c: Host profiling (per-host traffic analysis, service discovery, hostname resolution)
- Phase 5d: Timeline generation (chronological events from flows, findings, HTTP, credentials)
- Phase 5e: Auto executive summary (rule-based narrative, no AI required)
- Phase 6: SQLite FTS5 search index and query DSL (`wirehunt query` command)
- Phase 7: Interactive ratatui TUI with 7 tabs and Vim keybindings
- Phase 8: Standalone HTML report export, JSON export, STIX 2.1 bundle export
- Phase 9: Live network capture mode with real-time alerts (feature-gated, requires libpcap/Npcap)
- Phase 10: AI-powered analysis (OpenAI, Anthropic, Ollama) with explain, solve, decode, rule generation, query suggestions
- Phase 11: Threat intelligence enrichment (VirusTotal, AbuseIPDB, Shodan, AlienVault OTX, GeoIP, WHOIS)
- Web GUI: Professional dashboard with executive summary, MITRE kill chain, interactive network graph, threat intel enrichment, GeoIP flags, IOC reputation, host profiles, timeline, stream viewer with Follow/Copy/Hex, PDF export, 11 tabbed data sections
- One-command install scripts for Windows and Linux/macOS
- 46 unit tests passing across the entire workspace

### Remaining (Future)

- ICS/SCADA protocol support (Modbus, DNP3, S7comm, EtherNet/IP, OPC UA)
- YARA-X rule scanning for IOC detection
- Suricata rule compatibility
- Additional protocol dissectors (WebSocket, MQTT)

---

## Development

```bash
# Run all tests (46 tests across 5 crates)
cargo test

# Run with debug logging
RUST_LOG=wirehunt=debug cargo run --bin wirehunt -- analyze test.pcap --out case/

# Build optimized release binaries
cargo build --release

# Build with live capture support (requires libpcap/Npcap)
cargo build --release --features live

# Run benchmarks
cargo bench --package wirehunt-core
```

### Key Dependencies

- `pcap-parser` 0.16 -- Zero-copy pcap/pcapng parsing
- `etherparse` 0.16 -- Zero-allocation packet header parsing
- `nom` 7 -- Parser combinators for protocol dissection
- `tls-parser` 0.12 -- TLS message parsing
- `rusqlite` 0.32 -- SQLite with bundled library and FTS5
- `serde` + `serde_json` -- Serialization
- `regex` -- Pattern matching for flag/credential detection
- `sha2` + `md-5` -- Cryptographic hashing
- `base64` + `hex` + `flate2` + `percent-encoding` -- Decode pipeline
- `clap` 4 -- CLI framework with derive macros
- `axum` 0.8 -- Web server for GUI
- `ratatui` 0.29 + `crossterm` 0.28 -- Terminal UI
- `reqwest` 0.12 -- HTTP client for AI APIs
- `toml` 0.8 -- Configuration file parsing
- `pcap` 2 -- Live packet capture (optional, feature-gated)
- `chrono` -- Timestamps
- `uuid` -- Unique identifiers
- `tracing` -- Structured logging
- `tokio` -- Async runtime

---

## License

MIT

## Author

Brandon Cheong
