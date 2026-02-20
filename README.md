# WireHunt

All-in-one network forensic engine for CTF competitions, incident response, IOC detection, credential harvesting, and protocol analysis. Built from scratch in Rust for maximum performance, memory safety, and cross-platform deployment.

WireHunt replaces the need to manually use Wireshark, tshark, NetworkMiner, and other tools. Drop a pcap file in and it does everything: reassembles TCP streams, parses protocols, extracts files, finds flags, harvests credentials, and scores findings with MITRE ATT&CK tags.

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

**Protocol Dissectors**
- DNS: query/response parsing, name decompression (pointer support), A/AAAA/CNAME/NS/PTR/MX/TXT/SOA record types, response codes
- HTTP/1.0 and HTTP/1.1: request/response parsing, header extraction, cookie extraction, user-agent, chunked transfer-encoding support
- TLS: ClientHello/ServerHello parsing, SNI extraction, ALPN, cipher suites, JA3 and JA3S fingerprint computation, GREASE filtering
- ICMP: type/code parsing with human-readable names, embedded payload collection for covert channel detection
- FTP: command parsing, USER/PASS credential extraction, RETR/STOR file transfer tracking
- SMTP: session parsing, MAIL FROM/RCPT TO extraction, AUTH LOGIN and AUTH PLAIN credential decoding, email body and subject extraction
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

**Detection Engine**
- Generates scored findings with severity (Critical/High/Medium/Low/Info) and confidence (0-100%)
- MITRE ATT&CK technique tags on all findings
- Detects: CTF flags, cleartext protocol usage (FTP/Telnet), DNS anomalies (long names, large TXT records), suspicious HTTP user-agents, large file downloads, self-signed TLS certificates, ICMP covert channels
- Findings sorted by severity then confidence

**Entropy Analysis**
- Shannon entropy calculation on all stream content
- Classification: encrypted (>7.5), compressed (>6.5), mixed, structured, repetitive

**Three Interfaces**
- Web GUI: drag-and-drop browser dashboard at localhost:8888
- Terminal TUI: interactive ratatui-based interface with Vim keybindings
- CLI: scriptable command-line interface with JSON output

---

## Installation

### Prerequisites

- [Rust toolchain](https://rustup.rs/) version 1.80 or later
- Git

### Build from Source

```bash
git clone https://github.com/brand/WireGar.git
cd WireGar
cargo build --release
```

The binaries will be at `target/release/wirehunt` and `target/release/wirehunt-tui`.

### Install to PATH

```bash
cargo install --path crates/wirehunt-cli
cargo install --path crates/wirehunt-tui
```

### Quick Install Scripts

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

This starts a local web server at `http://localhost:8888` and opens your browser. Drag and drop any `.pcap` or `.pcapng` file onto the page. WireHunt analyzes it and displays results in a dark-themed dashboard with:
- Flag detection banner (pulsing red when flags are found)
- Findings panel with severity badges and MITRE ATT&CK tags
- File metadata (name, SHA256, size, packets, duration, profile)
- Stat cards (flows, streams, artifacts, credentials, findings, DNS, HTTP counts)
- Protocol breakdown bar chart
- Search bar to filter all tables
- Tabbed data tables: Flows, Streams, HTTP, DNS, Credentials, Artifacts
- Stream viewer modal with text and hex views, client/server direction coloring
- Flag highlighting throughout all views
- JSON export button

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

Note: `hunt`, `query`, `extract`, `export`, `live`, and `ai` subcommands are defined but not yet fully implemented. The core `analyze` and `serve` commands are fully functional.

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
          ftp.rs                     # FTP command parser
          smtp.rs                    # SMTP session parser
        extract.rs                   # Artifact extraction + flag detection + string sweep
        detect.rs                    # Detection rule engine
        crypto.rs                    # Decode pipeline (base64, hex, xor, gzip, etc.)
        credentials.rs               # Credential harvester
        entropy.rs                   # Shannon entropy analysis
        index.rs                     # SQLite FTS5 index (stub)
        timeline.rs                  # Timeline builder (stub)
        hostprofile.rs               # Host profiler (stub)
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
          query.rs                   # Query DSL (stub)
          extract.rs                 # Extraction subcommand (stub)
          export.rs                  # Export subcommand (stub)
          live.rs                    # Live capture (stub)
          ai.rs                      # AI subcommands (stub)
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
    wirehunt-ai/                     # AI layer (stubs, not yet implemented)
      Cargo.toml
      src/
        lib.rs
        provider.rs                  # Provider abstraction (OpenAI, Anthropic, Ollama)
        copilot.rs                   # Analyst copilot
        decoder.rs                   # Decode assistant
        rulegen.rs                   # Rule generator
    wirehunt-rules/                  # Detection rules (stubs, not yet implemented)
      Cargo.toml
      src/
        lib.rs
        ctf.rs                       # CTF rule pack
        creds.rs                     # Credential rule pack
        ioc.rs                       # IOC rule pack
        anomaly.rs                   # Anomaly rule pack
        exfil.rs                     # Exfiltration rule pack
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

**protocols/mod.rs** -- Orchestrates protocol dissection. Routes each stream to the appropriate parser based on the port-guessed protocol. Falls back to heuristic detection (inspecting first bytes) for streams on non-standard ports. Returns a `DissectionResults` struct containing parsed DNS records, HTTP transactions, TLS sessions, ICMP summaries, FTP sessions, and SMTP sessions.

**protocols/dns.rs** -- Full DNS message parser. Handles the recursive name compression pointer algorithm. Parses question and answer sections. Supports A, AAAA, CNAME, NS, PTR, MX, TXT, SOA, SRV, DNSKEY, and other record types.

**protocols/http.rs** -- Parses HTTP/1.0 and HTTP/1.1 request/response pairs from reassembled TCP streams. Extracts method, URI, host, status code, all headers, cookies, user-agent, content-type. Supports chunked transfer-encoding. Handles pipelined requests (multiple request/response pairs in one stream).

**protocols/tls.rs** -- Parses TLS ClientHello and ServerHello messages. Extracts version, SNI, ALPN, cipher suites, extensions, elliptic curves, EC point formats. Computes JA3 (client fingerprint) and JA3S (server fingerprint) MD5 hashes per the original spec. Filters GREASE values.

**protocols/icmp.rs** -- Parses ICMP type and code with human-readable names. Collects Echo Request/Reply payloads for covert channel and CTF exfiltration detection.

**protocols/ftp.rs** -- Parses FTP control channel commands. Extracts USER/PASS credentials and RETR/STOR file transfer filenames.

**protocols/smtp.rs** -- Parses SMTP session flow. Extracts EHLO domain, MAIL FROM, RCPT TO, email subject, DATA body content. Decodes AUTH LOGIN (base64 line-by-line) and AUTH PLAIN (base64 null-delimited) credentials.

**extract.rs** -- Runs four extraction passes: (1) string sweep for URLs, emails, base64 blobs, hex blobs via regex; (2) auto-decode of interesting strings up to 3 layers deep; (3) HTTP response body carving with MIME detection and hashing; (4) flag pattern sweep across all content including decoded strings. Deduplicates flags by value and artifacts by SHA256.

**crypto.rs** -- Multi-layer decode pipeline. `auto_decode()` recursively tries all single-layer decodings (base64, base32, hex, URL, ROT13, gzip, zlib, XOR brute-force) up to a configurable depth. `apply_chain()` executes a named pipeline string like `"base64 | xor:0x42 | gunzip"`. XOR brute-force (all 255 single-byte keys) only reports results where the output becomes mostly printable ASCII.

**credentials.rs** -- Scans all dissected protocol data and raw stream content for credentials. Uses lazy-initialized compiled regexes for JWT, AWS keys, GitHub tokens, Slack tokens, API key patterns, private key blocks, and password form fields.

**detect.rs** -- Runs all detection rules against the fully-built report. Generates findings for: CTF flags (Critical), harvested credentials (High/Medium), cleartext protocol usage (Medium), DNS anomalies like long names or large TXT records (Medium/Low), suspicious HTTP user-agents (Low), large downloads (Info), self-signed TLS certs (Medium), ICMP covert channels (Medium). All findings include MITRE ATT&CK technique IDs. Results are sorted by severity then confidence.

**entropy.rs** -- Computes Shannon entropy (0-8 bits per byte) on byte slices. Classifies data as encrypted (>7.5), compressed (>6.5), mixed, structured, or repetitive.

### CLI (wirehunt-cli)

**commands/analyze.rs** -- The main analysis pipeline. Runs 8 sequential steps: ingest, sessionize, dissect protocols, extract artifacts and credentials, flow summary, entropy analysis, detection rules, and report writing. Prints colored output at each step showing what was found.

**commands/serve.rs** -- Starts an axum web server with three endpoints: `GET /` serves the embedded HTML dashboard, `POST /api/analyze` accepts multipart file upload and runs the full analysis pipeline returning JSON, `GET /api/report` returns the last analysis result. Supports files up to 500MB. Auto-opens the browser on startup.

**static/index.html** -- Self-contained single-page web application (no external dependencies). Dark theme using CSS custom properties (Catppuccin Mocha palette). Features: drag-and-drop file upload, flag detection banner, findings panel, stat cards, protocol breakdown chart, search/filter bar, 6 tabbed data tables, stream viewer modal with text/hex toggle, flag highlighting via regex, JSON export.

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
- `findings` -- Array of scored detections, each with id, title, description, severity, confidence, category, evidence references, suggested pivots, MITRE ATT&CK technique IDs
- `flows` -- Array of network flows with 5-tuple key, timestamps, packet/byte counts per direction, detected application protocol, TCP flags, stream IDs
- `streams` -- Array of reassembled streams with ordered segments, each segment having direction (client_to_server/server_to_client) and byte data
- `artifacts` -- Array of extracted files with kind, name, MIME type, size, SHA256, MD5
- `credentials` -- Array of harvested credentials with kind, username, secret, service, host, evidence
- `dns_records` -- Array of parsed DNS queries and responses with query name, record type, response data, TTL
- `http_transactions` -- Array of HTTP request/response pairs with method, URI, host, status code, headers, cookies, user-agent, content-type, body sizes
- `tls_sessions` -- Array of TLS handshake metadata with version, SNI, ALPN, cipher suite, JA3/JA3S hashes
- `statistics` -- Protocol breakdown counts, top talkers, top ports, totals, analysis duration

---

## Current Status

### Completed

- Phase 0: Project scaffold, Rust toolchain, Cargo workspace
- Phase 1: Data models (30+ types), JSON schema generation
- Phase 2: Pcap/pcapng ingestion, TCP reassembly, UDP grouping, flow sessionization
- Phase 3: Protocol dissectors (DNS, HTTP, TLS/JA3, ICMP, FTP, SMTP) with heuristic detection
- Phase 4: Artifact extraction, string sweep, multi-layer decode pipeline, credential harvester, entropy analysis
- Phase 5: Detection engine with MITRE ATT&CK tagging and confidence scoring
- Phase 7: Interactive ratatui TUI with 7 tabs and Vim keybindings
- Web GUI: Drag-and-drop browser dashboard with axum server
- Install scripts for Windows and Linux/macOS
- 33 unit tests passing across the entire workspace

### Remaining (Planned for Next Phase)

- Phase 6: SQLite FTS5 search index and query DSL for the `wirehunt query` command
- Phase 8: Standalone HTML report export
- Phase 9: Live network capture mode
- Phase 10: AI layer (provider abstraction for OpenAI/Anthropic/Ollama, analyst copilot, decode assistant, rule generator)
- ICS/SCADA protocol support (Modbus, DNP3, S7comm, EtherNet/IP, OPC UA)
- YARA-X rule scanning for IOC detection
- Suricata rule compatibility
- More protocol dissectors (SSH banner, Telnet session, SMB/NTLM, WebSocket, MQTT, DHCP)

---

## Development

```bash
# Run all tests (33 tests across 5 crates)
cargo test

# Run with debug logging
RUST_LOG=wirehunt=debug cargo run --bin wirehunt -- analyze test.pcap --out case/

# Build optimized release binaries
cargo build --release

# Run benchmarks
cargo bench --package wirehunt-core
```

### Key Dependencies

- `pcap-parser` 0.16 -- Zero-copy pcap/pcapng parsing
- `etherparse` 0.16 -- Zero-allocation packet header parsing
- `nom` 7 -- Parser combinators for protocol dissection
- `tls-parser` 0.12 -- TLS message parsing
- `rusqlite` 0.32 -- SQLite with bundled library
- `serde` + `serde_json` -- Serialization
- `regex` -- Pattern matching for flag/credential detection
- `sha2` + `md-5` -- Cryptographic hashing
- `base64` + `hex` + `flate2` + `percent-encoding` -- Decode pipeline
- `clap` 4 -- CLI framework with derive macros
- `axum` 0.8 -- Web server for GUI
- `ratatui` 0.29 + `crossterm` 0.28 -- Terminal UI
- `chrono` -- Timestamps
- `uuid` -- Unique identifiers
- `tracing` -- Structured logging
- `tokio` -- Async runtime

---

## License

MIT

## Author

Brandon Cheong
