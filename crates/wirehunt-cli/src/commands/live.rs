use anyhow::Result;
use clap::Args;

#[derive(Args)]
pub struct LiveArgs {
    /// Network interface to capture from (or --list to show available)
    #[arg(default_value = "")]
    pub interface: String,

    /// List available network interfaces
    #[arg(long, default_value_t = false)]
    pub list: bool,

    /// Analysis profile
    #[arg(short, long, default_value = "ctf")]
    pub profile: String,

    /// Alert patterns (can be specified multiple times)
    #[arg(long)]
    pub alert: Vec<String>,

    /// Duration in seconds (0 = indefinite)
    #[arg(short, long, default_value_t = 0)]
    pub duration: u64,

    /// BPF capture filter
    #[arg(long)]
    pub filter: Option<String>,

    /// Output directory for final report
    #[arg(short, long)]
    pub out: Option<std::path::PathBuf>,

    /// Maximum packets to capture (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    pub max_packets: u64,
}

#[cfg(feature = "live")]
pub fn run(args: LiveArgs) -> Result<()> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Instant;

    use wirehunt_core::ingest::ParsedPacket;
    use wirehunt_core::models::*;
    use wirehunt_core::session::SessionManager;

    if args.list {
        return list_interfaces();
    }

    if args.interface.is_empty() {
        println!(
            "  {} specify an interface or use --list to see available ones",
            console::style("error:").red().bold(),
        );
        list_interfaces()?;
        return Ok(());
    }

    println!(
        "\n  {} on interface '{}'",
        console::style("LIVE CAPTURE").cyan().bold(),
        console::style(&args.interface).green().bold(),
    );
    if let Some(ref f) = args.filter {
        println!(
            "  {} {}",
            console::style("BPF filter:").cyan(),
            f,
        );
    }
    if !args.alert.is_empty() {
        println!(
            "  {} {:?}",
            console::style("alert patterns:").cyan(),
            args.alert,
        );
    }
    let dur_display = if args.duration == 0 {
        "indefinite".to_string()
    } else {
        format!("{}s", args.duration)
    };
    println!(
        "  {} profile={}, duration={}, max_packets={}",
        console::style("config:").cyan(),
        args.profile,
        dur_display,
        if args.max_packets == 0 {
            "unlimited".to_string()
        } else {
            args.max_packets.to_string()
        },
    );
    println!(
        "  {} press Ctrl+C to stop and generate report\n",
        console::style("-->").yellow(),
    );

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    let device = pcap::Device::list()?
        .into_iter()
        .find(|d| d.name == args.interface)
        .ok_or_else(|| anyhow::anyhow!("interface '{}' not found", args.interface))?;

    let mut cap = pcap::Capture::from_device(device)?
        .promisc(true)
        .snaplen(65535)
        .timeout(1000)
        .open()?;

    if let Some(ref filter) = args.filter {
        cap.filter(filter, true)?;
    }

    let started = Instant::now();
    let mut packet_count: u64 = 0;
    let mut alert_count: u64 = 0;
    let mut session_mgr = SessionManager::new();
    let mut raw_packets: Vec<ParsedPacket> = Vec::new();

    let alert_patterns: Vec<regex::Regex> = args
        .alert
        .iter()
        .filter_map(|p| regex::Regex::new(p).ok())
        .collect();

    while running.load(Ordering::SeqCst) {
        if args.duration > 0 && started.elapsed().as_secs() >= args.duration {
            println!(
                "\n  {} duration limit reached ({}s)",
                console::style("stopping:").yellow().bold(),
                args.duration,
            );
            break;
        }

        if args.max_packets > 0 && packet_count >= args.max_packets {
            println!(
                "\n  {} packet limit reached ({})",
                console::style("stopping:").yellow().bold(),
                args.max_packets,
            );
            break;
        }

        match cap.next_packet() {
            Ok(packet) => {
                packet_count += 1;
                let data = packet.data.to_vec();

                if let Some(parsed) = wirehunt_core::ingest::parse_raw_ethernet_packet(
                    &data,
                    packet_count,
                    packet.header.ts.tv_sec as i64,
                    packet.header.ts.tv_usec as u32,
                ) {
                    for pattern in &alert_patterns {
                        if let Ok(payload_str) = std::str::from_utf8(&parsed.payload) {
                            if pattern.is_match(payload_str) {
                                alert_count += 1;
                                println!(
                                    "  {} [pkt {}] pattern '{}' matched in {}:{} -> {}:{}",
                                    console::style("ALERT").red().bold(),
                                    packet_count,
                                    pattern.as_str(),
                                    parsed.flow_key.src_ip,
                                    parsed.flow_key.src_port,
                                    parsed.flow_key.dst_ip,
                                    parsed.flow_key.dst_port,
                                );
                            }
                        }
                    }

                    raw_packets.push(parsed);
                }

                if packet_count % 100 == 0 {
                    print!(
                        "\r  {} {} packets, {} alerts, {:.1}s elapsed",
                        console::style("live:").cyan(),
                        packet_count,
                        alert_count,
                        started.elapsed().as_secs_f64(),
                    );
                }
            }
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                println!(
                    "\n  {} capture error: {}",
                    console::style("error:").red().bold(),
                    e,
                );
                break;
            }
        }
    }

    println!(
        "\n\n  {} {} packets captured in {:.1}s ({} alerts)",
        console::style("capture complete:").green().bold(),
        packet_count,
        started.elapsed().as_secs_f64(),
        alert_count,
    );

    if raw_packets.is_empty() {
        println!(
            "  {} no packets to analyze",
            console::style("note:").yellow(),
        );
        return Ok(());
    }

    println!(
        "  {}",
        console::style("analyzing captured traffic...").cyan().bold(),
    );

    session_mgr.process_packets(&raw_packets);
    let (flows, streams) = session_mgr.finalize();

    let dissection = wirehunt_core::protocols::dissect_all(&flows, &streams);

    let out_dir = args.out.unwrap_or_else(|| {
        let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
        std::path::PathBuf::from(format!("live_{}", ts))
    });
    std::fs::create_dir_all(&out_dir)?;
    std::fs::create_dir_all(out_dir.join("artifacts"))?;

    let extraction =
        wirehunt_core::extract::run_extraction(&streams, &dissection, &out_dir);
    let credentials =
        wirehunt_core::credentials::harvest_credentials(&dissection, &streams);

    let saved_flags: Vec<(String, String, Option<String>)> = extraction
        .flag_candidates
        .iter()
        .map(|f| (f.value.clone(), f.stream_id.clone(), f.decode_chain.clone()))
        .collect();

    let mut proto_counts = std::collections::HashMap::new();
    for flow in &flows {
        let name = flow
            .detected_protocol
            .map(|p| format!("{:?}", p))
            .unwrap_or_else(|| "Unknown".to_string());
        *proto_counts.entry(name).or_insert(0u64) += 1;
    }

    let profile = match args.profile.as_str() {
        "ir" => AnalysisProfile::IncidentResponse,
        "forensics" => AnalysisProfile::Forensics,
        "threat-hunt" => AnalysisProfile::ThreatHunt,
        "quick" => AnalysisProfile::Quick,
        _ => AnalysisProfile::Ctf,
    };

    let mut report = Report {
        metadata: ReportMetadata {
            wirehunt_version: wirehunt_core::VERSION.to_string(),
            generated_at: chrono::Utc::now(),
            pcap_filename: format!("live:{}", args.interface),
            pcap_sha256: "live-capture".to_string(),
            pcap_size_bytes: 0,
            total_packets: packet_count,
            capture_start: raw_packets.first().map(|p| p.timestamp),
            capture_end: raw_packets.last().map(|p| p.timestamp),
            capture_duration_secs: started.elapsed().as_secs_f64(),
            profile,
        },
        findings: Vec::new(),
        flows,
        streams,
        artifacts: extraction.artifacts,
        credentials,
        iocs: Vec::new(),
        dns_records: dissection.dns_records,
        http_transactions: dissection.http_transactions,
        tls_sessions: dissection.tls_sessions,
        host_profiles: Vec::new(),
        timeline: Vec::new(),
        statistics: AnalysisStatistics {
            protocol_breakdown: proto_counts,
            top_talkers: Vec::new(),
            top_ports: Vec::new(),
            total_findings: 0,
            total_artifacts: 0,
            total_credentials: 0,
            analysis_duration_ms: started.elapsed().as_millis() as u64,
        },
    };

    let findings = wirehunt_core::detect::run_detection(&report, &saved_flags);
    report.statistics.total_findings = findings.len() as u64;
    report.findings = findings;

    let report_path = out_dir.join("report.json");
    let report_json = serde_json::to_string_pretty(&report)?;
    std::fs::write(&report_path, &report_json)?;

    println!(
        "\n  {} {}",
        console::style("report ->").green().bold(),
        report_path.display(),
    );
    println!(
        "  {} {} flows, {} streams, {} findings, {} credentials",
        console::style("results:").white().bold(),
        report.flows.len(),
        report.streams.len(),
        report.statistics.total_findings,
        report.credentials.len(),
    );

    if !extraction.flag_candidates.is_empty() {
        println!(
            "  {} {}",
            console::style("FLAGS FOUND:").red().bold(),
            extraction.flag_candidates.len(),
        );
        for flag in &extraction.flag_candidates {
            println!(
                "    {} [{}]",
                console::style(&flag.value).red().bold(),
                flag.decode_chain.as_deref().unwrap_or("plaintext"),
            );
        }
    }

    Ok(())
}

#[cfg(feature = "live")]
fn list_interfaces() -> Result<()> {
    let devices = pcap::Device::list()?;
    if devices.is_empty() {
        println!(
            "  {} no network interfaces found (need root/admin?)",
            console::style("warning:").yellow().bold(),
        );
        return Ok(());
    }

    println!(
        "\n  {} {} available interfaces:\n",
        console::style("network:").cyan().bold(),
        devices.len(),
    );

    for (i, dev) in devices.iter().enumerate() {
        let desc = dev
            .desc
            .as_deref()
            .unwrap_or("(no description)");
        let addrs: Vec<String> = dev
            .addresses
            .iter()
            .map(|a| a.addr.to_string())
            .collect();
        let addr_str = if addrs.is_empty() {
            String::new()
        } else {
            format!(" [{}]", addrs.join(", "))
        };

        println!(
            "  {:>3}. {} -- {}{}",
            i + 1,
            console::style(&dev.name).green().bold(),
            desc,
            console::style(addr_str).cyan(),
        );
    }
    println!();

    Ok(())
}

#[cfg(not(feature = "live"))]
pub fn run(_args: LiveArgs) -> Result<()> {
    println!(
        "  {} live capture requires the 'live' feature flag",
        console::style("error:").red().bold(),
    );
    println!();
    println!("  Rebuild with live capture support:");
    println!();
    println!(
        "    {}",
        console::style("cargo install --path crates/wirehunt-cli --features live").cyan(),
    );
    println!();
    println!("  Prerequisites:");
    println!("    Linux/macOS: libpcap-dev (apt install libpcap-dev / brew install libpcap)");
    println!("    Windows:     Npcap SDK (https://npcap.com/#download)");

    Ok(())
}
