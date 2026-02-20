use std::path::PathBuf;
use std::time::Instant;

use anyhow::{Context, Result};
use clap::Args;

use wirehunt_core::ingest::PcapIngestor;
use wirehunt_core::models::*;
use wirehunt_core::session::SessionManager;

#[derive(Args)]
pub struct AnalyzeArgs {
    /// Path to the PCAP or PCAPNG file
    pub pcap: PathBuf,

    /// Output directory for case files (report.json, artifacts/, index.db)
    #[arg(short, long, default_value = "case")]
    pub out: PathBuf,

    /// Analysis profile
    #[arg(short, long, default_value = "ctf", value_parser = parse_profile)]
    pub profile: AnalysisProfile,

    /// Enable deep analysis (slower, more thorough)
    #[arg(long, default_value_t = false)]
    pub deep: bool,

    /// Build search index (SQLite FTS5)
    #[arg(long, default_value_t = false)]
    pub index: bool,

    /// Maximum streams to reassemble (0 = unlimited)
    #[arg(long, default_value_t = 0)]
    pub max_streams: usize,
}

fn parse_profile(s: &str) -> Result<AnalysisProfile, String> {
    match s.to_lowercase().as_str() {
        "ctf" => Ok(AnalysisProfile::Ctf),
        "ir" | "incident-response" => Ok(AnalysisProfile::IncidentResponse),
        "forensics" => Ok(AnalysisProfile::Forensics),
        "threat-hunt" | "threathunt" => Ok(AnalysisProfile::ThreatHunt),
        "quick" => Ok(AnalysisProfile::Quick),
        _ => Err(format!(
            "unknown profile '{}': expected ctf, ir, forensics, threat-hunt, or quick",
            s
        )),
    }
}

pub fn run(args: AnalyzeArgs) -> Result<()> {
    let started = Instant::now();

    // 1. Ingest PCAP
    println!(
        "  {} {}",
        console::style("[1/4] ingesting").cyan().bold(),
        args.pcap.display(),
    );

    let ingestor = PcapIngestor::from_file(&args.pcap)
        .with_context(|| format!("failed to ingest {}", args.pcap.display()))?;

    println!(
        "        {} packets parsed, {} errors, sha256:{}",
        console::style(ingestor.total_packets).green().bold(),
        ingestor.parse_errors,
        &ingestor.file_sha256[..16],
    );

    if ingestor.packets.is_empty() {
        println!(
            "  {} no parseable packets found in this file",
            console::style("warning:").yellow().bold(),
        );
        return Ok(());
    }

    // 2. Sessionize + Reassemble
    println!(
        "  {}",
        console::style("[2/4] sessionizing + reassembling").cyan().bold(),
    );

    let mut session_mgr = SessionManager::new();
    session_mgr.process_packets(&ingestor.packets);
    let (flows, streams) = session_mgr.finalize();

    let tcp_flows = flows.iter().filter(|f| f.key.protocol == TransportProtocol::Tcp).count();
    let udp_flows = flows.iter().filter(|f| f.key.protocol == TransportProtocol::Udp).count();
    let icmp_flows = flows.iter().filter(|f| f.key.protocol == TransportProtocol::Icmp).count();

    println!(
        "        {} flows ({} TCP, {} UDP, {} ICMP), {} streams",
        console::style(flows.len()).green().bold(),
        tcp_flows,
        udp_flows,
        icmp_flows,
        console::style(streams.len()).green().bold(),
    );

    let stream_bytes: u64 = streams.iter().map(|s| s.total_bytes).sum();
    println!(
        "        {} bytes reassembled across streams",
        console::style(stream_bytes).green().bold(),
    );

    // 3. Protocol dissection
    println!(
        "  {}",
        console::style("[3/5] dissecting protocols").cyan().bold(),
    );

    let dissection = wirehunt_core::protocols::dissect_all(&flows, &streams);

    if !dissection.dns_records.is_empty() {
        let queries = dissection.dns_records.iter().filter(|r| !r.is_response).count();
        let responses = dissection.dns_records.iter().filter(|r| r.is_response).count();
        println!(
            "        DNS: {} records ({} queries, {} responses)",
            console::style(dissection.dns_records.len()).green(),
            queries,
            responses,
        );
        for rec in dissection.dns_records.iter().take(5) {
            let data = if rec.response_data.is_empty() {
                String::new()
            } else {
                format!(" -> {}", rec.response_data.join(", "))
            };
            println!(
                "          {} {} {}{}",
                if rec.is_response { "R" } else { "Q" },
                console::style(&rec.record_type).cyan(),
                rec.query_name,
                data,
            );
        }
        if dissection.dns_records.len() > 5 {
            println!("          ... and {} more", dissection.dns_records.len() - 5);
        }
    }

    if !dissection.http_transactions.is_empty() {
        println!(
            "        HTTP: {} transactions",
            console::style(dissection.http_transactions.len()).green(),
        );
        for tx in &dissection.http_transactions {
            let host = tx.host.as_deref().unwrap_or("-");
            let status = tx.status_code.map(|c| c.to_string()).unwrap_or_default();
            println!(
                "          {} {} {} [{}]",
                console::style(&tx.method).cyan(),
                host,
                tx.uri,
                console::style(status).yellow(),
            );
        }
    }

    if !dissection.tls_sessions.is_empty() {
        println!(
            "        TLS: {} sessions",
            console::style(dissection.tls_sessions.len()).green(),
        );
        for tls in &dissection.tls_sessions {
            let sni = tls.sni.as_deref().unwrap_or("-");
            let ja3 = tls.ja3_hash.as_deref().map(|h| &h[..12]).unwrap_or("-");
            println!(
                "          {} SNI={} JA3={}...",
                console::style(&tls.version).cyan(),
                console::style(sni).green(),
                ja3,
            );
        }
    }

    if !dissection.ftp_sessions.is_empty() {
        println!(
            "        FTP: {} sessions",
            console::style(dissection.ftp_sessions.len()).green(),
        );
        for ftp in &dissection.ftp_sessions {
            if let Some(ref user) = ftp.username {
                println!(
                    "          USER={} PASS={} files={:?}",
                    console::style(user).red().bold(),
                    ftp.password.as_deref().unwrap_or("*"),
                    ftp.files_transferred,
                );
            }
        }
    }

    if !dissection.smtp_sessions.is_empty() {
        println!(
            "        SMTP: {} sessions",
            console::style(dissection.smtp_sessions.len()).green(),
        );
        for smtp in &dissection.smtp_sessions {
            if let Some(ref from) = smtp.mail_from {
                println!(
                    "          FROM={} TO={:?} SUBJ={}",
                    from,
                    smtp.rcpt_to,
                    smtp.subject.as_deref().unwrap_or("-"),
                );
            }
        }
    }

    if !dissection.icmp_summaries.is_empty() {
        let msg_count: usize = dissection.icmp_summaries.iter().map(|s| s.messages.len()).sum();
        let payload_bytes: usize = dissection.icmp_summaries.iter().map(|s| s.embedded_payload.len()).sum();
        println!(
            "        ICMP: {} messages, {} bytes embedded payload",
            console::style(msg_count).green(),
            payload_bytes,
        );
    }

    // 4. Extract + Decode + Credentials
    println!(
        "  {}",
        console::style("[4/7] extracting artifacts + credentials").cyan().bold(),
    );

    std::fs::create_dir_all(&args.out)
        .with_context(|| format!("cannot create output dir {}", args.out.display()))?;
    std::fs::create_dir_all(args.out.join("artifacts"))?;

    let extraction = wirehunt_core::extract::run_extraction(&streams, &dissection, &args.out);

    if !extraction.flag_candidates.is_empty() {
        println!(
            "        {} {}",
            console::style("FLAGS FOUND:").red().bold(),
            console::style(extraction.flag_candidates.len()).red().bold(),
        );
        for flag in &extraction.flag_candidates {
            let chain = flag.decode_chain.as_deref().unwrap_or("plaintext");
            println!(
                "          {} [{}]",
                console::style(&flag.value).red().bold(),
                chain,
            );
        }
    }

    if !extraction.artifacts.is_empty() {
        println!(
            "        artifacts: {}",
            console::style(extraction.artifacts.len()).green(),
        );
        for art in &extraction.artifacts {
            println!(
                "          {} {} ({} bytes, {})",
                console::style(art.kind.clone() as u8).cyan(), // use name
                art.name.as_deref().unwrap_or("-"),
                art.size_bytes,
                art.mime_type.as_deref().unwrap_or("?"),
            );
        }
    }

    if !extraction.decoded_strings.is_empty() {
        println!(
            "        decoded strings: {}",
            console::style(extraction.decoded_strings.len()).green(),
        );
        for dec in extraction.decoded_strings.iter().take(5) {
            println!(
                "          [{}] {} -> {}",
                console::style(&dec.chain).cyan(),
                &dec.original[..dec.original.len().min(30)],
                &dec.decoded[..dec.decoded.len().min(50)],
            );
        }
        if extraction.decoded_strings.len() > 5 {
            println!("          ... and {} more", extraction.decoded_strings.len() - 5);
        }
    }

    let credentials = wirehunt_core::credentials::harvest_credentials(&dissection, &streams);

    if !credentials.is_empty() {
        println!(
            "        {} {}",
            console::style("CREDENTIALS:").red().bold(),
            console::style(credentials.len()).red().bold(),
        );
        for cred in &credentials {
            let user = cred.username.as_deref().unwrap_or("-");
            let svc = cred.service.as_deref().unwrap_or("-");
            println!(
                "          {:?} user={} svc={} secret={}",
                cred.kind,
                console::style(user).yellow(),
                svc,
                console::style(&cred.secret[..cred.secret.len().min(40)]).red(),
            );
        }
    }

    // 5. Flow summary
    println!(
        "  {}",
        console::style("[5/7] flow summary").cyan().bold(),
    );

    let mut proto_counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for flow in &flows {
        let proto_name = match flow.detected_protocol {
            Some(p) => format!("{:?}", p),
            None => "Unknown".to_string(),
        };
        *proto_counts.entry(proto_name).or_insert(0) += 1;
    }

    let mut proto_list: Vec<_> = proto_counts.iter().collect();
    proto_list.sort_by(|a, b| b.1.cmp(a.1));
    for (proto, count) in &proto_list {
        println!(
            "        {}: {} flows",
            console::style(proto).cyan(),
            count,
        );
    }

    // 6. Entropy analysis
    println!(
        "  {}",
        console::style("[6/7] entropy analysis").cyan().bold(),
    );

    for stream in &streams {
        let all_data: Vec<u8> = stream.segments.iter().flat_map(|s| s.data.iter().copied()).collect();
        if all_data.len() >= 64 {
            let entropy = wirehunt_core::entropy::shannon_entropy(&all_data);
            let class = wirehunt_core::entropy::classify_entropy(entropy);
            if entropy > 6.5 {
                println!(
                    "        stream {} ({:?}): entropy={:.2} [{}]",
                    &stream.id[..12],
                    stream.protocol,
                    entropy,
                    console::style(class.to_string()).yellow(),
                );
            }
        }
    }

    // Save flag candidates before moving extraction data
    let saved_flags: Vec<(String, String, Option<String>)> = extraction
        .flag_candidates
        .iter()
        .map(|f| (f.value.clone(), f.stream_id.clone(), f.decode_chain.clone()))
        .collect();

    // 7. Build report + run detection
    println!(
        "  {}",
        console::style("[7/8] running detection rules").cyan().bold(),
    );

    let statistics = AnalysisStatistics {
        protocol_breakdown: proto_counts,
        top_talkers: compute_top_talkers(&flows),
        top_ports: compute_top_ports(&flows),
        total_findings: 0,
        total_artifacts: extraction.artifacts.len() as u64,
        total_credentials: credentials.len() as u64,
        analysis_duration_ms: 0,
    };

    let mut report = Report {
        metadata: ReportMetadata {
            wirehunt_version: wirehunt_core::VERSION.to_string(),
            generated_at: chrono::Utc::now(),
            pcap_filename: ingestor.filename,
            pcap_sha256: ingestor.file_sha256,
            pcap_size_bytes: ingestor.file_size,
            total_packets: ingestor.total_packets,
            capture_start: ingestor.first_timestamp,
            capture_end: ingestor.last_timestamp,
            capture_duration_secs: ingestor
                .first_timestamp
                .zip(ingestor.last_timestamp)
                .map(|(s, e)| e.signed_duration_since(s).num_milliseconds() as f64 / 1000.0)
                .unwrap_or(0.0),
            profile: args.profile,
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
        statistics,
    };

    let findings = wirehunt_core::detect::run_detection(&report, &saved_flags);

    if !findings.is_empty() {
        println!(
            "        {} {} findings",
            console::style("TOP LEADS:").red().bold(),
            console::style(findings.len()).red().bold(),
        );
        for (i, f) in findings.iter().take(10).enumerate() {
            let sev_style = match f.severity {
                Severity::Critical => console::style(format!("{:?}", f.severity)).red().bold(),
                Severity::High => console::style(format!("{:?}", f.severity)).red(),
                Severity::Medium => console::style(format!("{:?}", f.severity)).yellow(),
                Severity::Low => console::style(format!("{:?}", f.severity)).cyan(),
                Severity::Info => console::style(format!("{:?}", f.severity)).white(),
            };
            println!(
                "          [{}] {} {} (conf: {:.0}%)",
                i + 1,
                sev_style,
                f.title,
                f.confidence * 100.0,
            );
        }
        if findings.len() > 10 {
            println!("          ... and {} more", findings.len() - 10);
        }
    } else {
        println!("        no findings generated");
    }

    report.statistics.total_findings = findings.len() as u64;
    report.findings = findings;

    // 7b. IOC extraction, timeline, host profiling
    report.iocs = wirehunt_core::iocextract::extract_iocs(&report);
    report.timeline = wirehunt_core::timeline::TimelineBuilder::new().build(&report);
    report.host_profiles = wirehunt_core::hostprofile::HostProfiler::new().build(&report);

    if !report.iocs.is_empty() {
        println!(
            "        IOCs: {}",
            console::style(report.iocs.len()).green(),
        );
    }
    if !report.host_profiles.is_empty() {
        println!(
            "        host profiles: {}",
            console::style(report.host_profiles.len()).green(),
        );
    }
    println!(
        "        timeline: {} events",
        console::style(report.timeline.len()).green(),
    );

    // 8. Write report
    let step_label = if args.index { "[8/9]" } else { "[8/8]" };
    println!(
        "  {}",
        console::style(format!("{} writing report", step_label)).cyan().bold(),
    );

    let elapsed = started.elapsed();
    report.statistics.analysis_duration_ms = elapsed.as_millis() as u64;

    let report_path = args.out.join("report.json");
    let report_json = serde_json::to_string_pretty(&report)
        .context("failed to serialize report")?;
    std::fs::write(&report_path, &report_json)
        .with_context(|| format!("failed to write {}", report_path.display()))?;

    let report_size = report_json.len();

    // 9. Build search index (optional)
    if args.index {
        println!(
            "  {}",
            console::style("[9/9] building search index").cyan().bold(),
        );

        let index_path = args.out.join("index.db");
        let search_index = wirehunt_core::index::SearchIndex::create(&index_path)
            .context("failed to create search index")?;
        search_index
            .build_from_report(&report)
            .context("failed to build search index")?;

        println!(
            "        index -> {}",
            console::style(index_path.display()).green(),
        );
    }

    println!();
    println!(
        "  {} {}",
        console::style("report ->").green().bold(),
        report_path.display(),
    );
    println!(
        "  {} report: {} bytes, {} flows, {} streams",
        console::style("summary:").white().bold(),
        report_size,
        report.flows.len(),
        report.streams.len(),
    );
    println!(
        "  {} {:.1}ms",
        console::style("completed in").white().bold(),
        elapsed.as_secs_f64() * 1000.0,
    );

    Ok(())
}

fn compute_top_talkers(flows: &[Flow]) -> Vec<(std::net::IpAddr, u64)> {
    let mut talkers: std::collections::HashMap<std::net::IpAddr, u64> =
        std::collections::HashMap::new();
    for flow in flows {
        *talkers.entry(flow.key.src_ip).or_insert(0) += flow.fwd_bytes;
        *talkers.entry(flow.key.dst_ip).or_insert(0) += flow.rev_bytes;
    }
    let mut sorted: Vec<_> = talkers.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted.truncate(20);
    sorted
}

fn compute_top_ports(flows: &[Flow]) -> Vec<(u16, u64)> {
    let mut ports: std::collections::HashMap<u16, u64> = std::collections::HashMap::new();
    for flow in flows {
        let port = std::cmp::min(flow.key.src_port, flow.key.dst_port);
        if port > 0 {
            *ports.entry(port).or_insert(0) += 1;
        }
    }
    let mut sorted: Vec<_> = ports.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1));
    sorted.truncate(20);
    sorted
}
