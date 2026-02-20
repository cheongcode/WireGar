use std::sync::Arc;

use anyhow::Result;
use axum::extract::{DefaultBodyLimit, Multipart, State};
use axum::http::StatusCode;
use axum::response::{Html, Json};
use axum::routing::{get, post};
use axum::Router;
use clap::Args;
use tokio::sync::Mutex;

use wirehunt_core::ingest::PcapIngestor;
use wirehunt_core::models::*;
use wirehunt_core::session::SessionManager;

#[derive(Args)]
pub struct ServeArgs {
    /// Port to listen on
    #[arg(short, long, default_value_t = 8888)]
    pub port: u16,

    /// Don't auto-open browser
    #[arg(long, default_value_t = false)]
    pub no_open: bool,
}

struct AppState {
    last_report: Mutex<Option<Report>>,
}

pub fn run(args: ServeArgs) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let state = Arc::new(AppState {
            last_report: Mutex::new(None),
        });

        let app = Router::new()
            .route("/", get(index_handler))
            .route("/api/analyze", post(analyze_handler))
            .route("/api/report", get(report_handler))
            .route("/api/enrich", post(enrich_handler))
            .layer(DefaultBodyLimit::max(500 * 1024 * 1024))
            .with_state(state);

        let addr = format!("127.0.0.1:{}", args.port);
        let url = format!("http://{}", addr);

        println!(
            "\n  {} {}",
            console::style("WireHunt GUI running at").green().bold(),
            console::style(&url).cyan().bold().underlined(),
        );
        println!(
            "  {} Drag and drop your pcap file into the browser\n",
            console::style("-->").cyan(),
        );

        if !args.no_open {
            let _ = open::that(&url);
        }

        let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
        axum::serve(listener, app).await.unwrap();

        Ok(())
    })
}

async fn index_handler() -> Html<&'static str> {
    Html(include_str!("../../static/index.html"))
}

async fn analyze_handler(
    State(state): State<Arc<AppState>>,
    mut multipart: Multipart,
) -> Result<Json<Report>, (StatusCode, String)> {
    let field = multipart
        .next_field()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("multipart error: {}", e)))?
        .ok_or((StatusCode::BAD_REQUEST, "no file uploaded".to_string()))?;

    let filename = field.file_name().unwrap_or("upload.pcap").to_string();
    let data = field
        .bytes()
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("read error: {}", e)))?
        .to_vec();

    // Write to temp file for the ingestor
    let tmp_dir = tempfile::tempdir()
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let tmp_path = tmp_dir.path().join(&filename);
    std::fs::write(&tmp_path, &data)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Run the full analysis pipeline
    let report = run_analysis(&tmp_path, &filename)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    *state.last_report.lock().await = Some(report.clone());

    Ok(Json(report))
}

async fn report_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Report>, (StatusCode, String)> {
    let report = state.last_report.lock().await;
    match report.as_ref() {
        Some(r) => Ok(Json(r.clone())),
        None => Err((StatusCode::NOT_FOUND, "no report available yet".to_string())),
    }
}

fn run_analysis(path: &std::path::Path, filename: &str) -> Result<Report, String> {
    let ingestor = PcapIngestor::from_file(path).map_err(|e| e.to_string())?;

    let mut session_mgr = SessionManager::new();
    session_mgr.process_packets(&ingestor.packets);
    let (flows, streams) = session_mgr.finalize();

    let dissection = wirehunt_core::protocols::dissect_all(&flows, &streams);

    let out_dir = path.parent().unwrap_or(std::path::Path::new("."));
    let extraction =
        wirehunt_core::extract::run_extraction(&streams, &dissection, out_dir);

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

    let mut report = Report {
        metadata: ReportMetadata {
            wirehunt_version: wirehunt_core::VERSION.to_string(),
            generated_at: chrono::Utc::now(),
            pcap_filename: filename.to_string(),
            pcap_sha256: ingestor.file_sha256.clone(),
            pcap_size_bytes: ingestor.file_size,
            total_packets: ingestor.total_packets,
            capture_start: ingestor.first_timestamp,
            capture_end: ingestor.last_timestamp,
            capture_duration_secs: ingestor
                .first_timestamp
                .zip(ingestor.last_timestamp)
                .map(|(s, e)| e.signed_duration_since(s).num_milliseconds() as f64 / 1000.0)
                .unwrap_or(0.0),
            profile: AnalysisProfile::Ctf,
        },
        executive_summary: None,
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
            analysis_duration_ms: 0,
        },
    };

    let findings = wirehunt_core::detect::run_detection(&report, &saved_flags);
    report.statistics.total_findings = findings.len() as u64;
    report.findings = findings;

    report.iocs = wirehunt_core::iocextract::extract_iocs(&report);
    report.timeline = wirehunt_core::timeline::TimelineBuilder::new().build(&report);
    report.host_profiles = wirehunt_core::hostprofile::HostProfiler::new().build(&report);
    report.executive_summary = Some(wirehunt_core::narrative::generate_executive_summary(&report));

    let mut talkers: std::collections::HashMap<std::net::IpAddr, u64> = std::collections::HashMap::new();
    for flow in &report.flows {
        *talkers.entry(flow.key.src_ip).or_insert(0) += flow.fwd_bytes;
        *talkers.entry(flow.key.dst_ip).or_insert(0) += flow.rev_bytes;
    }
    let mut sorted_talkers: Vec<_> = talkers.into_iter().collect();
    sorted_talkers.sort_by(|a, b| b.1.cmp(&a.1));
    sorted_talkers.truncate(20);
    report.statistics.top_talkers = sorted_talkers;

    let mut ports: std::collections::HashMap<u16, u64> = std::collections::HashMap::new();
    for flow in &report.flows {
        let port = std::cmp::min(flow.key.src_port, flow.key.dst_port);
        if port > 0 { *ports.entry(port).or_insert(0) += 1; }
    }
    let mut sorted_ports: Vec<_> = ports.into_iter().collect();
    sorted_ports.sort_by(|a, b| b.1.cmp(&a.1));
    sorted_ports.truncate(20);
    report.statistics.top_ports = sorted_ports;

    Ok(report)
}

async fn enrich_handler(
    State(state): State<Arc<AppState>>,
) -> Result<Json<Vec<IocEnrichment>>, (StatusCode, String)> {
    let report = state.last_report.lock().await;
    let report = report
        .as_ref()
        .ok_or((StatusCode::NOT_FOUND, "no report available".to_string()))?;

    let client = wirehunt_core::threatintel::ThreatIntelClient::new();
    let ip_iocs: Vec<Ioc> = report.iocs.iter()
        .filter(|i| matches!(i.kind, IocKind::IpAddress | IocKind::Domain | IocKind::FileHash))
        .take(20)
        .cloned()
        .collect();

    let enrichments = client.enrich_iocs(&ip_iocs).await;
    Ok(Json(enrichments))
}
