use anyhow::{Context, Result};
use clap::Args;
use std::path::PathBuf;

use wirehunt_core::models::Report;

#[derive(Args)]
pub struct ExportArgs {
    /// Path to the case directory
    pub case_dir: PathBuf,

    /// Export as interactive HTML report
    #[arg(long, default_value_t = false)]
    pub html: bool,

    /// Export as JSON report
    #[arg(long, default_value_t = false)]
    pub json: bool,

    /// Export as STIX 2.1 bundle
    #[arg(long, default_value_t = false)]
    pub stix: bool,

    /// Output file path (for reports)
    #[arg(short, long)]
    pub output: Option<PathBuf>,
}

pub fn run(args: ExportArgs) -> Result<()> {
    if !args.html && !args.json && !args.stix {
        println!(
            "  {} specify at least one export format: --html, --json, or --stix",
            console::style("error:").red().bold(),
        );
        return Ok(());
    }

    let report_path = args.case_dir.join("report.json");
    let report_data = std::fs::read_to_string(&report_path)
        .with_context(|| format!("cannot read {}", report_path.display()))?;
    let report: Report =
        serde_json::from_str(&report_data).context("failed to parse report.json")?;

    if args.json {
        let out = args
            .output
            .clone()
            .unwrap_or_else(|| args.case_dir.join("report_export.json"));
        std::fs::write(&out, &report_data)
            .with_context(|| format!("failed to write {}", out.display()))?;
        println!(
            "  {} {}",
            console::style("json ->").green().bold(),
            out.display(),
        );
    }

    if args.html {
        let out = args
            .output
            .clone()
            .unwrap_or_else(|| args.case_dir.join("report.html"));
        let html = generate_html_report(&report, &report_data);
        std::fs::write(&out, &html)
            .with_context(|| format!("failed to write {}", out.display()))?;
        println!(
            "  {} {} ({} bytes)",
            console::style("html ->").green().bold(),
            out.display(),
            html.len(),
        );
    }

    if args.stix {
        let out = args
            .output
            .clone()
            .unwrap_or_else(|| args.case_dir.join("stix_bundle.json"));
        let stix = generate_stix_bundle(&report);
        let stix_json = serde_json::to_string_pretty(&stix)?;
        std::fs::write(&out, &stix_json)
            .with_context(|| format!("failed to write {}", out.display()))?;
        println!(
            "  {} {}",
            console::style("stix ->").green().bold(),
            out.display(),
        );
    }

    Ok(())
}

fn generate_html_report(report: &Report, raw_json: &str) -> String {
    let meta = &report.metadata;

    let flags_count = report
        .findings
        .iter()
        .filter(|f| f.category == wirehunt_core::models::FindingCategory::CtfFlag)
        .count();

    let severity_counts = {
        let mut critical = 0u64;
        let mut high = 0u64;
        let mut medium = 0u64;
        let mut low = 0u64;
        let mut info = 0u64;
        for f in &report.findings {
            match f.severity {
                wirehunt_core::models::Severity::Critical => critical += 1,
                wirehunt_core::models::Severity::High => high += 1,
                wirehunt_core::models::Severity::Medium => medium += 1,
                wirehunt_core::models::Severity::Low => low += 1,
                wirehunt_core::models::Severity::Info => info += 1,
            }
        }
        (critical, high, medium, low, info)
    };

    let proto_breakdown_html = {
        let mut rows = String::new();
        let mut protos: Vec<_> = report.statistics.protocol_breakdown.iter().collect();
        protos.sort_by(|a, b| b.1.cmp(a.1));
        let total: u64 = protos.iter().map(|(_, v)| **v).sum();
        for (name, count) in &protos {
            let pct = if total > 0 {
                **count as f64 / total as f64 * 100.0
            } else {
                0.0
            };
            rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td><div class=\"bar\"><div class=\"bar-fill\" style=\"width:{:.1}%\"></div></div></td><td>{:.1}%</td></tr>\n",
                html_escape(name), count, pct, pct
            ));
        }
        rows
    };

    let findings_html = {
        let mut rows = String::new();
        for f in &report.findings {
            let sev_class = match f.severity {
                wirehunt_core::models::Severity::Critical => "sev-critical",
                wirehunt_core::models::Severity::High => "sev-high",
                wirehunt_core::models::Severity::Medium => "sev-medium",
                wirehunt_core::models::Severity::Low => "sev-low",
                wirehunt_core::models::Severity::Info => "sev-info",
            };
            let mitre = f.mitre_attack.join(", ");
            rows.push_str(&format!(
                "<tr><td><span class=\"badge {}\">{:?}</span></td><td>{}</td><td>{}</td><td>{:.0}%</td><td class=\"mitre\">{}</td></tr>\n",
                sev_class,
                f.severity,
                html_escape(&f.title),
                html_escape(&f.description),
                f.confidence * 100.0,
                html_escape(&mitre),
            ));
        }
        rows
    };

    let flows_html = {
        let mut rows = String::new();
        for f in report.flows.iter().take(500) {
            let proto = f
                .detected_protocol
                .map(|p| format!("{:?}", p))
                .unwrap_or_else(|| "?".to_string());
            rows.push_str(&format!(
                "<tr><td>{}:{}</td><td>{}:{}</td><td>{:?}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                f.key.src_ip, f.key.src_port,
                f.key.dst_ip, f.key.dst_port,
                f.key.protocol,
                html_escape(&proto),
                f.packet_count,
                f.byte_count,
            ));
        }
        rows
    };

    let dns_html = {
        let mut rows = String::new();
        for r in &report.dns_records {
            rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                if r.is_response { "R" } else { "Q" },
                html_escape(&r.query_name),
                html_escape(&r.record_type),
                html_escape(&r.response_data.join(", ")),
                r.ttl.map(|t| t.to_string()).unwrap_or_default(),
            ));
        }
        rows
    };

    let http_html = {
        let mut rows = String::new();
        for tx in &report.http_transactions {
            rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                html_escape(&tx.method),
                html_escape(tx.host.as_deref().unwrap_or("-")),
                html_escape(&tx.uri),
                tx.status_code.map(|c| c.to_string()).unwrap_or_default(),
                tx.content_type.as_deref().unwrap_or("-"),
                tx.response_body_size,
            ));
        }
        rows
    };

    let tls_html = {
        let mut rows = String::new();
        for t in &report.tls_sessions {
            rows.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                html_escape(&t.version),
                html_escape(t.sni.as_deref().unwrap_or("-")),
                html_escape(t.cipher_suite.as_deref().unwrap_or("-")),
                t.ja3_hash.as_deref().unwrap_or("-"),
                t.ja3s_hash.as_deref().unwrap_or("-"),
            ));
        }
        rows
    };

    let creds_html = {
        let mut rows = String::new();
        for c in &report.credentials {
            rows.push_str(&format!(
                "<tr><td>{:?}</td><td>{}</td><td class=\"secret\">{}</td><td>{}</td><td>{}</td></tr>\n",
                c.kind,
                html_escape(c.username.as_deref().unwrap_or("-")),
                html_escape(&c.secret),
                html_escape(c.service.as_deref().unwrap_or("-")),
                html_escape(c.host.as_deref().unwrap_or("-")),
            ));
        }
        rows
    };

    let artifacts_html = {
        let mut rows = String::new();
        for a in &report.artifacts {
            rows.push_str(&format!(
                "<tr><td>{:?}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                a.kind,
                html_escape(a.name.as_deref().unwrap_or("-")),
                a.mime_type.as_deref().unwrap_or("-"),
                a.size_bytes,
                &a.sha256[..16],
            ));
        }
        rows
    };

    let json_escaped = raw_json
        .replace('\\', "\\\\")
        .replace('\'', "\\'")
        .replace('\n', "\\n")
        .replace('\r', "");

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>WireHunt Report - {filename}</title>
<style>
:root {{
  --base: #1e1e2e; --mantle: #181825; --crust: #11111b; --surface0: #313244;
  --surface1: #45475a; --surface2: #585b70; --text: #cdd6f4; --subtext: #a6adc8;
  --red: #f38ba8; --green: #a6e3a1; --yellow: #f9e2af; --blue: #89b4fa;
  --mauve: #cba6f7; --teal: #94e2d5; --peach: #fab387; --pink: #f5c2e7;
  --cyan: #89dceb;
}}
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ background: var(--base); color: var(--text); font-family: 'Segoe UI', system-ui, -apple-system, sans-serif; font-size: 14px; line-height: 1.5; }}
.container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
header {{ text-align: center; padding: 30px 0 20px; border-bottom: 1px solid var(--surface0); margin-bottom: 20px; }}
header h1 {{ font-size: 28px; color: var(--cyan); letter-spacing: 2px; }}
header .meta {{ color: var(--subtext); margin-top: 8px; font-size: 13px; }}
.flag-banner {{ background: linear-gradient(90deg, #f38ba855, #f38ba822); border: 1px solid var(--red); border-radius: 8px; padding: 16px; text-align: center; margin-bottom: 20px; font-size: 18px; color: var(--red); font-weight: bold; }}
.stats {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin-bottom: 20px; }}
.stat {{ background: var(--mantle); border-radius: 8px; padding: 14px; text-align: center; border: 1px solid var(--surface0); }}
.stat .num {{ font-size: 24px; font-weight: bold; color: var(--cyan); }}
.stat .label {{ font-size: 11px; color: var(--subtext); text-transform: uppercase; letter-spacing: 1px; }}
.tabs {{ display: flex; gap: 4px; border-bottom: 2px solid var(--surface0); margin-bottom: 16px; flex-wrap: wrap; }}
.tab {{ padding: 8px 16px; cursor: pointer; border-radius: 6px 6px 0 0; background: var(--mantle); color: var(--subtext); border: 1px solid transparent; font-size: 13px; }}
.tab:hover {{ color: var(--text); }}
.tab.active {{ background: var(--surface0); color: var(--cyan); border-color: var(--surface1); border-bottom-color: var(--surface0); }}
.panel {{ display: none; }}
.panel.active {{ display: block; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th {{ background: var(--mantle); color: var(--subtext); text-align: left; padding: 8px 10px; font-weight: 600; position: sticky; top: 0; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }}
td {{ padding: 6px 10px; border-bottom: 1px solid var(--surface0); word-break: break-all; }}
tr:hover td {{ background: var(--surface0); }}
.badge {{ padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 700; text-transform: uppercase; }}
.sev-critical {{ background: var(--red); color: var(--crust); }}
.sev-high {{ background: var(--peach); color: var(--crust); }}
.sev-medium {{ background: var(--yellow); color: var(--crust); }}
.sev-low {{ background: var(--blue); color: var(--crust); }}
.sev-info {{ background: var(--surface1); color: var(--text); }}
.mitre {{ color: var(--mauve); font-size: 12px; }}
.secret {{ color: var(--red); font-family: monospace; }}
.bar {{ background: var(--surface0); border-radius: 4px; height: 14px; width: 120px; display: inline-block; }}
.bar-fill {{ background: var(--cyan); height: 100%; border-radius: 4px; }}
.section-title {{ font-size: 16px; color: var(--cyan); margin: 20px 0 10px; }}
.search {{ margin-bottom: 12px; }}
.search input {{ background: var(--mantle); border: 1px solid var(--surface1); color: var(--text); padding: 8px 14px; border-radius: 6px; width: 100%; max-width: 400px; font-size: 13px; }}
.search input::placeholder {{ color: var(--surface2); }}
footer {{ text-align: center; padding: 30px 0; color: var(--surface2); font-size: 12px; }}
.severity-summary {{ display: flex; gap: 12px; justify-content: center; margin: 12px 0; flex-wrap: wrap; }}
.severity-summary span {{ font-size: 13px; }}
.json-btn {{ background: var(--surface0); border: 1px solid var(--surface1); color: var(--text); padding: 6px 14px; border-radius: 6px; cursor: pointer; font-size: 12px; }}
.json-btn:hover {{ background: var(--surface1); }}
@media print {{
  body {{ background: #fff; color: #000; }}
  .tabs, .search, .json-btn {{ display: none; }}
  .panel {{ display: block !important; page-break-inside: avoid; }}
  .badge {{ border: 1px solid #000; }}
}}
</style>
</head>
<body>
<div class="container">
<header>
  <h1>WIREHUNT REPORT</h1>
  <div class="meta">
    {filename} &middot; SHA256: {sha256} &middot; {packets} packets &middot; {size} bytes &middot; {duration:.1}s capture
    <br>Generated {generated} by WireHunt v{version} (profile: {profile:?})
  </div>
</header>

{flag_banner}

<div class="severity-summary">
  <span><span class="badge sev-critical">Critical</span> {sev_crit}</span>
  <span><span class="badge sev-high">High</span> {sev_high}</span>
  <span><span class="badge sev-medium">Medium</span> {sev_med}</span>
  <span><span class="badge sev-low">Low</span> {sev_low}</span>
  <span><span class="badge sev-info">Info</span> {sev_info}</span>
</div>

<div class="stats">
  <div class="stat"><div class="num">{n_flows}</div><div class="label">Flows</div></div>
  <div class="stat"><div class="num">{n_streams}</div><div class="label">Streams</div></div>
  <div class="stat"><div class="num">{n_findings}</div><div class="label">Findings</div></div>
  <div class="stat"><div class="num">{n_creds}</div><div class="label">Credentials</div></div>
  <div class="stat"><div class="num">{n_artifacts}</div><div class="label">Artifacts</div></div>
  <div class="stat"><div class="num">{n_dns}</div><div class="label">DNS Records</div></div>
  <div class="stat"><div class="num">{n_http}</div><div class="label">HTTP Txns</div></div>
  <div class="stat"><div class="num">{n_tls}</div><div class="label">TLS Sessions</div></div>
</div>

<div class="search"><input type="text" id="searchBox" placeholder="Filter tables..." oninput="filterAll()"></div>

<div class="tabs" id="tabBar">
  <div class="tab active" onclick="switchTab('findings')">Findings</div>
  <div class="tab" onclick="switchTab('flows')">Flows</div>
  <div class="tab" onclick="switchTab('dns')">DNS</div>
  <div class="tab" onclick="switchTab('http')">HTTP</div>
  <div class="tab" onclick="switchTab('tls')">TLS</div>
  <div class="tab" onclick="switchTab('creds')">Credentials</div>
  <div class="tab" onclick="switchTab('artifacts')">Artifacts</div>
  <div class="tab" onclick="switchTab('proto')">Protocols</div>
</div>

<div class="panel active" id="panel-findings">
<table id="table-findings"><thead><tr><th>Severity</th><th>Title</th><th>Description</th><th>Confidence</th><th>MITRE ATT&amp;CK</th></tr></thead><tbody>
{findings_html}</tbody></table></div>

<div class="panel" id="panel-flows">
<table id="table-flows"><thead><tr><th>Source</th><th>Destination</th><th>Transport</th><th>App Protocol</th><th>Packets</th><th>Bytes</th></tr></thead><tbody>
{flows_html}</tbody></table></div>

<div class="panel" id="panel-dns">
<table id="table-dns"><thead><tr><th>Type</th><th>Query Name</th><th>Record Type</th><th>Response Data</th><th>TTL</th></tr></thead><tbody>
{dns_html}</tbody></table></div>

<div class="panel" id="panel-http">
<table id="table-http"><thead><tr><th>Method</th><th>Host</th><th>URI</th><th>Status</th><th>Content-Type</th><th>Body Size</th></tr></thead><tbody>
{http_html}</tbody></table></div>

<div class="panel" id="panel-tls">
<table id="table-tls"><thead><tr><th>Version</th><th>SNI</th><th>Cipher Suite</th><th>JA3</th><th>JA3S</th></tr></thead><tbody>
{tls_html}</tbody></table></div>

<div class="panel" id="panel-creds">
<table id="table-creds"><thead><tr><th>Kind</th><th>Username</th><th>Secret</th><th>Service</th><th>Host</th></tr></thead><tbody>
{creds_html}</tbody></table></div>

<div class="panel" id="panel-artifacts">
<table id="table-artifacts"><thead><tr><th>Kind</th><th>Name</th><th>MIME</th><th>Size</th><th>SHA256</th></tr></thead><tbody>
{artifacts_html}</tbody></table></div>

<div class="panel" id="panel-proto">
<h3 class="section-title">Protocol Breakdown</h3>
<table><thead><tr><th>Protocol</th><th>Flows</th><th>Distribution</th><th>Percentage</th></tr></thead><tbody>
{proto_html}</tbody></table></div>

<div style="text-align:right;margin-top:12px;">
  <button class="json-btn" onclick="downloadJson()">Export JSON</button>
</div>

<footer>WireHunt v{version} &middot; Network Forensic Engine</footer>
</div>

<script>
var REPORT_JSON = '{json_data}';
function switchTab(name) {{
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('panel-' + name).classList.add('active');
  var tabs = document.querySelectorAll('.tab');
  for (var i = 0; i < tabs.length; i++) {{
    if (tabs[i].textContent.toLowerCase().replace(/\s/g,'') === name || tabs[i].onclick.toString().indexOf("'" + name + "'") > -1)
      tabs[i].classList.add('active');
  }}
}}
function filterAll() {{
  var q = document.getElementById('searchBox').value.toLowerCase();
  document.querySelectorAll('tbody').forEach(function(tbody) {{
    var rows = tbody.querySelectorAll('tr');
    rows.forEach(function(row) {{
      row.style.display = row.textContent.toLowerCase().indexOf(q) > -1 ? '' : 'none';
    }});
  }});
}}
function downloadJson() {{
  var blob = new Blob([JSON.parse(JSON.stringify(REPORT_JSON)).replace(/\\n/g, '\n').replace(/\\'/g, "'")], {{type:'application/json'}});
  var a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'report.json';
  a.click();
}}
</script>
</body>
</html>"##,
        filename = html_escape(&meta.pcap_filename),
        sha256 = &meta.pcap_sha256[..meta.pcap_sha256.len().min(16)],
        packets = meta.total_packets,
        size = meta.pcap_size_bytes,
        duration = meta.capture_duration_secs,
        generated = meta.generated_at.format("%Y-%m-%d %H:%M:%S UTC"),
        version = html_escape(&meta.wirehunt_version),
        profile = meta.profile,
        flag_banner = if flags_count > 0 {
            format!("<div class=\"flag-banner\">FLAGS DETECTED: {}</div>", flags_count)
        } else {
            String::new()
        },
        sev_crit = severity_counts.0,
        sev_high = severity_counts.1,
        sev_med = severity_counts.2,
        sev_low = severity_counts.3,
        sev_info = severity_counts.4,
        n_flows = report.flows.len(),
        n_streams = report.streams.len(),
        n_findings = report.findings.len(),
        n_creds = report.credentials.len(),
        n_artifacts = report.artifacts.len(),
        n_dns = report.dns_records.len(),
        n_http = report.http_transactions.len(),
        n_tls = report.tls_sessions.len(),
        findings_html = findings_html,
        flows_html = flows_html,
        dns_html = dns_html,
        http_html = http_html,
        tls_html = tls_html,
        creds_html = creds_html,
        artifacts_html = artifacts_html,
        proto_html = proto_breakdown_html,
        json_data = json_escaped,
    )
}

fn generate_stix_bundle(report: &Report) -> serde_json::Value {
    let mut objects = Vec::new();

    objects.push(serde_json::json!({
        "type": "identity",
        "spec_version": "2.1",
        "id": format!("identity--wirehunt-{}", uuid::Uuid::new_v4()),
        "created": report.metadata.generated_at.to_rfc3339(),
        "modified": report.metadata.generated_at.to_rfc3339(),
        "name": "WireHunt",
        "identity_class": "tool",
    }));

    for finding in &report.findings {
        let sev_label = format!("{:?}", finding.severity).to_lowercase();
        let mut labels = vec![sev_label, format!("{:?}", finding.category)];
        labels.extend(finding.tags.clone());

        let mut external_refs: Vec<serde_json::Value> = Vec::new();
        for mitre in &finding.mitre_attack {
            external_refs.push(serde_json::json!({
                "source_name": "mitre-attack",
                "external_id": mitre,
            }));
        }

        objects.push(serde_json::json!({
            "type": "indicator",
            "spec_version": "2.1",
            "id": format!("indicator--{}", uuid::Uuid::new_v4()),
            "created": finding.timestamp.to_rfc3339(),
            "modified": finding.timestamp.to_rfc3339(),
            "name": finding.title,
            "description": finding.description,
            "indicator_types": ["anomalous-activity"],
            "pattern_type": "wirehunt",
            "pattern": format!("[finding:title = '{}']", finding.title),
            "valid_from": finding.timestamp.to_rfc3339(),
            "confidence": (finding.confidence * 100.0) as u32,
            "labels": labels,
            "external_references": external_refs,
        }));
    }

    for cred in &report.credentials {
        objects.push(serde_json::json!({
            "type": "observed-data",
            "spec_version": "2.1",
            "id": format!("observed-data--{}", uuid::Uuid::new_v4()),
            "created": report.metadata.generated_at.to_rfc3339(),
            "modified": report.metadata.generated_at.to_rfc3339(),
            "first_observed": report.metadata.generated_at.to_rfc3339(),
            "last_observed": report.metadata.generated_at.to_rfc3339(),
            "number_observed": 1,
            "object_refs": [],
            "x_wirehunt_credential_kind": format!("{:?}", cred.kind),
            "x_wirehunt_username": cred.username,
            "x_wirehunt_service": cred.service,
        }));
    }

    serde_json::json!({
        "type": "bundle",
        "id": format!("bundle--{}", uuid::Uuid::new_v4()),
        "objects": objects,
    })
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}
