use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::app::App;

const ACCENT: Color = Color::Cyan;
const RED: Color = Color::Rgb(243, 139, 168);
const GREEN: Color = Color::Rgb(166, 227, 161);
const YELLOW: Color = Color::Rgb(249, 226, 175);
const SURFACE: Color = Color::Rgb(49, 50, 68);

pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),  // file info
            Constraint::Length(12), // stats
            Constraint::Min(4),    // protocol breakdown
        ])
        .split(area);

    render_file_info(frame, app, layout[0]);
    render_stats(frame, app, layout[1]);
    render_protocol_breakdown(frame, app, layout[2]);
}

fn render_file_info(frame: &mut Frame, app: &App, area: Rect) {
    let m = &app.report.metadata;
    let duration = format!("{:.1}s", m.capture_duration_secs);

    let lines = vec![
        Line::from(vec![
            Span::styled("  File:     ", Style::default().fg(Color::DarkGray)),
            Span::styled(&m.pcap_filename, Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        ]),
        Line::from(vec![
            Span::styled("  SHA256:   ", Style::default().fg(Color::DarkGray)),
            Span::styled(&m.pcap_sha256[..32], Style::default().fg(ACCENT)),
            Span::styled("...", Style::default().fg(Color::DarkGray)),
        ]),
        Line::from(vec![
            Span::styled("  Size:     ", Style::default().fg(Color::DarkGray)),
            Span::styled(format_bytes(m.pcap_size_bytes), Style::default().fg(Color::White)),
            Span::styled("  Packets: ", Style::default().fg(Color::DarkGray)),
            Span::styled(m.total_packets.to_string(), Style::default().fg(Color::White)),
            Span::styled("  Duration: ", Style::default().fg(Color::DarkGray)),
            Span::styled(duration, Style::default().fg(Color::White)),
        ]),
        Line::from(vec![
            Span::styled("  Profile:  ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{:?}", m.profile), Style::default().fg(YELLOW).add_modifier(Modifier::BOLD)),
            Span::styled("  Engine: ", Style::default().fg(Color::DarkGray)),
            Span::styled(format!("WireHunt v{}", m.wirehunt_version), Style::default().fg(ACCENT)),
        ]),
    ];

    let block = Block::default()
        .title(Span::styled(" Capture Info ", Style::default().fg(ACCENT).bold()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(SURFACE));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_stats(frame: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);

    render_stat_box(frame, "Flows", &app.report.flows.len().to_string(), ACCENT, cols[0]);
    render_stat_box(frame, "Streams", &app.report.streams.len().to_string(), GREEN, cols[1]);
    render_stat_box(frame, "Artifacts", &app.report.artifacts.len().to_string(), YELLOW, cols[2]);

    let cred_count = app.report.credentials.len();
    let cred_color = if cred_count > 0 { RED } else { Color::DarkGray };
    render_stat_box(frame, "Credentials", &cred_count.to_string(), cred_color, cols[3]);
}

fn render_stat_box(frame: &mut Frame, label: &str, value: &str, color: Color, area: Rect) {
    let lines = vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  {}", value),
            Style::default().fg(color).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::styled(
            format!("  {}", label),
            Style::default().fg(Color::DarkGray),
        )),
    ];

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(SURFACE));

    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_protocol_breakdown(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = Vec::new();

    let mut sorted: Vec<_> = app.report.statistics.protocol_breakdown.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));

    let total: u64 = sorted.iter().map(|(_, v)| **v).sum();

    for (proto, count) in &sorted {
        let pct = if total > 0 { (**count as f64 / total as f64 * 100.0) } else { 0.0 };
        let bar_width = (pct / 100.0 * 30.0) as usize;
        let bar: String = "█".repeat(bar_width) + &"░".repeat(30 - bar_width);

        lines.push(Line::from(vec![
            Span::styled(format!("  {:<12}", proto), Style::default().fg(ACCENT)),
            Span::styled(format!("{} ", bar), Style::default().fg(Color::Rgb(88, 91, 112))),
            Span::styled(format!("{} ({:.0}%)", count, pct), Style::default().fg(Color::White)),
        ]));
    }

    if lines.is_empty() {
        lines.push(Line::from(Span::styled("  No flows detected", Style::default().fg(Color::DarkGray))));
    }

    let block = Block::default()
        .title(Span::styled(" Protocol Breakdown ", Style::default().fg(ACCENT).bold()))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(SURFACE));

    frame.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: false }), area);
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.1} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.1} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}
