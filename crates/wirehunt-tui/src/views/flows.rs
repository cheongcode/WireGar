use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::app::App;
use wirehunt_core::models::TransportProtocol;

const ACCENT: Color = Color::Cyan;
const SURFACE: Color = Color::Rgb(49, 50, 68);
const HIGHLIGHT_BG: Color = Color::Rgb(49, 50, 68);

pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = Vec::new();

    // Header
    lines.push(Line::from(vec![
        Span::styled(
            format!("  {:<6} {:<8} {:<22} {:<22} {:<6} {:<10} {:<8}",
                "#", "PROTO", "SOURCE", "DESTINATION", "PKTS", "BYTES", "APP"),
            Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
        ),
    ]));
    lines.push(Line::from(Span::styled(
        "  ".to_string() + &"─".repeat(area.width.saturating_sub(4) as usize),
        Style::default().fg(Color::Rgb(69, 71, 90)),
    )));

    for (i, flow) in app.report.flows.iter().enumerate() {
        let proto = match flow.key.protocol {
            TransportProtocol::Tcp => "TCP",
            TransportProtocol::Udp => "UDP",
            TransportProtocol::Icmp => "ICMP",
            TransportProtocol::Other(_) => "???",
        };
        let proto_color = match flow.key.protocol {
            TransportProtocol::Tcp => Color::Rgb(137, 180, 250),
            TransportProtocol::Udp => Color::Rgb(166, 227, 161),
            TransportProtocol::Icmp => Color::Rgb(249, 226, 175),
            _ => Color::Gray,
        };
        let app_proto = flow.detected_protocol
            .map(|p| format!("{:?}", p))
            .unwrap_or_else(|| "-".to_string());

        let src = format!("{}:{}", flow.key.src_ip, flow.key.src_port);
        let dst = format!("{}:{}", flow.key.dst_ip, flow.key.dst_port);

        let is_selected = i == app.selected_index;
        let bg = if is_selected { HIGHLIGHT_BG } else { Color::Reset };
        let fg = if is_selected { Color::White } else { Color::Rgb(205, 214, 244) };
        let marker = if is_selected { "▸ " } else { "  " };

        lines.push(Line::from(vec![
            Span::styled(marker, Style::default().fg(ACCENT).bg(bg)),
            Span::styled(format!("{:<6}", i), Style::default().fg(Color::DarkGray).bg(bg)),
            Span::styled(format!("{:<8}", proto), Style::default().fg(proto_color).bg(bg).add_modifier(Modifier::BOLD)),
            Span::styled(format!("{:<22}", src), Style::default().fg(fg).bg(bg)),
            Span::styled(format!("{:<22}", dst), Style::default().fg(fg).bg(bg)),
            Span::styled(format!("{:<6}", flow.packet_count), Style::default().fg(Color::Rgb(180, 190, 254)).bg(bg)),
            Span::styled(format!("{:<10}", flow.byte_count), Style::default().fg(Color::Rgb(180, 190, 254)).bg(bg)),
            Span::styled(format!("{:<8}", app_proto), Style::default().fg(ACCENT).bg(bg)),
        ]));
    }

    if app.report.flows.is_empty() {
        lines.push(Line::from(Span::styled("  No flows", Style::default().fg(Color::DarkGray))));
    }

    let block = Block::default()
        .title(Span::styled(
            format!(" Flows ({}) ", app.report.flows.len()),
            Style::default().fg(ACCENT).bold(),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(SURFACE));

    frame.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: false }), area);
}
