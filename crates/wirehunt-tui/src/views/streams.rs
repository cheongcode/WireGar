use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::app::App;
use wirehunt_core::models::StreamDirection;

const ACCENT: Color = Color::Cyan;
const SURFACE: Color = Color::Rgb(49, 50, 68);
const CLIENT_COLOR: Color = Color::Rgb(137, 180, 250);
const SERVER_COLOR: Color = Color::Rgb(166, 227, 161);

pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    if let Some(detail_idx) = app.stream_detail_index {
        if let Some(stream) = app.report.streams.get(detail_idx) {
            render_stream_detail(frame, stream, area);
            return;
        }
    }

    render_stream_list(frame, app, area);
}

fn render_stream_list(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = Vec::new();

    lines.push(Line::from(Span::styled(
        format!("  {:<6} {:<10} {:<12} {:<10} {:<8}",
            "#", "PROTO", "FLOW", "BYTES", "SEGS"),
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(Span::styled(
        "  ".to_string() + &"─".repeat(area.width.saturating_sub(4) as usize),
        Style::default().fg(Color::Rgb(69, 71, 90)),
    )));

    for (i, stream) in app.report.streams.iter().enumerate() {
        let is_selected = i == app.selected_index;
        let bg = if is_selected { Color::Rgb(49, 50, 68) } else { Color::Reset };
        let marker = if is_selected { "▸ " } else { "  " };

        lines.push(Line::from(vec![
            Span::styled(marker, Style::default().fg(ACCENT).bg(bg)),
            Span::styled(format!("{:<6}", i), Style::default().fg(Color::DarkGray).bg(bg)),
            Span::styled(
                format!("{:<10}", format!("{:?}", stream.protocol)),
                Style::default().fg(ACCENT).bg(bg).add_modifier(Modifier::BOLD),
            ),
            Span::styled(
                format!("{:<12}", &stream.flow_id[..stream.flow_id.len().min(10)]),
                Style::default().fg(Color::DarkGray).bg(bg),
            ),
            Span::styled(
                format!("{:<10}", stream.total_bytes),
                Style::default().fg(Color::White).bg(bg),
            ),
            Span::styled(
                format!("{:<8}", stream.segments.len()),
                Style::default().fg(Color::White).bg(bg),
            ),
        ]));
    }

    if app.report.streams.is_empty() {
        lines.push(Line::from(Span::styled("  No streams", Style::default().fg(Color::DarkGray))));
    }

    let block = Block::default()
        .title(Span::styled(
            format!(" Streams ({}) ─ press Enter to view detail ", app.report.streams.len()),
            Style::default().fg(ACCENT).bold(),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(SURFACE));

    frame.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: false }), area);
}

fn render_stream_detail(
    frame: &mut Frame,
    stream: &wirehunt_core::models::Stream,
    area: Rect,
) {
    let mut lines = Vec::new();

    lines.push(Line::from(vec![
        Span::styled("  Protocol: ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{:?}", stream.protocol), Style::default().fg(ACCENT).bold()),
        Span::styled("  Total: ", Style::default().fg(Color::DarkGray)),
        Span::styled(format!("{} bytes", stream.total_bytes), Style::default().fg(Color::White)),
        Span::styled("  Segments: ", Style::default().fg(Color::DarkGray)),
        Span::styled(stream.segments.len().to_string(), Style::default().fg(Color::White)),
    ]));
    lines.push(Line::from(Span::styled(
        "  ".to_string() + &"─".repeat(area.width.saturating_sub(4) as usize),
        Style::default().fg(Color::Rgb(69, 71, 90)),
    )));

    for (i, seg) in stream.segments.iter().enumerate() {
        let (dir_label, dir_color) = match seg.direction {
            StreamDirection::ClientToServer => ("▶ CLIENT", CLIENT_COLOR),
            StreamDirection::ServerToClient => ("◀ SERVER", SERVER_COLOR),
            StreamDirection::Unknown => ("? UNKNWN", Color::Gray),
        };

        lines.push(Line::from(vec![
            Span::styled(format!("  [{:3}] ", i), Style::default().fg(Color::DarkGray)),
            Span::styled(format!("{} ", dir_label), Style::default().fg(dir_color).bold()),
            Span::styled(format!("({} bytes)", seg.data.len()), Style::default().fg(Color::DarkGray)),
        ]));

        // Show content as text (if printable) or hex dump
        let text = String::from_utf8_lossy(&seg.data);
        let is_printable = seg.data.iter().all(|&b| b >= 0x20 && b < 0x7f || b == b'\n' || b == b'\r' || b == b'\t');

        if is_printable {
            for line in text.lines().take(20) {
                lines.push(Line::from(Span::styled(
                    format!("        {}", line),
                    Style::default().fg(dir_color).add_modifier(Modifier::DIM),
                )));
            }
            if text.lines().count() > 20 {
                lines.push(Line::from(Span::styled(
                    format!("        ... ({} more lines)", text.lines().count() - 20),
                    Style::default().fg(Color::DarkGray),
                )));
            }
        } else {
            // Hex dump (first 64 bytes)
            let hex_line: String = seg.data.iter().take(64)
                .map(|b| format!("{:02x}", b))
                .collect::<Vec<_>>()
                .chunks(16)
                .map(|chunk| chunk.join(" "))
                .collect::<Vec<_>>()
                .join("\n        ");
            lines.push(Line::from(Span::styled(
                format!("        {}", hex_line),
                Style::default().fg(Color::Rgb(180, 190, 254)),
            )));
        }
        lines.push(Line::from(""));
    }

    let block = Block::default()
        .title(Span::styled(
            format!(" Stream Detail ─ {:?} ─ Esc to go back ", stream.protocol),
            Style::default().fg(ACCENT).bold(),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(SURFACE));

    frame.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: false }), area);
}
