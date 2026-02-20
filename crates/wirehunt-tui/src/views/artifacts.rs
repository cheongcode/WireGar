use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::app::App;

const ACCENT: Color = Color::Cyan;
const SURFACE: Color = Color::Rgb(49, 50, 68);
const YELLOW: Color = Color::Rgb(249, 226, 175);

pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = Vec::new();

    lines.push(Line::from(Span::styled(
        format!("  {:<6} {:<12} {:<30} {:<12} {:<20}",
            "#", "TYPE", "NAME", "SIZE", "MIME"),
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(Span::styled(
        "  ".to_string() + &"─".repeat(area.width.saturating_sub(4) as usize),
        Style::default().fg(Color::Rgb(69, 71, 90)),
    )));

    for (i, art) in app.report.artifacts.iter().enumerate() {
        let is_selected = i == app.selected_index;
        let bg = if is_selected { Color::Rgb(49, 50, 68) } else { Color::Reset };
        let marker = if is_selected { "▸ " } else { "  " };

        let kind = format!("{:?}", art.kind);
        let name = art.name.as_deref().unwrap_or("-");
        let mime = art.mime_type.as_deref().unwrap_or("-");
        let size = format_bytes(art.size_bytes);

        lines.push(Line::from(vec![
            Span::styled(marker, Style::default().fg(ACCENT).bg(bg)),
            Span::styled(format!("{:<6}", i), Style::default().fg(Color::DarkGray).bg(bg)),
            Span::styled(format!("{:<12}", kind), Style::default().fg(YELLOW).bg(bg).bold()),
            Span::styled(format!("{:<30}", truncate(name, 28)), Style::default().fg(Color::White).bg(bg)),
            Span::styled(format!("{:<12}", size), Style::default().fg(Color::Rgb(180, 190, 254)).bg(bg)),
            Span::styled(format!("{:<20}", truncate(mime, 18)), Style::default().fg(Color::DarkGray).bg(bg)),
        ]));

        // Show hash on next line if selected
        if is_selected {
            lines.push(Line::from(vec![
                Span::styled("    SHA256: ", Style::default().fg(Color::DarkGray).bg(bg)),
                Span::styled(&art.sha256, Style::default().fg(Color::Rgb(137, 180, 250)).bg(bg)),
            ]));
        }
    }

    if app.report.artifacts.is_empty() {
        lines.push(Line::from(Span::styled("  No artifacts extracted", Style::default().fg(Color::DarkGray))));
    }

    let block = Block::default()
        .title(Span::styled(
            format!(" Artifacts ({}) ", app.report.artifacts.len()),
            Style::default().fg(ACCENT).bold(),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(SURFACE));

    frame.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: false }), area);
}

fn format_bytes(bytes: u64) -> String {
    if bytes >= 1_048_576 { format!("{:.1} MB", bytes as f64 / 1_048_576.0) }
    else if bytes >= 1024 { format!("{:.1} KB", bytes as f64 / 1024.0) }
    else { format!("{} B", bytes) }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max { format!("{}...", &s[..max.saturating_sub(3)]) }
    else { s.to_string() }
}
