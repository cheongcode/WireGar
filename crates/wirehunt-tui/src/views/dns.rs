use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::app::App;

const ACCENT: Color = Color::Cyan;
const SURFACE: Color = Color::Rgb(49, 50, 68);
const GREEN: Color = Color::Rgb(166, 227, 161);

pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = Vec::new();

    lines.push(Line::from(Span::styled(
        format!("  {:<4} {:<6} {:<8} {:<35} {:<30}",
            "#", "DIR", "TYPE", "QUERY NAME", "RESPONSE"),
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(Span::styled(
        "  ".to_string() + &"─".repeat(area.width.saturating_sub(4) as usize),
        Style::default().fg(Color::Rgb(69, 71, 90)),
    )));

    for (i, rec) in app.report.dns_records.iter().enumerate() {
        let is_selected = i == app.selected_index;
        let bg = if is_selected { Color::Rgb(49, 50, 68) } else { Color::Reset };
        let marker = if is_selected { "▸ " } else { "  " };

        let dir = if rec.is_response { "RESP" } else { "QUERY" };
        let dir_color = if rec.is_response { GREEN } else { Color::Rgb(137, 180, 250) };
        let response = rec.response_data.join(", ");

        lines.push(Line::from(vec![
            Span::styled(marker, Style::default().fg(ACCENT).bg(bg)),
            Span::styled(format!("{:<4}", i), Style::default().fg(Color::DarkGray).bg(bg)),
            Span::styled(format!("{:<6}", dir), Style::default().fg(dir_color).bg(bg).bold()),
            Span::styled(format!("{:<8}", rec.record_type), Style::default().fg(ACCENT).bg(bg)),
            Span::styled(
                format!("{:<35}", truncate(&rec.query_name, 33)),
                Style::default().fg(Color::White).bg(bg),
            ),
            Span::styled(
                format!("{:<30}", truncate(&response, 28)),
                Style::default().fg(GREEN).bg(bg),
            ),
        ]));
    }

    if app.report.dns_records.is_empty() {
        lines.push(Line::from(Span::styled("  No DNS records", Style::default().fg(Color::DarkGray))));
    }

    let block = Block::default()
        .title(Span::styled(
            format!(" DNS Records ({}) ", app.report.dns_records.len()),
            Style::default().fg(ACCENT).bold(),
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(SURFACE));

    frame.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: false }), area);
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max { format!("{}...", &s[..max.saturating_sub(3)]) }
    else { s.to_string() }
}
