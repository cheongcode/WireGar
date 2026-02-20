use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::app::App;

const ACCENT: Color = Color::Cyan;
const SURFACE: Color = Color::Rgb(49, 50, 68);
const RED: Color = Color::Rgb(243, 139, 168);
const YELLOW: Color = Color::Rgb(249, 226, 175);

pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = Vec::new();

    lines.push(Line::from(Span::styled(
        format!("  {:<6} {:<18} {:<16} {:<14} {:<30}",
            "#", "TYPE", "USERNAME", "SERVICE", "SECRET"),
        Style::default().fg(RED).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(Span::styled(
        "  ".to_string() + &"─".repeat(area.width.saturating_sub(4) as usize),
        Style::default().fg(Color::Rgb(69, 71, 90)),
    )));

    for (i, cred) in app.report.credentials.iter().enumerate() {
        let is_selected = i == app.selected_index;
        let bg = if is_selected { Color::Rgb(49, 50, 68) } else { Color::Reset };
        let marker = if is_selected { "▸ " } else { "  " };

        let kind = format!("{:?}", cred.kind);
        let user = cred.username.as_deref().unwrap_or("-");
        let svc = cred.service.as_deref().unwrap_or("-");
        let secret = &cred.secret[..cred.secret.len().min(28)];

        lines.push(Line::from(vec![
            Span::styled(marker, Style::default().fg(RED).bg(bg)),
            Span::styled(format!("{:<6}", i), Style::default().fg(Color::DarkGray).bg(bg)),
            Span::styled(format!("{:<18}", truncate(&kind, 16)), Style::default().fg(YELLOW).bg(bg).bold()),
            Span::styled(format!("{:<16}", truncate(user, 14)), Style::default().fg(Color::White).bg(bg)),
            Span::styled(format!("{:<14}", truncate(svc, 12)), Style::default().fg(ACCENT).bg(bg)),
            Span::styled(format!("{:<30}", secret), Style::default().fg(RED).bg(bg).bold()),
        ]));

        if is_selected {
            lines.push(Line::from(vec![
                Span::styled("    Full secret: ", Style::default().fg(Color::DarkGray).bg(bg)),
                Span::styled(&cred.secret, Style::default().fg(RED).bg(bg)),
            ]));
            lines.push(Line::from(vec![
                Span::styled("    Evidence: ", Style::default().fg(Color::DarkGray).bg(bg)),
                Span::styled(&cred.evidence.description, Style::default().fg(Color::Rgb(180, 190, 254)).bg(bg)),
            ]));
        }
    }

    if app.report.credentials.is_empty() {
        lines.push(Line::from(Span::styled(
            "  No credentials harvested",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let title_style = if app.report.credentials.is_empty() {
        Style::default().fg(ACCENT).bold()
    } else {
        Style::default().fg(RED).bold()
    };

    let block = Block::default()
        .title(Span::styled(
            format!(" Credentials ({}) ", app.report.credentials.len()),
            title_style,
        ))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(SURFACE));

    frame.render_widget(Paragraph::new(lines).block(block).wrap(Wrap { trim: false }), area);
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max { format!("{}...", &s[..max.saturating_sub(3)]) }
    else { s.to_string() }
}
