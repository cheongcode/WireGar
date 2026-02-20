use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};

use crate::app::App;

const ACCENT: Color = Color::Cyan;
const SURFACE: Color = Color::Rgb(49, 50, 68);
const GREEN: Color = Color::Rgb(166, 227, 161);
const YELLOW: Color = Color::Rgb(249, 226, 175);
const RED: Color = Color::Rgb(243, 139, 168);

pub fn render(frame: &mut Frame, app: &App, area: Rect) {
    let mut lines = Vec::new();

    lines.push(Line::from(Span::styled(
        format!("  {:<4} {:<8} {:<6} {:<25} {:<35} {:<12}",
            "#", "METHOD", "STATUS", "HOST", "URI", "TYPE"),
        Style::default().fg(ACCENT).add_modifier(Modifier::BOLD),
    )));
    lines.push(Line::from(Span::styled(
        "  ".to_string() + &"─".repeat(area.width.saturating_sub(4) as usize),
        Style::default().fg(Color::Rgb(69, 71, 90)),
    )));

    for (i, tx) in app.report.http_transactions.iter().enumerate() {
        let is_selected = i == app.selected_index;
        let bg = if is_selected { Color::Rgb(49, 50, 68) } else { Color::Reset };
        let marker = if is_selected { "▸ " } else { "  " };

        let method_color = match tx.method.as_str() {
            "GET" => GREEN,
            "POST" => YELLOW,
            "PUT" | "PATCH" => Color::Rgb(137, 180, 250),
            "DELETE" => RED,
            _ => Color::White,
        };

        let status = tx.status_code.map(|c| c.to_string()).unwrap_or_else(|| "-".to_string());
        let status_color = match tx.status_code {
            Some(200..=299) => GREEN,
            Some(300..=399) => YELLOW,
            Some(400..=499) => Color::Rgb(250, 179, 135),
            Some(500..=599) => RED,
            _ => Color::DarkGray,
        };

        let host = tx.host.as_deref().unwrap_or("-");
        let ctype = tx.content_type.as_deref().unwrap_or("-");

        lines.push(Line::from(vec![
            Span::styled(marker, Style::default().fg(ACCENT).bg(bg)),
            Span::styled(format!("{:<4}", i), Style::default().fg(Color::DarkGray).bg(bg)),
            Span::styled(format!("{:<8}", tx.method), Style::default().fg(method_color).bg(bg).bold()),
            Span::styled(format!("{:<6}", status), Style::default().fg(status_color).bg(bg).bold()),
            Span::styled(format!("{:<25}", truncate(host, 23)), Style::default().fg(Color::White).bg(bg)),
            Span::styled(format!("{:<35}", truncate(&tx.uri, 33)), Style::default().fg(ACCENT).bg(bg)),
            Span::styled(format!("{:<12}", truncate(ctype, 10)), Style::default().fg(Color::DarkGray).bg(bg)),
        ]));

        if is_selected {
            if let Some(ua) = &tx.user_agent {
                lines.push(Line::from(vec![
                    Span::styled("    User-Agent: ", Style::default().fg(Color::DarkGray).bg(bg)),
                    Span::styled(ua, Style::default().fg(Color::Rgb(180, 190, 254)).bg(bg)),
                ]));
            }
            if !tx.cookies.is_empty() {
                lines.push(Line::from(vec![
                    Span::styled("    Cookies: ", Style::default().fg(Color::DarkGray).bg(bg)),
                    Span::styled(tx.cookies.join("; "), Style::default().fg(YELLOW).bg(bg)),
                ]));
            }
        }
    }

    if app.report.http_transactions.is_empty() {
        lines.push(Line::from(Span::styled("  No HTTP transactions", Style::default().fg(Color::DarkGray))));
    }

    let block = Block::default()
        .title(Span::styled(
            format!(" HTTP Transactions ({}) ", app.report.http_transactions.len()),
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
