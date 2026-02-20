use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Tabs, Wrap};

use crate::app::{App, Tab};
use crate::views;

const ACCENT: Color = Color::Cyan;
const BG: Color = Color::Reset;
const HIGHLIGHT: Color = Color::Rgb(30, 30, 46);
const RED: Color = Color::Rgb(243, 139, 168);
const GREEN: Color = Color::Rgb(166, 227, 161);
const YELLOW: Color = Color::Rgb(249, 226, 175);
const MAUVE: Color = Color::Rgb(203, 166, 247);
const SURFACE: Color = Color::Rgb(49, 50, 68);

pub fn render(frame: &mut Frame, app: &App) {
    let size = frame.area();

    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // header + tabs
            Constraint::Min(5),    // main content
            Constraint::Length(1), // status bar
        ])
        .split(size);

    render_header(frame, app, outer[0]);
    render_content(frame, app, outer[1]);
    render_status_bar(frame, app, outer[2]);

    if app.show_help {
        render_help_overlay(frame, size);
    }
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let header_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Length(22),
            Constraint::Min(20),
        ])
        .split(area);

    // Logo
    let logo = Paragraph::new(Line::from(vec![
        Span::styled("  WIRE", Style::default().fg(ACCENT).add_modifier(Modifier::BOLD)),
        Span::styled("HUNT", Style::default().fg(Color::White).add_modifier(Modifier::BOLD)),
        Span::styled(" ", Style::default()),
        Span::styled(
            format!("v{}", wirehunt_core::VERSION),
            Style::default().fg(Color::DarkGray),
        ),
    ]))
    .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(SURFACE)));
    frame.render_widget(logo, header_layout[0]);

    // Tabs
    let tab_titles: Vec<Line> = Tab::ALL
        .iter()
        .map(|t| {
            let style = if *t == app.active_tab {
                Style::default().fg(Color::Black).bg(ACCENT).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            Line::from(Span::styled(t.label(), style))
        })
        .collect();

    let tabs = Tabs::new(tab_titles)
        .select(Tab::ALL.iter().position(|t| *t == app.active_tab).unwrap_or(0))
        .divider(Span::styled("│", Style::default().fg(SURFACE)))
        .block(Block::default().borders(Borders::ALL).border_style(Style::default().fg(SURFACE)));
    frame.render_widget(tabs, header_layout[1]);
}

fn render_content(frame: &mut Frame, app: &App, area: Rect) {
    match app.active_tab {
        Tab::Dashboard => views::dashboard::render(frame, app, area),
        Tab::Flows => views::flows::render(frame, app, area),
        Tab::Streams => views::streams::render(frame, app, area),
        Tab::Artifacts => views::artifacts::render(frame, app, area),
        Tab::Credentials => views::credentials::render(frame, app, area),
        Tab::DnsLog => views::dns::render(frame, app, area),
        Tab::HttpLog => views::http::render(frame, app, area),
    }
}

fn render_status_bar(frame: &mut Frame, app: &App, area: Rect) {
    let pcap = &app.report.metadata.pcap_filename;
    let packets = app.report.metadata.total_packets;
    let flows = app.report.flows.len();
    let streams = app.report.streams.len();
    let creds = app.report.credentials.len();

    let bar = Line::from(vec![
        Span::styled(" ", Style::default().bg(ACCENT).fg(Color::Black).bold()),
        Span::styled(
            format!(" {} ", pcap),
            Style::default().bg(ACCENT).fg(Color::Black).bold(),
        ),
        Span::styled(" ", Style::default()),
        Span::styled(
            format!("{}pkts ", packets),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            format!("{}flows ", flows),
            Style::default().fg(Color::DarkGray),
        ),
        Span::styled(
            format!("{}streams ", streams),
            Style::default().fg(Color::DarkGray),
        ),
        if creds > 0 {
            Span::styled(
                format!("{}creds! ", creds),
                Style::default().fg(RED).bold(),
            )
        } else {
            Span::styled("", Style::default())
        },
        Span::styled(
            "  j/k:scroll  Tab:switch  Enter:detail  ?:help  q:quit",
            Style::default().fg(Color::DarkGray),
        ),
    ]);

    frame.render_widget(Paragraph::new(bar), area);
}

fn render_help_overlay(frame: &mut Frame, area: Rect) {
    let popup_width = 52;
    let popup_height = 18;
    let popup_area = Rect {
        x: area.width.saturating_sub(popup_width) / 2,
        y: area.height.saturating_sub(popup_height) / 2,
        width: popup_width.min(area.width),
        height: popup_height.min(area.height),
    };

    frame.render_widget(Clear, popup_area);

    let help_text = vec![
        Line::from(Span::styled("  KEYBINDINGS", Style::default().fg(ACCENT).bold())),
        Line::from(""),
        Line::from(vec![
            Span::styled("  1-7     ", Style::default().fg(YELLOW).bold()),
            Span::raw("Switch to tab"),
        ]),
        Line::from(vec![
            Span::styled("  Tab     ", Style::default().fg(YELLOW).bold()),
            Span::raw("Next tab"),
        ]),
        Line::from(vec![
            Span::styled("  S-Tab   ", Style::default().fg(YELLOW).bold()),
            Span::raw("Previous tab"),
        ]),
        Line::from(vec![
            Span::styled("  j / ↓   ", Style::default().fg(YELLOW).bold()),
            Span::raw("Scroll down"),
        ]),
        Line::from(vec![
            Span::styled("  k / ↑   ", Style::default().fg(YELLOW).bold()),
            Span::raw("Scroll up"),
        ]),
        Line::from(vec![
            Span::styled("  d / PgDn", Style::default().fg(YELLOW).bold()),
            Span::raw("Page down"),
        ]),
        Line::from(vec![
            Span::styled("  u / PgUp", Style::default().fg(YELLOW).bold()),
            Span::raw("Page up"),
        ]),
        Line::from(vec![
            Span::styled("  g       ", Style::default().fg(YELLOW).bold()),
            Span::raw("Go to top"),
        ]),
        Line::from(vec![
            Span::styled("  G       ", Style::default().fg(YELLOW).bold()),
            Span::raw("Go to bottom"),
        ]),
        Line::from(vec![
            Span::styled("  Enter   ", Style::default().fg(YELLOW).bold()),
            Span::raw("Open detail view"),
        ]),
        Line::from(vec![
            Span::styled("  Esc     ", Style::default().fg(YELLOW).bold()),
            Span::raw("Close detail / help"),
        ]),
        Line::from(vec![
            Span::styled("  q       ", Style::default().fg(YELLOW).bold()),
            Span::raw("Quit"),
        ]),
        Line::from(vec![
            Span::styled("  ?       ", Style::default().fg(YELLOW).bold()),
            Span::raw("Toggle this help"),
        ]),
    ];

    let help = Paragraph::new(help_text)
        .block(
            Block::default()
                .title(Span::styled(" Help ", Style::default().fg(ACCENT).bold()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(MAUVE))
                .style(Style::default().bg(Color::Rgb(24, 24, 37))),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(help, popup_area);
}
