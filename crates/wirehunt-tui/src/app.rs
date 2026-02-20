use wirehunt_core::models::Report;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tab {
    Dashboard,
    Flows,
    Streams,
    Artifacts,
    Credentials,
    DnsLog,
    HttpLog,
}

impl Tab {
    pub const ALL: &[Tab] = &[
        Tab::Dashboard,
        Tab::Flows,
        Tab::Streams,
        Tab::Artifacts,
        Tab::Credentials,
        Tab::DnsLog,
        Tab::HttpLog,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            Tab::Dashboard => " Dashboard ",
            Tab::Flows => " Flows ",
            Tab::Streams => " Streams ",
            Tab::Artifacts => " Artifacts ",
            Tab::Credentials => " Creds ",
            Tab::DnsLog => " DNS ",
            Tab::HttpLog => " HTTP ",
        }
    }

    pub fn key_hint(&self) -> &'static str {
        match self {
            Tab::Dashboard => "1",
            Tab::Flows => "2",
            Tab::Streams => "3",
            Tab::Artifacts => "4",
            Tab::Credentials => "5",
            Tab::DnsLog => "6",
            Tab::HttpLog => "7",
        }
    }
}

pub struct App {
    pub report: Report,
    pub active_tab: Tab,
    pub running: bool,
    pub scroll_offset: usize,
    pub selected_index: usize,
    pub show_help: bool,
    pub stream_detail_index: Option<usize>,
}

impl App {
    pub fn new(report: Report) -> Self {
        Self {
            report,
            active_tab: Tab::Dashboard,
            running: true,
            scroll_offset: 0,
            selected_index: 0,
            show_help: false,
            stream_detail_index: None,
        }
    }

    pub fn next_tab(&mut self) {
        let tabs = Tab::ALL;
        let idx = tabs.iter().position(|t| *t == self.active_tab).unwrap_or(0);
        self.active_tab = tabs[(idx + 1) % tabs.len()];
        self.reset_scroll();
    }

    pub fn prev_tab(&mut self) {
        let tabs = Tab::ALL;
        let idx = tabs.iter().position(|t| *t == self.active_tab).unwrap_or(0);
        self.active_tab = tabs[(idx + tabs.len() - 1) % tabs.len()];
        self.reset_scroll();
    }

    pub fn set_tab(&mut self, tab: Tab) {
        self.active_tab = tab;
        self.reset_scroll();
    }

    pub fn scroll_down(&mut self) {
        let max = self.max_items();
        if self.selected_index + 1 < max {
            self.selected_index += 1;
        }
    }

    pub fn scroll_up(&mut self) {
        if self.selected_index > 0 {
            self.selected_index -= 1;
        }
    }

    pub fn page_down(&mut self) {
        let max = self.max_items();
        self.selected_index = (self.selected_index + 20).min(max.saturating_sub(1));
    }

    pub fn page_up(&mut self) {
        self.selected_index = self.selected_index.saturating_sub(20);
    }

    pub fn go_top(&mut self) {
        self.selected_index = 0;
    }

    pub fn go_bottom(&mut self) {
        let max = self.max_items();
        if max > 0 {
            self.selected_index = max - 1;
        }
    }

    fn max_items(&self) -> usize {
        match self.active_tab {
            Tab::Dashboard => 0,
            Tab::Flows => self.report.flows.len(),
            Tab::Streams => self.report.streams.len(),
            Tab::Artifacts => self.report.artifacts.len(),
            Tab::Credentials => self.report.credentials.len(),
            Tab::DnsLog => self.report.dns_records.len(),
            Tab::HttpLog => self.report.http_transactions.len(),
        }
    }

    fn reset_scroll(&mut self) {
        self.scroll_offset = 0;
        self.selected_index = 0;
        self.stream_detail_index = None;
    }

    pub fn enter(&mut self) {
        if self.active_tab == Tab::Streams && !self.report.streams.is_empty() {
            self.stream_detail_index = Some(self.selected_index);
        }
    }

    pub fn escape(&mut self) {
        if self.stream_detail_index.is_some() {
            self.stream_detail_index = None;
        } else if self.show_help {
            self.show_help = false;
        }
    }
}
