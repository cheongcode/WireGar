pub mod analyze;
pub mod hunt;
pub mod query;
pub mod extract;
pub mod export;
pub mod live;
pub mod ai;
pub mod serve;

use clap::{Parser, Subcommand};
use anyhow::Result;

#[derive(Parser)]
#[command(
    name = "wirehunt",
    about = "God-tier network forensic engine",
    long_about = "WireHunt - All-in-one network forensic engine for CTF, IOC detection,\n\
                  credential harvesting, protocol analysis, and AI-powered investigation.\n\n\
                  Replaces Wireshark, tshark, and everything in between.",
    version,
    propagate_version = true,
    styles = get_styles(),
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Analyze a PCAP file: parse, sessionize, extract, detect, write report
    Analyze(analyze::AnalyzeArgs),

    /// Run specific detection rule packs against an analyzed case
    Hunt(hunt::HuntArgs),

    /// Search the case index with the WireHunt query DSL
    Query(query::QueryArgs),

    /// Re-run extraction on selected streams or apply decode chains
    Extract(extract::ExtractArgs),

    /// Export filtered PCAPs, HTML reports, or STIX bundles
    Export(export::ExportArgs),

    /// Capture and analyze live network traffic in real-time
    Live(live::LiveArgs),

    /// AI-powered analysis (off by default, requires API key)
    Ai(ai::AiArgs),

    /// Launch web GUI -- open browser with drag-and-drop dashboard
    Serve(serve::ServeArgs),
}

pub fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Analyze(args) => analyze::run(args),
        Commands::Hunt(args) => hunt::run(args),
        Commands::Query(args) => query::run(args),
        Commands::Extract(args) => extract::run(args),
        Commands::Export(args) => export::run(args),
        Commands::Live(args) => live::run(args),
        Commands::Ai(args) => ai::run(args),
        Commands::Serve(args) => serve::run(args),
    }
}

fn get_styles() -> clap::builder::Styles {
    clap::builder::Styles::styled()
        .header(
            clap::builder::styling::AnsiColor::BrightCyan
                .on_default()
                .bold(),
        )
        .usage(
            clap::builder::styling::AnsiColor::BrightCyan
                .on_default()
                .bold(),
        )
        .literal(
            clap::builder::styling::AnsiColor::BrightGreen
                .on_default()
                .bold(),
        )
        .placeholder(
            clap::builder::styling::AnsiColor::BrightWhite
                .on_default()
                .dimmed(),
        )
}
