use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct QueryArgs {
    /// Path to the case directory
    pub case_dir: PathBuf,

    /// Query string in WireHunt DSL
    pub query: String,

    /// Maximum results to return
    #[arg(short, long, default_value_t = 50)]
    pub limit: usize,

    /// Output format
    #[arg(short, long, default_value = "table", value_parser = ["table", "json", "csv"])]
    pub format: String,
}

pub fn run(args: QueryArgs) -> Result<()> {
    println!(
        "  {} '{}' in {} (limit: {}, format: {})",
        console::style("querying").green().bold(),
        console::style(&args.query).cyan(),
        args.case_dir.display(),
        args.limit,
        args.format,
    );

    println!(
        "\n  {} query engine not yet implemented -- coming in Phase 6",
        console::style("note:").yellow().bold(),
    );

    Ok(())
}
