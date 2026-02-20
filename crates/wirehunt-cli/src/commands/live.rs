use anyhow::Result;
use clap::Args;

#[derive(Args)]
pub struct LiveArgs {
    /// Network interface to capture from
    pub interface: String,

    /// Analysis profile
    #[arg(short, long, default_value = "ctf")]
    pub profile: String,

    /// Alert patterns (can be specified multiple times)
    #[arg(long)]
    pub alert: Vec<String>,

    /// Duration in seconds (0 = indefinite)
    #[arg(short, long, default_value_t = 0)]
    pub duration: u64,

    /// BPF capture filter
    #[arg(long)]
    pub filter: Option<String>,
}

pub fn run(args: LiveArgs) -> Result<()> {
    println!(
        "  {} on interface '{}' (profile: {}, duration: {}s)",
        console::style("live capture").green().bold(),
        console::style(&args.interface).cyan(),
        args.profile,
        if args.duration == 0 {
            "indefinite".to_string()
        } else {
            args.duration.to_string()
        },
    );

    if !args.alert.is_empty() {
        println!(
            "  {} {:?}",
            console::style("alert patterns:").cyan(),
            args.alert,
        );
    }

    println!(
        "\n  {} live capture not yet implemented -- coming in Phase 9",
        console::style("note:").yellow().bold(),
    );

    Ok(())
}
