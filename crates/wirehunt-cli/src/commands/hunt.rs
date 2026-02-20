use anyhow::Result;
use clap::Args;
use std::path::PathBuf;

#[derive(Args)]
pub struct HuntArgs {
    /// Path to the case directory (output of `analyze`)
    pub case_dir: PathBuf,

    /// Run CTF flag detection rules
    #[arg(long, default_value_t = false)]
    pub ctf: bool,

    /// Run credential detection rules
    #[arg(long, default_value_t = false)]
    pub creds: bool,

    /// Run file/artifact detection rules
    #[arg(long, default_value_t = false)]
    pub files: bool,

    /// Run anomaly detection rules
    #[arg(long, default_value_t = false)]
    pub anomalies: bool,

    /// Run data exfiltration detection rules
    #[arg(long, default_value_t = false)]
    pub exfil: bool,

    /// Run all rule packs
    #[arg(long, default_value_t = false)]
    pub all: bool,
}

pub fn run(args: HuntArgs) -> Result<()> {
    let packs: Vec<&str> = [
        args.ctf.then_some("ctf"),
        args.creds.then_some("creds"),
        args.files.then_some("files"),
        args.anomalies.then_some("anomalies"),
        args.exfil.then_some("exfil"),
    ]
    .into_iter()
    .flatten()
    .collect();

    let packs_display = if args.all || packs.is_empty() {
        "all".to_string()
    } else {
        packs.join(", ")
    };

    println!(
        "  {} {} with rule packs: [{}]",
        console::style("hunting").green().bold(),
        args.case_dir.display(),
        console::style(&packs_display).cyan(),
    );

    println!(
        "\n  {} hunt engine not yet implemented -- coming in Phase 5",
        console::style("note:").yellow().bold(),
    );

    Ok(())
}
