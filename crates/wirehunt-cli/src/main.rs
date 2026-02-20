mod commands;
mod banner;

use clap::Parser;
use commands::Cli;

fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "wirehunt=info".into()),
        )
        .with_target(false)
        .init();

    banner::print_banner();

    let cli = Cli::parse();

    if let Err(e) = commands::run(cli) {
        eprintln!("\x1b[1;31merror:\x1b[0m {e:#}");
        std::process::exit(1);
    }
}
