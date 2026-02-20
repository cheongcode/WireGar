use anyhow::{Context, Result};
use clap::Args;
use std::path::PathBuf;

use wirehunt_core::index::SearchIndex;

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
    let index_path = args.case_dir.join("index.db");

    let idx = SearchIndex::open(&index_path).with_context(|| {
        format!(
            "no search index at {}. Run `wirehunt analyze` with --index first.",
            index_path.display()
        )
    })?;

    let results = idx.query(&args.query, args.limit)?;

    if results.is_empty() {
        println!(
            "  {} no results for '{}'",
            console::style("query:").yellow().bold(),
            args.query,
        );
        return Ok(());
    }

    match args.format.as_str() {
        "json" => {
            let json_results: Vec<serde_json::Value> = results
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "table": r.table,
                        "id": r.id,
                        "rank": r.rank,
                        "fields": r.metadata,
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json_results)?);
        }
        "csv" => {
            println!("table,id,rank,snippet");
            for r in &results {
                let snippet_escaped = r.snippet.replace(',', ";").replace('\n', " ");
                println!(
                    "{},{},{:.2},\"{}\"",
                    r.table,
                    r.id,
                    r.rank,
                    snippet_escaped.replace('"', "\"\""),
                );
            }
        }
        _ => {
            println!(
                "  {} '{}' -> {} results\n",
                console::style("query:").green().bold(),
                console::style(&args.query).cyan(),
                console::style(results.len()).green().bold(),
            );

            for (i, r) in results.iter().enumerate() {
                let table_badge = match r.table.as_str() {
                    "fts_streams" => console::style("STREAM").cyan(),
                    "fts_dns" => console::style("DNS").green(),
                    "fts_http" => console::style("HTTP").blue(),
                    "fts_credentials" => console::style("CRED").red(),
                    "fts_artifacts" => console::style("FILE").yellow(),
                    "fts_findings" => console::style("FIND").magenta(),
                    "fts_tls" => console::style("TLS").white(),
                    _ => console::style(r.table.as_str()).white(),
                };

                let snippet_display = if r.snippet.len() > 200 {
                    format!("{}...", &r.snippet[..200])
                } else {
                    r.snippet.clone()
                };

                println!(
                    "  {:>3}. [{}] {}",
                    i + 1,
                    table_badge,
                    snippet_display,
                );
            }
        }
    }

    Ok(())
}
