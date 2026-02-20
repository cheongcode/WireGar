use anyhow::{Context, Result};
use clap::{Args, Subcommand};
use std::path::PathBuf;

use wirehunt_core::models::Report;

#[derive(Args)]
pub struct AiArgs {
    #[command(subcommand)]
    pub command: AiCommands,
}

#[derive(Subcommand)]
pub enum AiCommands {
    /// Get AI-powered analysis and storyline hypotheses
    Explain {
        /// Path to the case directory
        case_dir: PathBuf,

        /// Allow raw stream excerpts (privacy risk)
        #[arg(long, default_value_t = false)]
        allow_raw: bool,
    },

    /// Get AI-suggested queries and pivots
    SuggestQueries {
        /// Path to the case directory
        case_dir: PathBuf,
    },

    /// Generate detection rules from a finding
    GenerateRule {
        /// Path to the case directory
        case_dir: PathBuf,

        /// Finding ID to generate rule from (or "first" for the top finding)
        #[arg(long, default_value = "first")]
        from_finding: String,
    },

    /// AI-assisted decode/decrypt of an artifact or stream data
    Decode {
        /// Path to the case directory
        case_dir: PathBuf,

        /// Stream or artifact ID to decode
        #[arg(long)]
        id: String,
    },

    /// AI-assisted CTF flag solving
    Solve {
        /// Path to the case directory
        case_dir: PathBuf,
    },

    /// Configure AI provider and API key
    Login,
}

pub fn run(args: AiArgs) -> Result<()> {
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(run_async(args))
}

async fn run_async(args: AiArgs) -> Result<()> {
    match args.command {
        AiCommands::Login => run_login().await,
        AiCommands::Explain {
            case_dir,
            allow_raw,
        } => run_explain(case_dir, allow_raw).await,
        AiCommands::Solve { case_dir } => run_solve(case_dir).await,
        AiCommands::SuggestQueries { case_dir } => run_suggest_queries(case_dir).await,
        AiCommands::GenerateRule {
            case_dir,
            from_finding,
        } => run_generate_rule(case_dir, from_finding).await,
        AiCommands::Decode { case_dir, id } => run_decode(case_dir, id).await,
    }
}

fn load_report(case_dir: &std::path::Path) -> Result<Report> {
    let path = case_dir.join("report.json");
    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read {}. Run `wirehunt analyze` first.", path.display()))?;
    serde_json::from_str(&data).context("failed to parse report.json")
}

async fn run_login() -> Result<()> {
    println!(
        "\n  {}",
        console::style("WireHunt AI Configuration").cyan().bold(),
    );

    let config_path = wirehunt_ai::AiConfig::config_path();
    println!(
        "  config: {}\n",
        console::style(config_path.display()).white(),
    );

    println!("  Supported providers:");
    println!("    1. OpenAI (GPT-4o)");
    println!("    2. Anthropic (Claude)");
    println!("    3. Ollama (local, no API key needed)");
    println!();

    println!("  Set your API key via environment variable:");
    println!(
        "    {}",
        console::style("export OPENAI_API_KEY=sk-...").green(),
    );
    println!(
        "    {}",
        console::style("export ANTHROPIC_API_KEY=sk-ant-...").green(),
    );
    println!();

    println!("  Or create a config file at:");
    println!(
        "    {}",
        console::style(config_path.display()).green(),
    );
    println!();
    println!("  Example config.toml:");
    println!(
        "{}",
        console::style(
            "    provider = \"openai\"\n    api_key = \"sk-...\"\n    model = \"gpt-4o\"\n    max_tokens = 4096\n    temperature = 0.3"
        )
        .cyan(),
    );

    let mut config = wirehunt_ai::AiConfig::default();

    if std::env::var("OPENAI_API_KEY").is_ok() {
        config.provider = wirehunt_ai::AiProvider::OpenAi;
        config.api_key = Some(std::env::var("OPENAI_API_KEY")?);
        println!(
            "\n  {} detected OPENAI_API_KEY in environment",
            console::style("found:").green().bold(),
        );
    } else if std::env::var("ANTHROPIC_API_KEY").is_ok() {
        config.provider = wirehunt_ai::AiProvider::Anthropic;
        config.api_key = Some(std::env::var("ANTHROPIC_API_KEY")?);
        println!(
            "\n  {} detected ANTHROPIC_API_KEY in environment",
            console::style("found:").green().bold(),
        );
    } else {
        println!(
            "\n  {} no API key detected in environment. Set one of:",
            console::style("note:").yellow().bold(),
        );
        println!("    OPENAI_API_KEY, ANTHROPIC_API_KEY, or configure Ollama");
    }

    config.save()?;
    println!(
        "  {} {}",
        console::style("config saved ->").green().bold(),
        config_path.display(),
    );

    Ok(())
}

async fn run_explain(case_dir: PathBuf, allow_raw: bool) -> Result<()> {
    let report = load_report(&case_dir)?;

    println!(
        "\n  {} analyzing {} with AI...\n",
        console::style("explain:").cyan().bold(),
        case_dir.display(),
    );

    let client = wirehunt_ai::AiClient::from_config()?;
    let copilot = wirehunt_ai::AnalystCopilot::new(client);
    let response = copilot.explain(&report, allow_raw).await?;

    println!("{}", response);
    Ok(())
}

async fn run_solve(case_dir: PathBuf) -> Result<()> {
    let report = load_report(&case_dir)?;

    println!(
        "\n  {} solving CTF challenge in {} with AI...\n",
        console::style("solve:").cyan().bold(),
        case_dir.display(),
    );

    let client = wirehunt_ai::AiClient::from_config()?;
    let copilot = wirehunt_ai::AnalystCopilot::new(client);
    let response = copilot.solve(&report).await?;

    println!("{}", response);
    Ok(())
}

async fn run_suggest_queries(case_dir: PathBuf) -> Result<()> {
    let report = load_report(&case_dir)?;

    println!(
        "\n  {} generating query suggestions...\n",
        console::style("suggest:").cyan().bold(),
    );

    let client = wirehunt_ai::AiClient::from_config()?;
    let copilot = wirehunt_ai::AnalystCopilot::new(client);
    let response = copilot.suggest_queries(&report).await?;

    println!("{}", response);
    Ok(())
}

async fn run_generate_rule(case_dir: PathBuf, finding_ref: String) -> Result<()> {
    let report = load_report(&case_dir)?;

    let finding = if finding_ref == "first" {
        report
            .findings
            .first()
            .ok_or_else(|| anyhow::anyhow!("no findings in report"))?
    } else {
        report
            .findings
            .iter()
            .find(|f| f.id == finding_ref)
            .ok_or_else(|| anyhow::anyhow!("finding '{}' not found", finding_ref))?
    };

    println!(
        "\n  {} generating rules for: {}\n",
        console::style("rulegen:").cyan().bold(),
        console::style(&finding.title).yellow(),
    );

    let client = wirehunt_ai::AiClient::from_config()?;
    let generator = wirehunt_ai::RuleGenerator::new(client);
    let response = generator.generate_from_finding(finding).await?;

    println!("{}", response);
    Ok(())
}

async fn run_decode(case_dir: PathBuf, id: String) -> Result<()> {
    let report = load_report(&case_dir)?;

    let data = if let Some(stream) = report.streams.iter().find(|s| s.id.starts_with(&id)) {
        let all_data: Vec<u8> = stream
            .segments
            .iter()
            .flat_map(|seg| seg.data.iter().copied())
            .collect();
        let text = String::from_utf8_lossy(&all_data[..all_data.len().min(2000)]).to_string();
        (text, format!("Stream {} ({:?}, {} bytes)", &stream.id[..12], stream.protocol, stream.total_bytes))
    } else if let Some(artifact) = report.artifacts.iter().find(|a| a.id.starts_with(&id)) {
        let desc = format!(
            "Artifact {} ({:?}, {} bytes, {})",
            artifact.name.as_deref().unwrap_or("-"),
            artifact.kind,
            artifact.size_bytes,
            artifact.mime_type.as_deref().unwrap_or("?"),
        );
        if let Some(ref path) = artifact.path {
            let file_path = case_dir.join(path);
            if file_path.exists() {
                let data = std::fs::read(&file_path)?;
                let text = String::from_utf8_lossy(&data[..data.len().min(2000)]).to_string();
                (text, desc)
            } else {
                (format!("SHA256: {}, MD5: {}", artifact.sha256, artifact.md5), desc)
            }
        } else {
            (format!("SHA256: {}, MD5: {}", artifact.sha256, artifact.md5), desc)
        }
    } else {
        anyhow::bail!(
            "no stream or artifact found matching '{}'. Use the first few chars of the ID.",
            id
        );
    };

    println!(
        "\n  {} analyzing: {}\n",
        console::style("decode:").cyan().bold(),
        console::style(&data.1).yellow(),
    );

    let client = wirehunt_ai::AiClient::from_config()?;
    let decoder = wirehunt_ai::DecodeAssistant::new(client);
    let response = decoder.analyze_data(&data.0, &data.1).await?;

    println!("{}", response);
    Ok(())
}
