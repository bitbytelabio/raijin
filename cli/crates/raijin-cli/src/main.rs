//! `raijin`: runs Burp Suite with Raijin per target, serves the `raijin mcp` gateway, and reads
//! `.burp` projects offline.

mod burp;
mod catalog;
mod config;
mod history;
mod init;
mod jar;
mod mcp;
mod util;

use std::io::{IsTerminal, Write};
use std::process::ExitCode;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use serde_json::Value;

use crate::burp::instance;
use crate::config::{Mode, Target};

#[derive(Parser)]
#[command(
    name = "raijin",
    version,
    about = "Burp Suite with Raijin per target, an MCP gateway, and offline .burp review"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

// Parsed once per run; boxing the history variant buys nothing.
#[allow(clippy::large_enum_variant)]
#[derive(Subcommand)]
enum Command {
    /// Make the current folder a target: raijin.toml, burp/, .raijin/, and agent MCP config.
    Init {
        /// Do not register `raijin mcp` in .mcp.json and .omp/mcp.json.
        #[arg(long)]
        no_mcp: bool,
        /// `default_project` for raijin.toml.
        #[arg(long, default_value = "main")]
        project: String,
    },
    /// Start Burp with Raijin for a project (default: `default_project`); it keeps running after this exits.
    Up {
        project: Option<String>,
        #[arg(long, conflicts_with = "headless")]
        ui: bool,
        #[arg(long)]
        headless: bool,
    },
    /// Stop a project's Burp (default: `default_project`), or every running one with --all.
    Down {
        project: Option<String>,
        #[arg(long, conflicts_with = "project")]
        all: bool,
    },
    /// Every project of the target and its Burp state.
    Status {
        #[arg(long)]
        json: bool,
    },
    /// Offline review of the target's .burp projects and the Raijin archive; Burp need not run.
    #[command(subcommand)]
    History(HistoryCommand),
    /// stdio MCP server for coding agents (discover / execute / skill).
    Mcp {
        /// lean: the 3 gateway tools; full: also every Raijin tool directly.
        #[arg(long, value_enum, default_value_t = mcp::server::Surface::Lean)]
        surface: mcp::server::Surface,
        /// Use an already-running Raijin at this MCP URL (overrides [remote] url).
        #[arg(long)]
        remote: Option<String>,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Table,
    Jsonl,
    Json,
}

#[derive(clap::Args)]
struct Output {
    /// table (default on a terminal), jsonl (default otherwise) or json.
    #[arg(short = 'F', long, value_enum, global = true)]
    format: Option<Format>,
}

impl Output {
    fn resolve(&self) -> Format {
        self.format.unwrap_or(if std::io::stdout().is_terminal() {
            Format::Table
        } else {
            Format::Jsonl
        })
    }
}

#[derive(Subcommand)]
enum HistoryCommand {
    /// Exchanges (Proxy + archive) or scanner issues, oldest first.
    List {
        #[command(flatten)]
        params: history::list::ListParams,
        #[command(flatten)]
        output: Output,
    },
    /// One exchange or issue by ref.
    Show {
        #[command(flatten)]
        params: history::show::ShowParams,
        #[command(flatten)]
        output: Output,
    },
    /// Regex over raw requests and responses.
    Search {
        #[command(flatten)]
        params: history::search::SearchParams,
        #[command(flatten)]
        output: Output,
    },
    /// API map: host + method + path groups with parameters and statuses.
    Endpoints {
        #[command(flatten)]
        params: history::endpoints::EndpointsParams,
        #[command(flatten)]
        output: Output,
    },
    /// Unified diff of two exchanges.
    Diff {
        #[command(flatten)]
        params: history::diff::DiffParams,
        #[command(flatten)]
        output: Output,
    },
    /// amber JSON export per project, plus the archive files.
    Export {
        #[command(flatten)]
        params: history::export::ExportParams,
        #[command(flatten)]
        output: Output,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    match runtime.block_on(run(cli)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn target() -> Result<Target> {
    Target::discover_or_init(&std::env::current_dir()?)
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Init { no_mcp, project } => {
            init::run(&std::env::current_dir()?, &project, !no_mcp)
        }
        Command::Up {
            project,
            ui,
            headless,
        } => {
            let target = target()?;
            let project = target.project_or_default(project.as_deref())?;
            let mode = if ui {
                Mode::Ui
            } else if headless {
                Mode::Headless
            } else {
                target.config.mode
            };
            let report =
                burp::launch::up(&target, &project, mode, Duration::from_secs(180)).await?;
            print_status(&report.status);
            for warning in &report.warnings {
                eprintln!("warning: {warning}");
            }
            Ok(())
        }
        Command::Down { project, all } => {
            let target = target()?;
            let projects = if all {
                target.known_projects()
            } else {
                vec![target.project_or_default(project.as_deref())?]
            };
            for project in projects {
                let result = instance::stop(&target, &project).await?;
                if result["was_running"].as_bool() == Some(true) || !all {
                    println!(
                        "{project}: stopped{}",
                        result["method"].as_str().map_or_else(
                            || " (was not running)".to_owned(),
                            |m| format!(" (method: {m})")
                        )
                    );
                }
            }
            Ok(())
        }
        Command::Status { json } => {
            let target = target()?;
            let all = instance::status_all(&target).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&all)?);
            } else if all.is_empty() {
                println!(
                    "no projects yet; raijin up starts {}",
                    target.config.default_project
                );
            } else {
                println!(
                    "{:<16} {:<9} {:<9} {:>7}  {:<32} {:<16} LOG",
                    "PROJECT", "STATE", "MODE", "PID", "MCP", "PROXY"
                );
                for s in &all {
                    println!(
                        "{:<16} {:<9} {:<9} {:>7}  {:<32} {:<16} {}",
                        s.project,
                        json_str(&s.state),
                        s.mode.map(|m| m.to_string()).unwrap_or_default(),
                        s.pid.map(|p| p.to_string()).unwrap_or_default(),
                        s.mcp_url.clone().unwrap_or_default(),
                        s.proxy.clone().unwrap_or_default(),
                        s.log
                            .as_ref()
                            .map(|l| l.display().to_string())
                            .unwrap_or_default()
                    );
                }
            }
            Ok(())
        }
        Command::History(command) => history_command(command).await,
        Command::Mcp { surface, remote } => mcp::server::serve(surface, remote).await,
    }
}

fn json_str<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_value(value)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_default()
}

fn print_status(s: &instance::Status) {
    println!("project: {}", s.project);
    println!("state:   {}", json_str(&s.state));
    if let Some(mode) = s.mode {
        println!("mode:    {mode}");
    }
    if let Some(pid) = s.pid {
        println!("pid:     {pid}");
    }
    if let Some(url) = &s.mcp_url {
        println!("mcp:     {url}");
    }
    if let Some(proxy) = &s.proxy {
        println!("proxy:   {proxy}");
    }
    if let Some(log) = &s.log {
        println!("log:     {}", log.display());
    }
}

/// Runs a blocking history operation off the async runtime.
async fn blocking<T: Send + 'static>(f: impl FnOnce() -> Result<T> + Send + 'static) -> Result<T> {
    tokio::task::spawn_blocking(f)
        .await
        .context("history task panicked")?
}

async fn history_command(command: HistoryCommand) -> Result<()> {
    let target = target()?;
    let mut out = std::io::stdout().lock();
    match command {
        HistoryCommand::List { params, output } => {
            let result = blocking(move || history::list::run(&target, &params)).await?;
            let value = serde_json::to_value(&result)?;
            emit(&mut out, output.resolve(), &value, "rows", list_line)?;
            if output.resolve() == Format::Table {
                eprintln!(
                    "{} of {} rows",
                    value["rows"].as_array().map_or(0, Vec::len),
                    result.total
                );
            }
        }
        HistoryCommand::Show { params, output } => {
            let value = blocking(move || history::show::run(&target, &params)).await?;
            match output.resolve() {
                Format::Table => show_table(&mut out, &value)?,
                format => print_value(&mut out, format, &value)?,
            }
        }
        HistoryCommand::Search { params, output } => {
            let value = serde_json::to_value(
                blocking(move || history::search::run(&target, &params)).await?,
            )?;
            emit(&mut out, output.resolve(), &value, "hits", search_line)?;
        }
        HistoryCommand::Endpoints { params, output } => {
            let value = serde_json::to_value(
                blocking(move || history::endpoints::run(&target, &params)).await?,
            )?;
            emit(
                &mut out,
                output.resolve(),
                &value,
                "endpoints",
                endpoint_line,
            )?;
        }
        HistoryCommand::Diff { params, output } => {
            let value = blocking(move || history::diff::run(&target, &params)).await?;
            match output.resolve() {
                Format::Table => {
                    let diff = str_at(&value, "diff").replace("\r\n", "\n");
                    write!(out, "{}", util::visible(&diff))?;
                }
                format => print_value(&mut out, format, &value)?,
            }
        }
        HistoryCommand::Export { params, output } => {
            let value = blocking(move || history::export::run(&target, &params)).await?;
            match output.resolve() {
                Format::Table => {
                    writeln!(
                        out,
                        "exported to {}",
                        value["out_dir"].as_str().unwrap_or_default()
                    )?;
                    for p in value["projects"].as_array().into_iter().flatten() {
                        writeln!(
                            out,
                            "  {}: {} entries",
                            p["project"].as_str().unwrap_or_default(),
                            p["entries"].as_u64().unwrap_or_default()
                        )?;
                    }
                    print_warnings(&value);
                }
                format => print_value(&mut out, format, &value)?,
            }
        }
    }
    Ok(())
}

fn str_at<'v>(value: &'v Value, key: &str) -> &'v str {
    value[key].as_str().unwrap_or_default()
}

fn list_line(row: &Value) -> String {
    let time = row["time_epoch_ms"]
        .as_u64()
        .map(|ms| util::utc_stamp_at(ms / 1000))
        .unwrap_or_default();
    let status = row["status"]
        .as_u64()
        .map(|s| s.to_string())
        .unwrap_or_default();
    // Issue rows have severity and name where exchanges have method and URL.
    let method = row["method"].as_str().unwrap_or(str_at(row, "severity"));
    let url = row["url"].as_str().unwrap_or(str_at(row, "name"));
    format!(
        "{:<14} {time:<17} {method:<7} {status:>4}  {url}",
        str_at(row, "ref")
    )
}

fn search_line(hit: &Value) -> String {
    let snippet = str_at(hit, "snippet").replace(['\r', '\n'], " ");
    format!(
        "{:<14} {:<8} {:>7}  {snippet}",
        str_at(hit, "ref"),
        str_at(hit, "where"),
        hit["offset"].as_u64().unwrap_or_default()
    )
}

fn endpoint_line(e: &Value) -> String {
    let join = |k: &str| -> String {
        let items: Vec<String> = e[k]
            .as_array()
            .into_iter()
            .flatten()
            .map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_owned))
            .collect();
        items.join(",")
    };
    format!(
        "{:>5} {:<7} {:<28} {:<40} status={} query={} body={}",
        e["count"].as_u64().unwrap_or_default(),
        str_at(e, "method"),
        str_at(e, "host"),
        str_at(e, "path"),
        join("statuses"),
        join("query_params"),
        join("body_params")
    )
}

fn show_table(out: &mut impl Write, value: &Value) -> Result<()> {
    let line = format!(
        "{} {} {}",
        str_at(value, "ref"),
        str_at(value, "method"),
        str_at(value, "url")
    );
    writeln!(out, "{}", util::visible_line(&line))?;
    for key in ["request", "response"] {
        if let Some(text) = value[key].as_str() {
            // CRLF ends HTTP lines; a lone CR (which could overwrite a line) is still escaped.
            let text = text.replace("\r\n", "\n");
            writeln!(out, "\n--- {key} ---\n{}", util::visible(&text))?;
        }
    }
    if let Some(name) = value["name"].as_str() {
        let issue = format!(
            "{name} [{}]\n{}",
            str_at(value, "severity"),
            str_at(value, "detail")
        );
        writeln!(out, "{}", util::visible(&issue))?;
    }
    Ok(())
}

fn print_value(out: &mut impl Write, format: Format, value: &Value) -> Result<()> {
    match format {
        Format::Json | Format::Table => writeln!(out, "{}", serde_json::to_string_pretty(value)?)?,
        Format::Jsonl => writeln!(out, "{}", serde_json::to_string(value)?)?,
    }
    Ok(())
}

fn print_warnings(value: &Value) {
    for w in value["warnings"].as_array().into_iter().flatten() {
        eprintln!(
            "warning: {}: {}",
            w["project"].as_str().unwrap_or_default(),
            w["error"].as_str().unwrap_or_default()
        );
    }
}

/// Table: one formatted line per item of `value[key]`; jsonl: one item per line; json: the whole value.
fn emit(
    out: &mut impl Write,
    format: Format,
    value: &Value,
    key: &str,
    line: impl Fn(&Value) -> String,
) -> Result<()> {
    match format {
        Format::Json => writeln!(out, "{}", serde_json::to_string_pretty(value)?)?,
        Format::Jsonl => {
            for item in value[key].as_array().into_iter().flatten() {
                writeln!(out, "{}", serde_json::to_string(item)?)?;
            }
        }
        Format::Table => {
            for item in value[key].as_array().into_iter().flatten() {
                writeln!(out, "{}", util::visible_line(&line(item)))?;
            }
        }
    }
    if format != Format::Json {
        print_warnings(value);
    }
    Ok(())
}
