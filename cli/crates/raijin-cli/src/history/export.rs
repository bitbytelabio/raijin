//! `history export` / `history_export`: amber's JSON export per project, plus the archive files.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde_json::{Value, json};

use super::source::{self, EXCHANGES_FILE, ISSUES_FILE};
use super::{Filters, Selection};
use crate::config::Target;
use crate::util::utc_stamp;

#[derive(Debug, Clone, Default, clap::Args, serde::Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct ExportParams {
    /// Output folder (default `.raijin/exports/<UTC stamp>`); one sub-folder per project.
    #[arg(short = 'o', long)]
    pub out_dir: Option<PathBuf>,
    /// Skip the raw message blobs.
    #[arg(long)]
    pub no_blobs: bool,
    #[command(flatten)]
    #[serde(flatten)]
    pub selection: Selection,
    #[command(flatten)]
    #[serde(flatten)]
    pub filters: Filters,
}

pub fn run(target: &Target, params: &ExportParams) -> Result<Value> {
    let out_dir = params.out_dir.as_deref().map_or_else(
        || target.state_dir().join("exports").join(utc_stamp()),
        |p| target.resolve(p),
    );
    let filter = params.filters.amber()?;
    let sources = source::discover(target, &params.selection)?;
    let (projects, warnings) = source::par_map(&sources, |s, _notes| {
        let dest = out_dir.join(&s.project);
        let mut entry = json!({"project": s.project, "dir": dest.display().to_string()});
        if let Some(burp) = &s.burp {
            let options = amber::ExportOptions {
                write_blobs: !params.no_blobs,
                force: false,
                filter: filter.clone(),
            };
            let summary = amber::export(burp, &dest, &options)
                .with_context(|| format!("exporting {}", burp.display()))?;
            entry["entries"] = json!(summary.entry_count);
            entry["complete"] = json!(summary.complete);
            entry["blobs"] = json!(summary.blob_count);
        }
        if let Some(archive) = &s.archive {
            let mut copied = Vec::new();
            for name in [EXCHANGES_FILE, ISSUES_FILE] {
                let from = archive.join(name);
                if from.is_file() {
                    let to_dir = dest.join("archive");
                    fs::create_dir_all(&to_dir)?;
                    fs::copy(&from, to_dir.join(name))?;
                    copied.push(name);
                }
            }
            entry["archive_files"] = json!(copied);
        }
        Ok(entry)
    });
    Ok(
        json!({"out_dir": out_dir.display().to_string(), "projects": projects, "warnings": warnings}),
    )
}
