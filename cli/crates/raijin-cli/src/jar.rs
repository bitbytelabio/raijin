//! The Raijin jar: which one to load into Burp, and the catalog and skills packaged in it.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use sha2::{Digest, Sha256};

use crate::catalog::{Catalog, Skill};
use crate::config::{Target, user_state_dir};
use crate::util::{hex, private_dir};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
const RELEASE_BASE: &str = "https://github.com/bitbytelabio/raijin/releases/download";
/// SHA-256 of the release jar, baked in by the release build from the jar it just published. A
/// release binary checks its download against this, not against a `.sha256` fetched from the same
/// place as the jar (which proves integrity, not origin). Dev builds fall back to that file.
const PINNED_SHA256: Option<&str> = option_env!("RAIJIN_JAR_SHA256");

/// `RAIJIN_JAR`, else `jar` in raijin.toml, else the release matching this CLI under
/// `~/.raijin/jars/` (downloaded and checksum-verified on first use).
pub async fn resolve(target: Option<&Target>) -> Result<PathBuf> {
    if let Some(path) = std::env::var_os("RAIJIN_JAR").filter(|v| !v.is_empty()) {
        let path = PathBuf::from(path);
        if !path.is_file() {
            bail!("RAIJIN_JAR={} does not exist", path.display());
        }
        return Ok(fs::canonicalize(&path)?);
    }
    if let Some(target) = target
        && let Some(jar) = &target.config.jar
    {
        let path = target.resolve(jar);
        if !path.is_file() {
            bail!("jar {} (raijin.toml) does not exist", path.display());
        }
        return Ok(fs::canonicalize(&path)?);
    }
    let path = user_state_dir()?
        .join("jars")
        .join(format!("raijin-{VERSION}.jar"));
    if !path.is_file() {
        download(&path).await?;
    }
    Ok(path)
}

async fn download(dest: &Path) -> Result<()> {
    let name = format!("raijin-{VERSION}.jar");
    let url = format!("{RELEASE_BASE}/v{VERSION}/{name}");
    eprintln!("downloading {url}");
    let client = reqwest::Client::builder().build()?;
    let expected = match PINNED_SHA256 {
        Some(pinned) => pinned.to_owned(),
        None => {
            client
                .get(format!("{url}.sha256"))
                .send()
                .await?
                .error_for_status()
                .with_context(|| format!("fetching {url}.sha256"))?
                .text()
                .await?
        }
    };
    let expected = expected
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_ascii_lowercase();
    let bytes = client
        .get(&url)
        .send()
        .await?
        .error_for_status()
        .with_context(|| format!("fetching {url}"))?
        .bytes()
        .await?;

    let dir = dest.parent().context("jar path has no parent")?;
    private_dir(dir)?;
    let tmp = dir.join(format!(".{name}.part-{}", std::process::id()));
    fs::write(&tmp, &bytes)?;
    let actual = hex(&Sha256::digest(&bytes));
    if actual != expected {
        let _ = fs::remove_file(&tmp);
        bail!("checksum mismatch for {url}: expected {expected}, got {actual}");
    }
    fs::rename(&tmp, dest)?;
    Ok(())
}

/// What the CLI reads out of the jar.
#[derive(Debug, Clone)]
pub struct Assets {
    pub catalog: Catalog,
    pub skills: Vec<Skill>,
}

pub fn read_assets(jar: &Path) -> Result<Assets> {
    let file = fs::File::open(jar).with_context(|| format!("opening {}", jar.display()))?;
    let mut archive =
        zip::ZipArchive::new(file).with_context(|| format!("reading {}", jar.display()))?;
    let catalog = match archive.by_name("catalog/tools.json") {
        Ok(mut entry) => {
            let mut text = String::new();
            entry.read_to_string(&mut text)?;
            Catalog::parse(&text)
                .with_context(|| format!("{}: catalog/tools.json", jar.display()))?
        }
        Err(zip::result::ZipError::FileNotFound) => bail!(
            "{} has no catalog/tools.json (built before raijin-cli support); set RAIJIN_JAR to a newer build",
            jar.display()
        ),
        Err(e) => return Err(e.into()),
    };
    let names: Vec<String> = archive
        .file_names()
        .filter_map(Result::ok)
        .filter(|n| {
            n.starts_with("skills/") && n.ends_with(".md") && !n["skills/".len()..].contains('/')
        })
        .map(std::borrow::Cow::into_owned)
        .collect();
    let mut skills = Vec::with_capacity(names.len());
    for name in names {
        let mut text = String::new();
        archive.by_name(&name)?.read_to_string(&mut text)?;
        let stem = name.trim_start_matches("skills/").trim_end_matches(".md");
        skills.push(Skill::parse(&text, stem, "raijin"));
    }
    skills.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(Assets { catalog, skills })
}
