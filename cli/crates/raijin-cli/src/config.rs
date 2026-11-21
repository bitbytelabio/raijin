//! `raijin.toml`: one target (engagement) folder, found by walking up from the working directory.

use std::collections::BTreeSet;
use std::fmt;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const CONFIG_FILE: &str = "raijin.toml";
/// Per-target state the CLI owns (instances, overlays, logs, archive, spills); git-ignored.
pub const STATE_DIR: &str = ".raijin";

#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, schemars::JsonSchema,
)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    #[default]
    Headless,
    Ui,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Headless => "headless",
            Self::Ui => "ui",
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Theme {
    #[default]
    Dark,
    Light,
}

impl Theme {
    /// Burp's `user_options.display.user_interface.look_and_feel` value.
    pub const fn burp_name(self) -> &'static str {
        match self {
            Self::Dark => "Dark",
            Self::Light => "Light",
        }
    }
}

/// Burp's task engine after `raijin up` reopens a project file (Burp itself pauses it).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TaskEngine {
    #[default]
    Running,
    Paused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExtensionKind {
    Java,
    Python,
}

impl ExtensionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Java => "java",
            Self::Python => "python",
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Extension {
    pub path: PathBuf,
    #[serde(rename = "type")]
    pub kind: ExtensionKind,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct History {
    #[serde(default)]
    pub include: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mcp {
    #[serde(default = "default_inline_limit_kb")]
    pub inline_limit_kb: u64,
}

impl Default for Mcp {
    fn default() -> Self {
        Self {
            inline_limit_kb: default_inline_limit_kb(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Remote {
    pub url: String,
    pub token_env: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Burp {
    pub install_dir: Option<PathBuf>,
    pub java: Option<PathBuf>,
    pub jar: Option<PathBuf>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_project")]
    pub default_project: String,
    #[serde(default)]
    pub mode: Mode,
    #[serde(default)]
    pub theme: Theme,
    #[serde(default)]
    pub task_engine: TaskEngine,
    #[serde(default = "default_projects_dir")]
    pub projects_dir: PathBuf,
    pub jar: Option<PathBuf>,
    #[serde(default)]
    pub bapps: Vec<String>,
    #[serde(default)]
    pub extensions: Vec<Extension>,
    #[serde(default)]
    pub history: History,
    #[serde(default)]
    pub mcp: Mcp,
    pub remote: Option<Remote>,
    #[serde(default)]
    pub burp: Burp,
}

fn default_project() -> String {
    "main".to_owned()
}

fn default_projects_dir() -> PathBuf {
    PathBuf::from("burp")
}

const fn default_inline_limit_kb() -> u64 {
    24
}

impl Config {
    pub fn parse(text: &str) -> Result<Self> {
        let config: Self = toml::from_str(text)?;
        validate_project_name(&config.default_project).context("default_project")?;
        Ok(config)
    }
}

/// A target folder: the directory holding `raijin.toml`, and its parsed contents.
#[derive(Debug, Clone)]
pub struct Target {
    pub root: PathBuf,
    pub config: Config,
}

impl Target {
    /// Walks up from `cwd` to the first directory with a `raijin.toml`. That file decides which
    /// programs run and where tool calls go, so it must be ours: owned by the current user, and
    /// neither it nor its folder writable by others (like git's `safe.directory`).
    /// When there is none anywhere above `cwd`, scaffolds a default target (project "main") in
    /// `cwd`. Ownership errors still fail: a foreign config is never shadowed.
    pub fn discover_or_init(cwd: &Path) -> Result<Self> {
        if let Some(root) = find_root(cwd)? {
            return Self::load(&root);
        }
        let path = crate::init::scaffold(cwd, "main")?;
        // stderr only: stdout is the MCP stdio channel under `raijin mcp`.
        eprintln!(
            "raijin: created default {} (no {CONFIG_FILE} found)",
            path.display()
        );
        Self::load(cwd)
    }

    pub fn load(root: &Path) -> Result<Self> {
        let path = root.join(CONFIG_FILE);
        let text = std::fs::read_to_string(&path)
            .with_context(|| format!("reading {}", path.display()))?;
        let config = Config::parse(&text).with_context(|| format!("parsing {}", path.display()))?;
        Ok(Self {
            root: root.to_path_buf(),
            config,
        })
    }

    /// `path` relative to the target root unless absolute.
    pub fn resolve(&self, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            self.root.join(path)
        }
    }

    pub fn projects_dir(&self) -> PathBuf {
        self.resolve(&self.config.projects_dir)
    }

    pub fn project_file(&self, project: &str) -> PathBuf {
        self.projects_dir().join(format!("{project}.burp"))
    }

    pub fn state_dir(&self) -> PathBuf {
        self.root.join(STATE_DIR)
    }

    pub fn run_dir(&self, project: &str) -> PathBuf {
        self.state_dir().join("run").join(project)
    }

    pub fn instances_dir(&self) -> PathBuf {
        self.state_dir().join("instances")
    }

    pub fn instance_file(&self, project: &str) -> PathBuf {
        self.instances_dir().join(format!("{project}.json"))
    }

    pub fn archive_dir(&self, project: &str) -> PathBuf {
        self.state_dir().join("archive").join(project)
    }

    pub fn log_file(&self, project: &str) -> PathBuf {
        self.state_dir().join("logs").join(format!("{project}.log"))
    }

    pub fn browser_dir(&self, project: &str) -> PathBuf {
        self.state_dir().join("browser").join(project)
    }

    /// The project to act on: `requested`, else `default_project`.
    pub fn project_or_default(&self, requested: Option<&str>) -> Result<String> {
        let name = requested.unwrap_or(&self.config.default_project);
        validate_project_name(name)?;
        Ok(name.to_owned())
    }

    /// Project names: every `<projects_dir>/*.burp` stem plus every instance file, sorted.
    pub fn known_projects(&self) -> Vec<String> {
        let mut names = BTreeSet::new();
        for (dir, ext) in [
            (self.projects_dir(), "burp"),
            (self.instances_dir(), "json"),
        ] {
            let Ok(entries) = std::fs::read_dir(dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|e| e == ext)
                    && let Some(stem) = path.file_stem().and_then(|s| s.to_str())
                    && validate_project_name(stem).is_ok()
                {
                    names.insert(stem.to_owned());
                }
            }
        }
        names.into_iter().collect()
    }
}

/// The nearest directory at or above `cwd` holding a `raijin.toml`, after its ownership checks;
/// `None` when there is none.
fn find_root(cwd: &Path) -> Result<Option<PathBuf>> {
    let mut dir = Some(cwd);
    while let Some(current) = dir {
        let file = current.join(CONFIG_FILE);
        if file.is_file() {
            check_owned(&file)?;
            check_owned(current)?;
            return Ok(Some(current.to_path_buf()));
        }
        dir = current.parent();
    }
    Ok(None)
}

/// Refuses `path` unless the current user owns it and others cannot write it.
fn check_owned(path: &Path) -> Result<()> {
    let meta = std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    let me = nix::unistd::getuid().as_raw();
    if meta.uid() != me {
        bail!(
            "refusing {}: owned by uid {}, not you (uid {me}); a {CONFIG_FILE} decides what raijin runs",
            path.display(),
            meta.uid()
        );
    }
    // Group-writable is the norm under a 002 umask (user private groups); world-writable is not.
    if meta.mode() & 0o002 != 0 {
        bail!(
            "refusing {}: writable by others (mode {:o}); chmod o-w it",
            path.display(),
            meta.mode() & 0o7777
        );
    }
    Ok(())
}

/// Project names are file stems: `^[A-Za-z0-9_-]+$`.
pub fn validate_project_name(name: &str) -> Result<()> {
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        bail!("invalid project name {name:?}: use letters, digits, '_' and '-'");
    }
    Ok(())
}

/// `~`, from `$HOME`.
pub fn home_dir() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .context("HOME is not set")
}

/// `~/.raijin`: state shared by every target (jars, the Burp profile, spills outside a target).
pub fn user_state_dir() -> Result<PathBuf> {
    Ok(home_dir()?.join(".raijin"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_keys_are_rejected() {
        let err = Config::parse("default_projet = \"x\"\n").unwrap_err();
        assert!(format!("{err:#}").contains("unknown field"), "{err:#}");
        let nested = Config::parse("[mcp]\ninline_limit = 3\n").unwrap_err();
        assert!(
            format!("{nested:#}").contains("unknown field"),
            "{nested:#}"
        );
    }

    #[test]
    fn defaults_apply() {
        let config = Config::parse("").unwrap();
        assert_eq!(config.default_project, "main");
        assert_eq!(config.mode, Mode::Headless);
        assert_eq!(config.theme, Theme::Dark);
        assert_eq!(config.task_engine, TaskEngine::Running);
        assert_eq!(config.projects_dir, PathBuf::from("burp"));
        assert_eq!(config.mcp.inline_limit_kb, 24);
        assert!(config.remote.is_none());
    }

    #[test]
    fn theme_is_dark_or_light() {
        let light = Config::parse("theme = \"light\"\n").expect("light theme");
        assert_eq!(light.theme.burp_name(), "Light");
        assert!(Config::parse("theme = \"blue\"\n").is_err());
    }

    #[test]
    fn a_config_others_can_write_is_refused() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().expect("temp dir");
        let file = dir.path().join(CONFIG_FILE);
        std::fs::write(&file, "").expect("config");
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755))
            .expect("chmod dir");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let nested = dir.path().join("sub");
        std::fs::create_dir(&nested).expect("sub");
        assert!(Target::discover_or_init(&nested).is_ok());
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o666)).expect("chmod");
        let err = Target::discover_or_init(&nested).expect_err("world-writable config");
        assert!(
            !nested.join(CONFIG_FILE).exists(),
            "a refused config must not be shadowed by a scaffolded one"
        );
        assert!(format!("{err:#}").contains("writable by others"), "{err:#}");
    }

    #[test]
    fn a_missing_config_is_scaffolded_once() {
        let dir = tempfile::tempdir().expect("temp dir");
        let root = dir.path().canonicalize().expect("canonical");
        let target = Target::discover_or_init(&root).expect("auto init");
        assert_eq!(target.root, root);
        assert!(root.join(CONFIG_FILE).is_file());
        assert!(root.join(STATE_DIR).is_dir());
        assert!(!root.join(".mcp.json").exists());
        assert_eq!(target.config.default_project, "main");
        let again = Target::discover_or_init(&root).expect("reload");
        assert_eq!(again.root, root);
    }

    #[test]
    fn project_names_are_file_stems() {
        assert!(validate_project_name("day-1_a").is_ok());
        for bad in ["", "a/b", "a:b", "..", "a b"] {
            assert!(validate_project_name(bad).is_err(), "{bad}");
        }
    }
}
