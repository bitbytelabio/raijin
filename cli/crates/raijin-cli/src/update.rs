//! `raijin update`: replaces this binary and the `raijin.jar` beside it (where install.sh puts
//! both) with a GitHub release, and the "new version available" note `raijin up` prints.

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use semver::Version;
use serde::{Deserialize, Serialize};

use crate::burp::instance::{self, State};
use crate::config::{Mode, Target, user_state_dir};
use crate::jar::{self, VERSION};
use crate::util::{now_ms, private_dir, write_private};

const REPO: &str = "https://github.com/bitbytelabio/raijin";
const CHECK_TTL_MS: u64 = 24 * 3600 * 1000;

#[derive(clap::Args)]
pub struct Options {
    /// Release to install, e.g. 2.3.0 (default: the latest; an older one downgrades).
    #[arg(value_name = "VERSION")]
    release: Option<String>,
    /// Only report whether a newer release exists.
    #[arg(long, conflicts_with_all = ["release", "force"])]
    check: bool,
    /// Reinstall even when up to date, and restart this target's running Burp projects.
    #[arg(long)]
    force: bool,
}

pub async fn run(opts: Options) -> Result<()> {
    let Options {
        release,
        check,
        force,
    } = opts;
    let client = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(15))
        .build()?;
    let current = Version::parse(VERSION)?;
    let explicit = release.is_some();
    let wanted = match release {
        Some(s) => Version::parse(s.trim_start_matches('v'))
            .with_context(|| format!("invalid version {s}"))?,
        None => Version::parse(&latest(&client).await?)?,
    };

    if check {
        if wanted > current {
            println!("raijin {wanted} is available (this is {current}); run raijin update");
        } else {
            println!("raijin {current} is up to date");
        }
        return Ok(());
    }
    match plan(&current, &wanted, explicit, force) {
        Plan::UpToDate => {
            println!("raijin {current} is up to date (raijin update --force reinstalls)");
            return Ok(());
        }
        Plan::AheadOfLatest => {
            println!("raijin {current} is newer than the latest release {wanted}");
            return Ok(());
        }
        Plan::Install => {}
    }

    let exe = install(&client, &current, &wanted).await?;
    if std::env::var_os("RAIJIN_JAR").is_some_and(|v| !v.is_empty()) {
        eprintln!("warning: RAIJIN_JAR is set; raijin up loads that jar, not the updated one");
    }
    restart_running(&exe, &current, force).await
}

/// Removes the staging directory on every exit path.
struct Staging(PathBuf);

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// Downloads and checks release `wanted`, then renames the jar and the binary over the installed
/// ones. Rename, never an in-place write: a running Burp or `raijin mcp` keeps its open file.
/// Returns the installed binary's path.
async fn install(client: &reqwest::Client, current: &Version, wanted: &Version) -> Result<PathBuf> {
    let (os, arch) = (std::env::consts::OS, std::env::consts::ARCH);
    let Some(target) = release_target(os, arch) else {
        bail!("no release build for {os} {arch}");
    };
    let exe = fs::canonicalize(std::env::current_exe()?)?;
    let dir = exe
        .parent()
        .context("the raijin binary has no parent directory")?;
    let staging = Staging(dir.join(format!(".raijin-update-{}", std::process::id())));
    private_dir(&staging.0).with_context(|| {
        format!(
            "cannot write to {}; rerun with write access or reinstall with install.sh",
            dir.display()
        )
    })?;

    let base = format!("{REPO}/releases/download/v{wanted}");
    let asset = format!("raijin-cli-{wanted}-{target}.tar.gz");
    let jar_name = format!("raijin-{wanted}.jar");
    eprintln!("downloading raijin {wanted} ({target}) and {jar_name}");
    for name in [&asset, &jar_name] {
        let bytes = jar::fetch_checked(client, &format!("{base}/{name}"), None).await?;
        fs::write(staging.0.join(name), bytes)?;
    }

    // --no-same-owner: under sudo, tar would keep the CI runner's uid from the archive.
    let status = tokio::process::Command::new("tar")
        .arg("--no-same-owner")
        .arg("-xzf")
        .arg(staging.0.join(&asset))
        .arg("-C")
        .arg(&staging.0)
        .arg("raijin")
        .status()
        .await
        .context("running tar")?;
    if !status.success() {
        bail!("could not extract {asset}");
    }

    let new_bin = staging.0.join("raijin");
    fs::set_permissions(&new_bin, fs::Permissions::from_mode(0o755))?;
    let output = tokio::process::Command::new(&new_bin)
        .arg("--version")
        .output()
        .await
        .context("running the downloaded binary")?;
    let reported = String::from_utf8_lossy(&output.stdout);
    let reported = reported.trim();
    let expected = format!("raijin {wanted}");
    if reported != expected {
        bail!("downloaded binary reports {reported:?}, expected {expected}");
    }

    let staged_jar = staging.0.join(&jar_name);
    let jar_path = dir.join("raijin.jar");
    fs::set_permissions(&staged_jar, fs::Permissions::from_mode(0o644))?;
    fs::rename(&staged_jar, &jar_path)
        .with_context(|| format!("replacing {}", jar_path.display()))?;
    fs::rename(&new_bin, &exe).with_context(|| format!("replacing {}", exe.display()))?;
    eprintln!("updated raijin {current} -> {wanted}: {}", exe.display());
    eprintln!("installed the Burp extension: {}", jar_path.display());
    Ok(exe)
}

/// Running Burp projects of the current target still load the old jar: report them, or with
/// `force` restart them through the new binary `exe` (this process still carries the old version
/// and jar pin, so it cannot start them itself).
async fn restart_running(exe: &Path, current: &Version, force: bool) -> Result<()> {
    let target = match Target::discover(&std::env::current_dir()?) {
        Err(e) => {
            eprintln!("warning: {e:#}");
            return Ok(());
        }
        Ok(Some(target)) if target.config.remote.is_none() => target,
        Ok(_) => {
            eprintln!(
                "note: Burp sessions started before this update keep Raijin {current} until restarted (raijin down && raijin up)"
            );
            return Ok(());
        }
    };
    if target.config.jar.is_some() {
        eprintln!("warning: jar in raijin.toml overrides the updated raijin.jar");
    }
    let running: Vec<_> = instance::status_all(&target)
        .await?
        .into_iter()
        .filter(|s| s.state != State::Stopped)
        .collect();
    if running.is_empty() {
        return Ok(());
    }
    if !force {
        let names = running
            .iter()
            .map(|s| s.project.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        eprintln!(
            "note: still on Raijin {current}: {names}; restart with raijin down <project> && raijin up <project>, or raijin update --force"
        );
        return Ok(());
    }
    for s in &running {
        let mode = match s.mode.unwrap_or(target.config.mode) {
            Mode::Ui => "--ui",
            Mode::Headless => "--headless",
        };
        for args in [vec!["down", &s.project], vec!["up", &s.project, mode]] {
            let status = tokio::process::Command::new(exe)
                .args(&args)
                .current_dir(&target.root)
                .status()
                .await
                .with_context(|| format!("running {}", exe.display()))?;
            if !status.success() {
                bail!(
                    "restarting {} failed (raijin {} exited with {status})",
                    s.project,
                    args[0]
                );
            }
        }
    }
    Ok(())
}

/// The latest release's version, from the redirect of `/releases/latest` (no API, no token).
async fn latest(client: &reqwest::Client) -> Result<String> {
    let response = client
        .get(format!("{REPO}/releases/latest"))
        .send()
        .await
        .context("resolving the latest release")?;
    tag_from_url(response.url().as_str()).context("could not resolve the latest release")
}

/// `2.3.1` from `.../releases/tag/v2.3.1`; `None` unless it is a semver version.
fn tag_from_url(url: &str) -> Option<String> {
    let (_, tag) = url.rsplit_once("/releases/tag/")?;
    let tag = tag.trim_start_matches('v');
    Version::parse(tag).ok()?;
    Some(tag.to_owned())
}

/// The release archive's target triple for this OS and CPU.
fn release_target(os: &str, arch: &str) -> Option<&'static str> {
    match (os, arch) {
        ("macos", "aarch64") => Some("aarch64-apple-darwin"),
        ("linux", "x86_64") => Some("x86_64-unknown-linux-gnu"),
        ("linux", "aarch64") => Some("aarch64-unknown-linux-gnu"),
        _ => None,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Plan {
    UpToDate,
    AheadOfLatest,
    Install,
}

/// `explicit`: the user named `wanted`, so an older one is a downgrade, not "ahead of latest".
/// `force` reinstalls the same version but never downgrades to an unnamed latest.
fn plan(current: &Version, wanted: &Version, explicit: bool, force: bool) -> Plan {
    if !explicit && wanted < current {
        Plan::AheadOfLatest
    } else if wanted == current && !force {
        Plan::UpToDate
    } else {
        Plan::Install
    }
}

/// `~/.raijin/update-check.json`: the last latest-release lookup, failed ones included.
#[derive(Serialize, Deserialize)]
struct UpdateCheck {
    checked_at_ms: u64,
    latest: Option<String>,
}

/// "raijin X is available" when the latest release is newer than this binary. Looks it up at most
/// once a day (3 s timeout); `RAIJIN_NO_UPDATE_CHECK` turns it off. Any failure is silent.
pub async fn hint() -> Option<String> {
    if std::env::var_os("RAIJIN_NO_UPDATE_CHECK").is_some_and(|v| !v.is_empty()) {
        return None;
    }
    let path = user_state_dir().ok()?.join("update-check.json");
    let cached = fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<UpdateCheck>(&bytes).ok())
        .filter(|c| now_ms().saturating_sub(c.checked_at_ms) < CHECK_TTL_MS);
    let found = if let Some(check) = cached {
        check.latest
    } else {
        let check = UpdateCheck {
            checked_at_ms: now_ms(),
            latest: lookup_latest().await,
        };
        if let Ok(json) = serde_json::to_vec(&check) {
            let _ = write_private(&path, &json);
        }
        check.latest
    }?;
    (Version::parse(&found).ok()? > Version::parse(VERSION).ok()?)
        .then(|| format!("raijin {found} is available (this is {VERSION}); run raijin update"))
}

async fn lookup_latest() -> Option<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .ok()?;
    latest(&client).await.ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Version {
        Version::parse(s).unwrap()
    }

    #[test]
    fn tag_is_read_from_the_release_redirect() {
        assert_eq!(
            tag_from_url("https://github.com/bitbytelabio/raijin/releases/tag/v2.3.1").as_deref(),
            Some("2.3.1")
        );
        assert_eq!(
            tag_from_url("https://github.com/bitbytelabio/raijin/releases"),
            None
        );
        assert_eq!(
            tag_from_url("https://github.com/bitbytelabio/raijin/releases/tag/vjunk"),
            None
        );
    }

    #[test]
    fn release_targets_cover_the_published_archives() {
        assert_eq!(
            release_target("macos", "aarch64"),
            Some("aarch64-apple-darwin")
        );
        assert_eq!(
            release_target("linux", "x86_64"),
            Some("x86_64-unknown-linux-gnu")
        );
        assert_eq!(release_target("windows", "x86_64"), None);
    }

    #[test]
    fn plan_installs_only_what_was_asked() {
        assert_eq!(plan(&v("2.3.1"), &v("2.3.1"), false, false), Plan::UpToDate);
        assert_eq!(plan(&v("2.3.1"), &v("2.3.1"), false, true), Plan::Install);
        assert_eq!(
            plan(&v("2.3.1"), &v("2.3.0"), false, false),
            Plan::AheadOfLatest
        );
        assert_eq!(
            plan(&v("2.3.1"), &v("2.3.0"), false, true),
            Plan::AheadOfLatest
        );
        assert_eq!(plan(&v("2.3.1"), &v("2.3.0"), true, false), Plan::Install);
        assert_eq!(plan(&v("2.3.0"), &v("2.3.1"), false, false), Plan::Install);
    }
}
