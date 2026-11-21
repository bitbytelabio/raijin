//! `raijin up`: ports, overlays, spawn, readiness.

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom};
use std::net::TcpListener;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use nix::fcntl::{Flock, FlockArg};
use nix::sys::signal::Signal;
use serde_json::{Map, Value, json};

use super::install::{self, Launcher};
use super::instance::{self, Instance, Ports, State, Status};
use super::{profile, vmoptions};
use crate::config::{Mode, Target, home_dir, user_state_dir};
use crate::jar;
use crate::util::{hex, now_ms, private_dir};

const LICENCE_PROMPTS: [&str; 2] = [
    "Please paste your license key",
    "Do you accept the license agreement",
];
const PROXY_PORTS: std::ops::RangeInclusive<u16> = 8080..=8180;
const LOG_TAIL_LINES: usize = 40;

/// Result of `raijin up` / `burp_up`.
#[derive(Debug, serde::Serialize)]
pub struct UpReport {
    #[serde(flatten)]
    pub status: Status,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

pub async fn up(target: &Target, project: &str, mode: Mode, wait: Duration) -> Result<UpReport> {
    if let Some(remote) = &target.config.remote {
        bail!("target uses remote {}; Burp is not CLI-managed", remote.url);
    }
    // Held until this launch is ready or has failed: a free port is only reserved once Burp binds it.
    let _launch_lock = launch_lock().await?;
    let client = instance::http();
    let current = instance::status(target, project, &client).await?;
    if current.state != State::Stopped {
        let running_mode = current.mode.unwrap_or_default();
        if running_mode != mode {
            bail!("{project} is running in {running_mode}; raijin down {project} first");
        }
        return Ok(UpReport {
            status: current,
            warnings: Vec::new(),
        });
    }
    let previous = Instance::load(target, project)?;

    let jar = jar::resolve(Some(target)).await?;
    let launcher = install::discover(&target.config.burp, &target.root)?;
    let ports = pick_ports(previous.as_ref().map(|i| i.ports))?;

    let run_dir = target.run_dir(project);
    private_dir(&run_dir)?;
    let user_overlay = run_dir.join("user-options.json");
    let project_overlay = run_dir.join("project-options.json");
    fs::write(
        &user_overlay,
        serde_json::to_vec_pretty(&user_options(target, project, mode, &jar)?)?,
    )?;
    fs::write(
        &project_overlay,
        serde_json::to_vec_pretty(&project_options(ports.proxy))?,
    )?;
    let profile_dir = profile::ensure_seeded()?;

    let project_file = target.project_file(project);
    fs::create_dir_all(target.projects_dir())?;
    let archive = target.archive_dir(project);
    private_dir(&archive)?;
    let log = target.log_file(project);
    let token = control_token()?;

    let jvm = jvm_flags(mode, ports, &token, &archive);
    let app_args = [
        format!("--data-dir={}", profile_dir.display()),
        format!("--project-file={}", project_file.display()),
        format!("--user-config-file={}", user_overlay.display()),
        format!("--config-file={}", project_overlay.display()),
        "--disable-auto-update".to_owned(),
    ];
    let mut command = burp_command(&launcher, mode, project, &jvm)?;
    command.args(&app_args);
    let log_file = open_log(&log)?;
    command
        .current_dir(&target.root)
        .stdin(Stdio::null())
        .stdout(log_file.try_clone()?)
        .stderr(log_file)
        .process_group(0);
    let child = command
        .spawn()
        .with_context(|| format!("starting Burp ({launcher:?})"))?;
    let pid = child.id();
    instance::adopt(child);

    let mut record = Instance {
        project: project.to_owned(),
        project_file,
        mode,
        pid: Some(pid),
        started_at_ms: Some(now_ms()),
        control_token: Some(token),
        jar,
        jar_version: None,
        ports,
        log: log.clone(),
    };
    record.save(target)?;

    let mut warnings = Vec::new();
    let ready = wait_ready(&client, &record, wait).await?;
    if let Some(info) = ready {
        if let Some(version) = info["version"].as_str() {
            record.jar_version = Some(version.to_owned());
            record.save(target)?;
            if version != jar::VERSION {
                warnings.push(format!(
                    "Raijin in Burp is {version}, this CLI is {}",
                    jar::VERSION
                ));
            }
        }
    } else {
        warnings.push(format!(
            "Burp is still starting after {} s; check again with raijin status (log: {})",
            wait.as_secs(),
            log.display()
        ));
    }
    let status = instance::status(target, project, &client).await?;
    Ok(UpReport { status, warnings })
}

/// One launch at a time for this user (`~/.raijin/launch.lock`, across targets and processes), so
/// two concurrent launches cannot pick the same free ports or start the same project twice.
async fn launch_lock() -> Result<Flock<fs::File>> {
    let dir = user_state_dir()?;
    private_dir(&dir)?;
    let path = dir.join("launch.lock");
    tokio::task::spawn_blocking(move || {
        let file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("opening {}", path.display()))?;
        Flock::lock(file, FlockArg::LockExclusive)
            .map_err(|(_, e)| anyhow::anyhow!("locking {}: {e}", path.display()))
    })
    .await
    .context("launch lock task panicked")?
}

/// The `-D` flags Raijin reads (`RaijinExtension`, `ServerSettings`, `RemoteAccess`,
/// `ControlEndpoint`, `ExchangeArchive`), plus headless mode.
fn jvm_flags(mode: Mode, ports: Ports, token: &str, archive: &Path) -> Vec<String> {
    let mut jvm = Vec::new();
    if mode == Mode::Headless {
        jvm.push("-Djava.awt.headless=true".to_owned());
    }
    jvm.extend([
        format!("-Draijin.ssePort={}", ports.mcp),
        format!("-Draijin.httpPort={}", ports.mcp_secondary),
        format!("-Draijin.dashboardPort={}", ports.dashboard),
        "-Draijin.bindHost=127.0.0.1".to_owned(),
        "-Draijin.allowRemoteBind=false".to_owned(),
        "-Draijin.requireAuth=false".to_owned(),
        format!("-Draijin.controlToken={token}"),
        format!("-Draijin.archiveDir={}", archive.display()),
    ]);
    jvm
}

/// The process to spawn, without Burp's own arguments.
fn burp_command(launcher: &Launcher, mode: Mode, project: &str, jvm: &[String]) -> Result<Command> {
    Ok(match launcher {
        Launcher::MacStub { stub } => {
            let mut c = Command::new(stub);
            c.env("JAVA_TOOL_OPTIONS", java_tool_options(jvm)?);
            c
        }
        Launcher::Java {
            java,
            jar,
            vmoption_roots,
        } => {
            let home_vm = home_dir()?.join(".BurpSuite/user.vmoptions");
            let mut c = Command::new(java);
            c.args(vmoptions::collect(vmoption_roots, Some(&home_vm)));
            if cfg!(target_os = "macos") && mode == Mode::Ui {
                c.arg(format!("-Xdock:name=Burp ({project})"));
            }
            c.args(jvm).arg("-jar").arg(jar);
            c
        }
    })
}

/// Polls `/api/info` once a second until it reports this instance's MCP port. Fails when the
/// process dies or Burp asks for a licence; returns `None` on timeout.
async fn wait_ready(
    client: &reqwest::Client,
    record: &Instance,
    wait: Duration,
) -> Result<Option<Value>> {
    let pid = record.pid.context("instance has no pid")?;
    let deadline = tokio::time::Instant::now() + wait;
    let mut log_offset = 0u64;
    loop {
        if let Some(info) = instance::api_info(client, record.ports.dashboard).await
            && info["ports"]["primary_mcp"].as_u64() == Some(u64::from(record.ports.mcp))
        {
            return Ok(Some(info));
        }
        let fresh = read_from(&record.log, &mut log_offset);
        if LICENCE_PROMPTS.iter().any(|p| fresh.contains(p)) {
            instance::signal_group(pid, Signal::SIGKILL);
            bail!(
                "Burp is not activated for this launch; run raijin up {} --ui once and finish activation in the Burp window",
                record.project
            );
        }
        if !instance::pid_alive(pid) {
            bail!(
                "Burp exited during startup; last log lines ({}):\n{}",
                record.log.display(),
                log_tail(&record.log)
            );
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(None);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

fn read_from(path: &Path, offset: &mut u64) -> String {
    let Ok(mut file) = fs::File::open(path) else {
        return String::new();
    };
    if file.seek(SeekFrom::Start(*offset)).is_err() {
        return String::new();
    }
    let mut bytes = Vec::new();
    let _ = file.read_to_end(&mut bytes);
    *offset += bytes.len() as u64;
    String::from_utf8_lossy(&bytes).into_owned()
}

fn log_tail(path: &Path) -> String {
    let text = fs::read(path)
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(LOG_TAIL_LINES)..].join("\n")
}

/// The log, owner-only (the JVM echoes `JAVA_TOOL_OPTIONS`, control token included); the previous one moves to `.log.1`.
fn open_log(path: &Path) -> Result<fs::File> {
    if let Some(parent) = path.parent() {
        private_dir(parent)?;
    }
    if path.exists() {
        let mut old = path.as_os_str().to_owned();
        old.push(".1");
        fs::rename(path, PathBuf::from(old))?;
    }
    OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("opening {}", path.display()))
}

/// `JAVA_TOOL_OPTIONS` value. `HotSpot` splits it on whitespace and treats both ' and " as quotes,
/// with no escape character: an option holding whitespace or a quote is wrapped in the quote
/// character it does not contain, and one holding both is refused.
fn java_tool_options(options: &[String]) -> Result<String> {
    let mut quoted = Vec::with_capacity(options.len());
    for o in options {
        let needs_quotes = o.contains(|c: char| c.is_whitespace() || c == '"' || c == '\'');
        quoted.push(if !needs_quotes {
            o.clone()
        } else if !o.contains('"') {
            format!("\"{o}\"")
        } else if !o.contains('\'') {
            format!("'{o}'")
        } else {
            bail!(
                "cannot pass {o:?} to the JVM: it contains both ' and \"; rename the target folder"
            );
        });
    }
    Ok(quoted.join(" "))
}

fn control_token() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|e| anyhow::anyhow!("random token: {e}"))?;
    Ok(hex(&bytes))
}

fn bindable(port: u16) -> Option<TcpListener> {
    TcpListener::bind(("127.0.0.1", port)).ok()
}

/// The previous ports when they all still bind; otherwise OS-assigned MCP and dashboard ports and
/// the first free proxy port in 8080..=8180 (else OS-assigned). Listeners are held until all four
/// are chosen so no two coincide.
fn pick_ports(previous: Option<Ports>) -> Result<Ports> {
    if let Some(p) = previous {
        let held: Vec<_> = [p.mcp, p.mcp_secondary, p.dashboard, p.proxy]
            .into_iter()
            .map(bindable)
            .collect();
        if held.iter().all(Option::is_some) {
            return Ok(p);
        }
    }
    let ephemeral = || -> Result<(TcpListener, u16)> {
        let l = TcpListener::bind(("127.0.0.1", 0))?;
        let port = l.local_addr()?.port();
        Ok((l, port))
    };
    let (_a, mcp) = ephemeral()?;
    let (_b, mcp_secondary) = ephemeral()?;
    let (_c, dashboard) = ephemeral()?;
    let (_d, proxy) = match PROXY_PORTS
        .clone()
        .find_map(|p| bindable(p).map(|l| (l, p)))
    {
        Some(found) => found,
        None => ephemeral()?,
    };
    Ok(Ports {
        mcp,
        mcp_secondary,
        dashboard,
        proxy,
    })
}

fn extension_entry(name: &str, file: &Path, kind: &str, stream: &str) -> Value {
    // No bapp_uuid / bapp_serial_version: Burp treats an entry with them as a BApp and refuses a plain jar.
    json!({
        "auto_reload": false,
        "errors": stream,
        "extension_file": file.display().to_string(),
        "extension_type": kind,
        "loaded": true,
        "name": name,
        "output": stream,
        "use_ai": false,
    })
}

fn user_options(target: &Target, project: &str, mode: Mode, jar: &Path) -> Result<Value> {
    let stream = if mode == Mode::Headless {
        "console"
    } else {
        "ui"
    };
    let mut extensions = vec![extension_entry("Raijin", jar, "java", stream)];
    if !target.config.bapps.is_empty() {
        extensions.extend(bapp_entries(&target.config.bapps, stream)?);
    }
    for ext in &target.config.extensions {
        let path = target.resolve(&ext.path);
        if !path.is_file() {
            bail!("extension {} does not exist", path.display());
        }
        let name = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("extension")
            .to_owned();
        extensions.push(extension_entry(&name, &path, ext.kind.as_str(), stream));
    }
    Ok(json!({"user_options": {
        "display": {"user_interface": {"look_and_feel": target.config.theme.burp_name()}},
        "extender": {"extensions": extensions},
        "misc": {
            "api": {"enabled": false},
            "embedded_browser": {"browser_data_directory": target.browser_dir(project).display().to_string()},
        },
    }}))
}

/// `BApps` from the global user config by case-insensitive name, with absolute paths.
fn bapp_entries(names: &[String], stream: &str) -> Result<Vec<Value>> {
    let burp_home = home_dir()?.join(".BurpSuite");
    let global = profile::global_config()?;
    let config: Value = fs::read_to_string(&global)
        .ok()
        .and_then(|t| serde_json::from_str(&t).ok())
        .unwrap_or(Value::Null);
    let installed = config["user_options"]["extender"]["extensions"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    names
        .iter()
        .map(|wanted| {
            let entry = installed
                .iter()
                .find(|e| {
                    e["name"]
                        .as_str()
                        .is_some_and(|n| n.eq_ignore_ascii_case(wanted))
                })
                .with_context(|| format!("bapp \"{wanted}\" is not installed in ~/.BurpSuite"))?;
            let mut entry: Map<String, Value> = entry.as_object().cloned().unwrap_or_default();
            let file = entry
                .get("extension_file")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let path = Path::new(file);
            let abs = if path.is_absolute() {
                path.to_path_buf()
            } else {
                burp_home.join(path)
            };
            entry.insert(
                "extension_file".to_owned(),
                json!(abs.display().to_string()),
            );
            entry.insert("loaded".to_owned(), json!(true));
            entry.insert("errors".to_owned(), json!(stream));
            entry.insert("output".to_owned(), json!(stream));
            Ok(Value::Object(entry))
        })
        .collect()
}

fn project_options(proxy_port: u16) -> Value {
    json!({"proxy": {"request_listeners": [{
        "certificate_mode": "per_host",
        "custom_tls_protocols": [],
        "enable_http2": true,
        "listen_mode": "loopback_only",
        "listener_port": proxy_port,
        "running": true,
        "use_custom_tls_protocols": false,
    }]}})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_options_quote_values_with_spaces() {
        let options = [
            "-Da=1".to_owned(),
            "-Draijin.archiveDir=/tmp/a b".to_owned(),
        ];
        assert_eq!(
            java_tool_options(&options).expect("quotable"),
            "-Da=1 \"-Draijin.archiveDir=/tmp/a b\""
        );
        let apostrophe = ["-Dd=/eng/o'brien".to_owned()];
        assert_eq!(
            java_tool_options(&apostrophe).expect("quotable"),
            "\"-Dd=/eng/o'brien\""
        );
        let injection = ["-Dd=/x\" -javaagent:/evil.jar -Dz=\"y".to_owned()];
        assert_eq!(
            java_tool_options(&injection).expect("quotable"),
            "'-Dd=/x\" -javaagent:/evil.jar -Dz=\"y'",
            "a double quote in the value cannot end the option"
        );
        assert!(java_tool_options(&["-Dd='\"".to_owned()]).is_err());
    }

    #[test]
    fn fresh_ports_are_distinct() {
        let p = pick_ports(None).expect("ports");
        let all = [p.mcp, p.mcp_secondary, p.dashboard, p.proxy];
        let unique: std::collections::HashSet<_> = all.iter().collect();
        assert_eq!(unique.len(), 4, "{all:?}");
    }

    #[test]
    fn raijin_entry_is_not_a_bapp() {
        let entry = extension_entry("Raijin", Path::new("/x/raijin.jar"), "java", "console");
        assert!(entry.get("bapp_uuid").is_none() && entry.get("bapp_serial_version").is_none());
        assert_eq!(entry["errors"], "console");
    }

    #[test]
    fn overlay_sets_the_configured_theme() {
        let look = |target: &Target| {
            let options = user_options(target, "main", Mode::Ui, Path::new("/x/raijin.jar"))
                .expect("overlay");
            options["user_options"]["display"]["user_interface"]["look_and_feel"].clone()
        };
        let dir = tempfile::tempdir().expect("temp dir");
        let scaffolded = Target::discover_or_init(dir.path()).expect("auto init");
        assert_eq!(look(&scaffolded), "Dark");
        fs::write(dir.path().join(crate::config::CONFIG_FILE), "theme = \"light\"\n")
            .expect("config");
        let light = Target::discover_or_init(dir.path()).expect("reload");
        assert_eq!(look(&light), "Light");
    }
}
