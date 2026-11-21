//! Instance files (`.raijin/instances/<project>.json`), state derivation, and stopping.

use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::Duration;

use anyhow::{Context, Result};
use futures::future;
use nix::errno::Errno;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::config::{Mode, Target};
use crate::util::write_private;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ports {
    pub mcp: u16,
    pub mcp_secondary: u16,
    pub dashboard: u16,
    pub proxy: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Instance {
    pub project: String,
    pub project_file: PathBuf,
    pub mode: Mode,
    pub pid: Option<u32>,
    pub started_at_ms: Option<u64>,
    pub control_token: Option<String>,
    pub jar: PathBuf,
    pub jar_version: Option<String>,
    pub ports: Ports,
    pub log: PathBuf,
}

impl Instance {
    pub fn load(target: &Target, project: &str) -> Result<Option<Self>> {
        let path = target.instance_file(project);
        match std::fs::read_to_string(&path) {
            Ok(text) => Ok(Some(
                serde_json::from_str(&text)
                    .with_context(|| format!("parsing {}", path.display()))?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
        }
    }

    pub fn save(&self, target: &Target) -> Result<()> {
        write_private(
            &target.instance_file(&self.project),
            &serde_json::to_vec_pretty(self)?,
        )
    }

    pub fn mcp_url(&self) -> String {
        mcp_url(self.ports.mcp)
    }

    fn mark_stopped(&mut self, target: &Target) -> Result<()> {
        self.pid = None;
        self.control_token = None;
        self.save(target)
    }
}

pub fn mcp_url(port: u16) -> String {
    format!("http://127.0.0.1:{port}/mcp")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Stopped,
    Starting,
    Running,
}

/// Reaps a spawned Burp on its own thread when it exits. An unreaped child is a zombie, which
/// `kill(pid, 0)` still reports alive, and `raijin mcp` lives as long as the agent session.
pub fn adopt(mut child: Child) {
    std::thread::spawn(move || {
        let _ = child.wait();
    });
}

pub fn pid_alive(pid: u32) -> bool {
    let Ok(raw) = i32::try_from(pid) else {
        return false;
    };
    matches!(
        signal::kill(Pid::from_raw(raw), None),
        Ok(()) | Err(Errno::EPERM)
    )
}

/// The command line of `pid`: `/proc/<pid>/cmdline` on Linux, else `ps`. `None` when it cannot be read.
fn command_line(pid: u32) -> Option<String> {
    if let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) {
        return Some(String::from_utf8_lossy(&raw).replace('\0', " "));
    }
    // -ww: never truncate the command line to a terminal width.
    let output = Command::new("ps")
        .args(["-ww", "-o", "command=", "-p", &pid.to_string()])
        .output()
        .ok()
        .filter(|o| o.status.success() || !o.stdout.is_empty())?;
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Whether `pid` is alive and still the Burp `instance` started: its command line names the
/// instance's project file. After a crash or reboot the recorded pid may belong to an unrelated
/// process, which must never be signalled. When the command line cannot be read at all, liveness alone decides.
pub fn is_ours(pid: u32, instance: &Instance) -> bool {
    if !pid_alive(pid) {
        return false;
    }
    let wanted = format!("--project-file={}", instance.project_file.display());
    command_line(pid).is_none_or(|line| line.contains(&wanted))
}

/// Signals the process group led by `pid` (Burp is started as a group leader), falling back to the pid.
pub fn signal_group(pid: u32, sig: Signal) {
    let Ok(raw) = i32::try_from(pid) else { return };
    if signal::killpg(Pid::from_raw(raw), sig).is_err() {
        let _ = signal::kill(Pid::from_raw(raw), sig);
    }
}

pub fn http() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .no_proxy()
        .build()
        .expect("reqwest client with static settings builds")
}

/// `GET /api/info` when it answers 200 for the dashboard on `port`.
pub async fn api_info(client: &reqwest::Client, port: u16) -> Option<Value> {
    let response = client
        .get(format!("http://127.0.0.1:{port}/api/info"))
        .send()
        .await
        .ok()?;
    if !response.status().is_success() {
        return None;
    }
    response.json().await.ok()
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub project: String,
    pub state: State,
    pub mode: Option<Mode>,
    pub pid: Option<u32>,
    pub mcp_url: Option<String>,
    pub proxy: Option<String>,
    pub log: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// stopped: no pid, or the pid is dead (cleared). running: the pid lives and `/api/info` answers
/// for this instance's ports within 2 s. starting: anything else.
pub async fn status(target: &Target, project: &str, client: &reqwest::Client) -> Result<Status> {
    let Some(mut instance) = Instance::load(target, project)? else {
        return Ok(Status {
            project: project.to_owned(),
            state: State::Stopped,
            mode: None,
            pid: None,
            mcp_url: None,
            proxy: None,
            log: None,
            version: None,
        });
    };
    let alive = instance.pid.is_some_and(|pid| is_ours(pid, &instance));
    if instance.pid.is_some() && !alive {
        instance.mark_stopped(target)?;
    }
    let (state, version) = if alive {
        match api_info(client, instance.ports.dashboard).await {
            Some(info)
                if info["ports"]["primary_mcp"].as_u64() == Some(u64::from(instance.ports.mcp)) =>
            {
                (State::Running, info["version"].as_str().map(str::to_owned))
            }
            _ => (State::Starting, None),
        }
    } else {
        (State::Stopped, None)
    };
    let live = state != State::Stopped;
    Ok(Status {
        project: project.to_owned(),
        state,
        mode: Some(instance.mode),
        pid: instance.pid,
        mcp_url: live.then(|| instance.mcp_url()),
        proxy: live.then(|| format!("127.0.0.1:{}", instance.ports.proxy)),
        log: Some(instance.log),
        version,
    })
}

/// Every `<projects_dir>/*.burp` and every instance file, checked concurrently.
pub async fn status_all(target: &Target) -> Result<Vec<Status>> {
    let client = http();
    let projects = target.known_projects();
    let checks = projects.iter().map(|p| status(target, p, &client));
    future::join_all(checks).await.into_iter().collect()
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum StopMethod {
    Graceful,
    Sigterm,
    Sigkill,
}

async fn wait_exit(pid: u32, within: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + within;
    while tokio::time::Instant::now() < deadline {
        if !pid_alive(pid) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    !pid_alive(pid)
}

/// `/api/shutdown` with the control token, then SIGTERM after 30 s, then SIGKILL after 15 more.
/// An older jar without the endpoint (404) goes straight to SIGTERM.
pub async fn stop(target: &Target, project: &str) -> Result<Value> {
    let Some(mut instance) = Instance::load(target, project)? else {
        return Ok(json!({"project": project, "state": "stopped", "was_running": false}));
    };
    let Some(pid) = instance.pid.filter(|p| is_ours(*p, &instance)) else {
        if instance.pid.is_some() {
            instance.mark_stopped(target)?;
        }
        return Ok(json!({"project": project, "state": "stopped", "was_running": false}));
    };
    let client = http();
    let accepted = match &instance.control_token {
        Some(token) => client
            .post(format!(
                "http://127.0.0.1:{}/api/shutdown",
                instance.ports.dashboard
            ))
            .header("X-Raijin-Control-Token", token)
            .send()
            .await
            .is_ok_and(|r| r.status().as_u16() == 202),
        None => false,
    };
    let method = if accepted && wait_exit(pid, Duration::from_secs(30)).await {
        StopMethod::Graceful
    } else {
        signal_group(pid, Signal::SIGTERM);
        if wait_exit(pid, Duration::from_secs(15)).await {
            StopMethod::Sigterm
        } else {
            signal_group(pid, Signal::SIGKILL);
            wait_exit(pid, Duration::from_secs(5)).await;
            StopMethod::Sigkill
        }
    };
    instance.mark_stopped(target)?;
    Ok(json!({"project": project, "state": "stopped", "was_running": true, "method": method}))
}
