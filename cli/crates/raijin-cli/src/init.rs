//! `raijin init`: makes the current directory a target folder and registers `raijin mcp` with the agents.

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde_json::{Map, Value, json};

use crate::config::{CONFIG_FILE, STATE_DIR, validate_project_name};

/// Agent MCP config files, relative to the target root.
const MCP_FILES: [&str; 2] = [".mcp.json", ".omp/mcp.json"];

fn template(project: &str) -> String {
    format!(
        r#"# Raijin target. `raijin up` starts Burp with Raijin for a project of this target;
# `raijin mcp` (registered in .mcp.json) lets the agent drive it.

# Project started when none is named; its file is <projects_dir>/<name>.burp.
default_project = "{project}"

# "headless" (no window) or "ui"; `raijin up --ui` / `--headless` override it per launch.
mode = "headless"

# Folder holding the .burp project files, relative to this file.
projects_dir = "burp"

# Raijin jar; default: the release matching this CLI, downloaded to ~/.raijin/jars/.
# RAIJIN_JAR overrides both.
# jar = "/path/to/raijin.jar"

# BApps installed in your global Burp (~/.BurpSuite) to load too, by name.
bapps = []

# Other extensions to load.
# [[extensions]]
# path = "extensions/my-extension.jar"
# type = "java"   # or "python"

[history]
# Extra .burp files for `raijin history` (globs relative to this file).
include = []

[mcp]
# Tool results larger than this many KiB are saved to .raijin/tool-results/ instead of returned inline.
inline_limit_kb = 24

# Drive an already-running Raijin instead of a CLI-managed Burp.
# [remote]
# url = "http://127.0.0.1:9876/mcp"
# token_env = "RAIJIN_TOKEN"   # only when that Raijin requires a bearer token

# Burp install; found automatically in the usual places.
# [burp]
# install_dir = "/Applications/Burp Suite Professional.app"
# java = "/path/to/java"
# jar = "/path/to/burpsuite.jar"
"#
    )
}

/// Writes the default `raijin.toml`, `burp/.gitignore` and the private state folder into `root`.
/// Prints nothing (stdout may be the MCP stdio channel); returns the config path.
pub fn scaffold(root: &Path, project: &str) -> Result<PathBuf> {
    validate_project_name(project)?;
    let config = root.join(CONFIG_FILE);
    if config.exists() {
        bail!("{} already exists", config.display());
    }
    fs::write(&config, template(project))
        .with_context(|| format!("writing {}", config.display()))?;

    write_if_missing(&root.join("burp").join(".gitignore"), "*.burp\n")?;
    crate::util::private_dir(&root.join(STATE_DIR))?;
    write_if_missing(&root.join(STATE_DIR).join(".gitignore"), "*\n")?;
    Ok(config)
}

pub fn run(root: &Path, project: &str, register_mcp: bool) -> Result<()> {
    let config = scaffold(root, project)?;
    println!("wrote {}", config.display());

    if register_mcp {
        for file in MCP_FILES {
            let path = root.join(file);
            let has_burpsuite = register(&path)?;
            println!("registered raijin in {}", path.display());
            if has_burpsuite {
                println!(
                    "warning: {file} also has \"burpsuite\" (direct HTTP); remove it to avoid duplicate Raijin tools"
                );
            }
        }
    }
    println!("next: raijin up   (starts Burp for project {project:?})");
    Ok(())
}

fn write_if_missing(path: &Path, text: &str) -> Result<()> {
    if path.exists() {
        return Ok(());
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, text).with_context(|| format!("writing {}", path.display()))
}

/// Merges the `raijin` server into `mcpServers` of `path` (created if missing), keeping every other
/// key in place. Returns whether a `burpsuite` server is also configured.
fn register(path: &Path) -> Result<bool> {
    let mut document = if path.exists() {
        let text =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        if text.trim().is_empty() {
            Value::Object(Map::new())
        } else {
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?
        }
    } else {
        Value::Object(Map::new())
    };
    let Value::Object(root) = &mut document else {
        bail!("{} is not a JSON object", path.display());
    };
    let servers = root
        .entry("mcpServers")
        .or_insert_with(|| Value::Object(Map::new()));
    let Value::Object(servers) = servers else {
        bail!("{}: mcpServers is not an object", path.display());
    };
    servers.insert(
        "raijin".to_owned(),
        json!({"command": "raijin", "args": ["mcp"]}),
    );
    let has_burpsuite = servers.contains_key("burpsuite");

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut text = serde_json::to_string_pretty(&document)?;
    text.push('\n');
    fs::write(path, text).with_context(|| format!("writing {}", path.display()))?;
    Ok(has_burpsuite)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_keeps_other_keys_and_reports_burpsuite() {
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join(".mcp.json");
        fs::write(
            &path,
            r#"{"$schema":"x","mcpServers":{"burpsuite":{"url":"http://127.0.0.1:9876/mcp"},"other":{"command":"o"}}}"#,
        )
        .expect("seed");
        assert!(register(&path).expect("register"));
        let doc: Value =
            serde_json::from_str(&fs::read_to_string(&path).expect("read")).expect("json");
        assert_eq!(doc["$schema"], "x");
        assert_eq!(doc["mcpServers"]["other"]["command"], "o");
        assert_eq!(
            doc["mcpServers"]["raijin"],
            json!({"command": "raijin", "args": ["mcp"]})
        );
        let keys: Vec<_> = doc.as_object().expect("object").keys().cloned().collect();
        assert_eq!(keys, ["$schema", "mcpServers"], "key order is kept");
    }

    #[test]
    fn the_template_parses() {
        crate::config::Config::parse(&template("main")).expect("template is valid raijin.toml");
    }
}
