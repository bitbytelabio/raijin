//! Where Burp is installed, and how to start it.

use std::path::{Path, PathBuf};

use anyhow::{Result, bail};

use crate::config::{Burp, home_dir};

/// How a Burp process is started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Launcher {
    /// macOS app bundle: run its `JavaApplicationStub`, which applies `Contents/vmoptions.txt`
    /// (and its includes) itself; extra JVM flags go through `JAVA_TOOL_OPTIONS`. The bundled
    /// `bin/java` cannot be used: `PortSwigger` signs it with a parent launch constraint, so macOS
    /// kills it (AMFI, SIGKILL) unless Burp's own launcher starts it.
    MacStub { stub: PathBuf },
    /// `java <vmoptions> <flags> -jar burpsuite.jar`; `vmoption_roots` are the install's vmoptions files.
    Java {
        java: PathBuf,
        jar: PathBuf,
        vmoption_roots: Vec<PathBuf>,
    },
}

fn candidates(home: &Path) -> Vec<PathBuf> {
    if cfg!(target_os = "macos") {
        let mut out = Vec::new();
        for base in [PathBuf::from("/Applications"), home.join("Applications")] {
            out.push(base.join("Burp Suite.app"));
            out.push(base.join("Burp Suite Professional.app"));
        }
        out
    } else {
        vec![
            home.join("BurpSuitePro"),
            PathBuf::from("/opt/BurpSuitePro"),
            home.join("BurpSuite"),
            PathBuf::from("/opt/BurpSuite"),
        ]
    }
}

fn first_match(dir: &Path, prefix: &str, suffix: &str) -> Option<PathBuf> {
    let mut names: Vec<PathBuf> = std::fs::read_dir(dir)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(prefix) && n.ends_with(suffix))
        })
        .collect();
    names.sort();
    names.into_iter().next()
}

pub fn discover(burp: &Burp, root: &Path) -> Result<Launcher> {
    let resolve = |p: &Path| {
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            root.join(p)
        }
    };
    let home = home_dir()?;
    let tried: Vec<PathBuf> = burp
        .install_dir
        .as_deref()
        .map_or_else(|| candidates(&home), |d| vec![resolve(d)]);
    let install = tried.iter().find(|p| p.is_dir()).cloned();

    let (java_override, jar_override) = (
        burp.java.as_deref().map(resolve),
        burp.jar.as_deref().map(resolve),
    );
    if java_override.is_none()
        && jar_override.is_none()
        && let Some(dir) = &install
    {
        let stub = dir.join("Contents/MacOS/JavaApplicationStub");
        if cfg!(target_os = "macos") && stub.is_file() {
            return Ok(Launcher::MacStub { stub });
        }
    }

    let jar = jar_override.or_else(|| {
        let dir = install.as_ref()?;
        first_match(&dir.join("Contents/Resources/app"), "burpsuite", ".jar")
            .or_else(|| first_match(dir, "burpsuite", ".jar"))
    });
    let java = java_override.or_else(|| {
        let dir = install.as_ref()?;
        [
            dir.join("Contents/Resources/jre.bundle/Contents/Home/bin/java"),
            dir.join("jre/bin/java"),
        ]
        .into_iter()
        .find(|p| p.is_file())
    });
    let (Some(java), Some(jar)) = (java, jar) else {
        let paths: Vec<String> = tried.iter().map(|p| p.display().to_string()).collect();
        bail!(
            "Burp Suite not found (tried {}); set [burp] install_dir, or [burp] java and [burp] jar, in raijin.toml",
            paths.join(", ")
        );
    };
    let vmoption_roots = match &install {
        Some(dir) if dir.join("Contents/vmoptions.txt").is_file() => {
            vec![dir.join("Contents/vmoptions.txt")]
        }
        Some(dir) => {
            let mut files: Vec<PathBuf> = std::fs::read_dir(dir).map_or_default(|rd| {
                rd.flatten()
                    .map(|e| e.path())
                    .filter(|p| p.extension().is_some_and(|e| e == "vmoptions"))
                    .collect()
            });
            files.sort();
            files
        }
        None => Vec::new(),
    };
    Ok(Launcher::Java {
        java,
        jar,
        vmoption_roots,
    })
}
