//! The isolated Burp profile every CLI-managed launch shares.
//!
//! Spike outcome (Burp Suite Professional 2026.10.1, macOS 27.2, Raijin 2.2.1), mechanism A:
//! `--data-dir=~/.raijin/burp-profile` keeps Burp's user config in the profile. Both headless
//! (`-Djava.awt.headless=true`) and UI launches came up without a licence prompt (licence and EULA
//! live in Java Preferences, which the profile does not move), served `/api/info`, opened the proxy
//! listener from the `--config-file` overlay, and shut down through `/api/shutdown`. Afterwards
//! `~/.BurpSuite/UserConfigPro.json` was byte-identical to its backup, and the profile's
//! `UserConfigPro.json` still had an empty extension list: the `--user-config-file` overlay applies
//! for the run only and is not written back. Turbo raised nothing headless (no Step 1.1 contingency).
//!
//! Two findings changed the launch itself (see `launch.rs` and `install.rs`):
//! - On macOS the bundled `bin/java` has a `PortSwigger` parent launch constraint; exec'd by
//!   anything but Burp's own `JavaApplicationStub` it is killed by AMFI. The CLI runs the stub,
//!   which reads the install's vmoptions chain itself, and passes its JVM flags in `JAVA_TOOL_OPTIONS`.
//! - An extension entry must omit `bapp_uuid` / `bapp_serial_version` unless it is a `BApp`: with
//!   `""` / `0` Burp refuses the jar ("Extension class is not a recognized type").

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde_json::{Value, json};

use crate::config::{home_dir, user_state_dir};
use crate::util::private_dir;

pub const USER_CONFIG: &str = "UserConfigPro.json";

/// `~/.raijin/burp-profile`, passed as `--data-dir`.
pub fn dir() -> Result<PathBuf> {
    Ok(user_state_dir()?.join("burp-profile"))
}

/// The global Burp user config, `~/.BurpSuite/UserConfigPro.json`.
pub fn global_config() -> Result<PathBuf> {
    Ok(home_dir()?.join(".BurpSuite").join(USER_CONFIG))
}

/// Seeds the profile once from the global user config, without its extensions and with Burp's REST
/// API off; each launch adds its own extensions through an overlay. Skipped when there is no global config.
pub fn ensure_seeded() -> Result<PathBuf> {
    let dir = dir()?;
    private_dir(&dir)?;
    let profile_config = dir.join(USER_CONFIG);
    if profile_config.exists() {
        return Ok(dir);
    }
    let global = global_config()?;
    let Ok(text) = fs::read_to_string(&global) else {
        return Ok(dir);
    };
    let mut config: Value =
        serde_json::from_str(&text).with_context(|| format!("parsing {}", global.display()))?;
    strip(&mut config);
    fs::write(&profile_config, serde_json::to_string_pretty(&config)?)
        .with_context(|| format!("writing {}", profile_config.display()))?;
    Ok(dir)
}

fn strip(config: &mut Value) {
    let Some(user) = config
        .get_mut("user_options")
        .and_then(Value::as_object_mut)
    else {
        return;
    };
    if let Some(extender) = user.get_mut("extender").and_then(Value::as_object_mut) {
        extender.insert("extensions".to_owned(), json!([]));
    }
    if let Some(api) = user
        .get_mut("misc")
        .and_then(|m| m.get_mut("api"))
        .and_then(Value::as_object_mut)
    {
        api.insert("enabled".to_owned(), json!(false));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeding_drops_extensions_and_the_rest_api() {
        let mut config = json!({"user_options": {
            "extender": {"extensions": [{"name": "X"}], "java": {"a": 1}},
            "misc": {"api": {"enabled": true, "port": 1337}, "other": 1},
        }});
        strip(&mut config);
        assert_eq!(
            config["user_options"]["extender"],
            json!({"extensions": [], "java": {"a": 1}})
        );
        assert_eq!(
            config["user_options"]["misc"]["api"],
            json!({"enabled": false, "port": 1337})
        );
        assert_eq!(config["user_options"]["misc"]["other"], 1);
    }
}
