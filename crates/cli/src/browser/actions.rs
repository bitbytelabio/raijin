//! Launcher actions: one `ShardBrowser` API call each (profiles, proxies, folders, extensions,
//! bookmarks, tags, templates, trash, cookies, automation projects and modules).

use reqwest::Method;
use rmcp::model::CallToolResult;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use super::{Call, Ctx, Hub, json_result};
use crate::burp::instance::{self, State};
use crate::mcp::error::{Code, ToolError};

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
pub enum Platform {
    Windows,
    #[serde(rename = "macOS")]
    MacOs,
    Linux,
}

impl Platform {
    fn as_str(self) -> &'static str {
        match self {
            Self::Windows => "Windows",
            Self::MacOs => "macOS",
            Self::Linux => "Linux",
        }
    }
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ProxyKind {
    Socks5,
    Http,
    Https,
}

#[derive(Debug, Clone, Copy, Deserialize, Serialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TagColor {
    Blue,
    Violet,
    Magenta,
    Red,
    Orange,
    Yellow,
    Green,
    Sky,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NoArgs {}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct IdArgs {
    pub id: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct NameArgs {
    pub name: String,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct OptionalNameArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct PathArgs {
    /// A path on this machine.
    pub path: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FingerprintArgs {
    pub platform: Option<Platform>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CreateProfileArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Files the profile in this folder.
    #[serde(skip_serializing)]
    pub folder: Option<String>,
    /// A proxy string (scheme://user:pass@host:port), added to the store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_id: Option<String>,
    /// The platform of the generated fingerprint (default: the host OS).
    #[serde(skip_serializing)]
    pub platform: Option<Platform>,
    /// Icon and omnibox-pill accent; omit to derive it from the name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// Extension-library ids; see `list_extensions`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String>>,
    /// Claimed display refresh rate in Hz, 24 to 480 (default the engine's 60).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 24, max = 480))]
    pub refresh_rate: Option<u32>,
    /// A fingerprint to use verbatim; omit to generate one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<Value>,
    /// Point the profile at this target's running Burp proxy listener.
    #[serde(skip_serializing)]
    pub via_burp: Option<bool>,
    /// The Burp project whose proxy `via_burp` uses, when several run.
    #[serde(skip_serializing)]
    pub burp_project: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TempProfileArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
    /// A proxy string (scheme://user:pass@host:port).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    /// Noise by vector (`canvas`, `webgl`, `audio`, `client_rects`, `sensors`, `fonts`): `true`,
    /// or `{enabled, seed, intensity, max_offset}`; omitted vectors stay off.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub noise: Option<Map<String, Value>>,
    /// Claimed display refresh rate in Hz, 24 to 480 (default the engine's 60).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 24, max = 480))]
    pub refresh_rate: Option<u32>,
    /// Point the profile at this target's running Burp proxy listener.
    #[serde(skip_serializing)]
    pub via_burp: Option<bool>,
    /// The Burp project whose proxy `via_burp` uses, when several run.
    #[serde(skip_serializing)]
    pub burp_project: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct EditProfileArgs {
    #[serde(skip_serializing)]
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// A folder to file it in; "" unfiles.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    /// A stored proxy's id; "" unbinds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    /// "" goes back to the name-derived colour.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// Replaces the whole list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Vec<String>>,
    /// Tag ids or names from `list_tags`; replaces the profile's tags.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    /// Claimed display refresh rate in Hz, 24 to 480; applied after fingerprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 24, max = 480))]
    pub refresh_rate: Option<u32>,
    /// Replaces the fingerprint verbatim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<Value>,
    /// Point the profile at this target's running Burp proxy listener.
    #[serde(skip_serializing)]
    pub via_burp: Option<bool>,
    /// The Burp project whose proxy `via_burp` uses, when several run.
    #[serde(skip_serializing)]
    pub burp_project: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct StartArgs {
    pub id: String,
    pub headless: Option<bool>,
    pub password: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct RenameFolderArgs {
    pub folder: String,
    pub name: String,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct DeleteFolderArgs {
    pub folder: String,
    /// true removes its profiles; false (default) unfiles them.
    pub delete_profiles: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddProxyArgs {
    /// scheme://user:pass@host:port, or give the fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<ProxyKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct AddExtensionArgs {
    /// A Web Store page, a bare extension id, or a direct .crx/.zip link.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// A local .crx/.zip file or unpacked folder.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BookmarkArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// The folder whose profiles get it; omit for every profile.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TagArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<TagColor>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct ProfileTagsArgs {
    pub id: String,
    /// Tag ids or names; [] clears.
    pub tags: Vec<String>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct TemplateArgs {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    /// Takes this profile's settings, folder, tags and fingerprint source.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_default: Option<bool>,
}

#[derive(Debug, Deserialize, Serialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct FromTemplateArgs {
    /// The template's id.
    #[serde(skip_serializing)]
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct CookiesArgs {
    pub id: String,
    /// Cookies as `export_cookies` returns them.
    pub cookies: Vec<Value>,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct SaveProjectArgs {
    pub id: String,
    /// The whole project, as `get_automation_project` returned it.
    pub project: Value,
}

#[derive(Debug, Deserialize, JsonSchema)]
#[serde(deny_unknown_fields)]
pub struct BundleArgs {
    /// A bundle as `export_automation_project` returned it.
    pub bundle: Value,
}

#[derive(Clone, Copy)]
enum Verb {
    Get,
    Post,
    Delete,
}

impl Verb {
    fn method(self) -> Method {
        match self {
            Self::Get => Method::GET,
            Self::Post => Method::POST,
            Self::Delete => Method::DELETE,
        }
    }
}

/// An action that is one call with no arguments but `id`: `{id}` in `path` takes it.
struct Route {
    action: &'static str,
    verb: Verb,
    path: &'static [&'static str],
    /// The profile's browser goes away, so its page session is dropped first.
    drops_session: bool,
}

const fn route(
    action: &'static str,
    verb: Verb,
    path: &'static [&'static str],
    drops_session: bool,
) -> Route {
    Route {
        action,
        verb,
        path,
        drops_session,
    }
}

const BY_ID: &[Route] = &[
    route("get_profile", Verb::Get, &["profiles", "{id}"], false),
    route("delete_profile", Verb::Delete, &["profiles", "{id}"], true),
    route(
        "stop_profile",
        Verb::Post,
        &["profiles", "{id}", "stop"],
        true,
    ),
    route("delete_proxy", Verb::Delete, &["proxies", "{id}"], false),
    route(
        "delete_extension",
        Verb::Delete,
        &["extensions", "{id}"],
        false,
    ),
    route(
        "delete_bookmark",
        Verb::Delete,
        &["bookmarks", "{id}"],
        false,
    ),
    route("delete_tag", Verb::Delete, &["tags", "{id}"], false),
    route(
        "delete_template",
        Verb::Delete,
        &["templates", "{id}"],
        false,
    ),
    route(
        "restore_profile",
        Verb::Post,
        &["trash", "{id}", "restore"],
        false,
    ),
    route("purge_profile", Verb::Delete, &["trash", "{id}"], true),
    route(
        "export_cookies",
        Verb::Get,
        &["profiles", "{id}", "cookies"],
        false,
    ),
    route(
        "get_automation_project",
        Verb::Get,
        &["automation", "projects", "{id}"],
        false,
    ),
    route(
        "delete_automation_project",
        Verb::Delete,
        &["automation", "projects", "{id}"],
        false,
    ),
    route(
        "duplicate_automation_project",
        Verb::Post,
        &["automation", "projects", "{id}", "duplicate"],
        false,
    ),
    route(
        "export_automation_project",
        Verb::Get,
        &["automation", "projects", "{id}", "export"],
        false,
    ),
    route(
        "run_automation_project",
        Verb::Post,
        &["automation", "projects", "{id}", "run"],
        false,
    ),
    route(
        "stop_automation_project",
        Verb::Post,
        &["automation", "projects", "{id}", "stop"],
        false,
    ),
    route(
        "automation_status",
        Verb::Get,
        &["automation", "projects", "{id}", "status"],
        false,
    ),
    route(
        "remove_automation_module",
        Verb::Delete,
        &["automation", "modules", "{id}"],
        false,
    ),
];

/// Actions that are one `GET` with no arguments.
const LISTS: &[(&str, &[&str])] = &[
    ("list_profiles", &["profiles"]),
    ("list_running", &["running"]),
    ("list_fingerprints", &["fingerprints"]),
    ("list_folders", &["folders"]),
    ("list_proxies", &["proxies"]),
    ("list_extensions", &["extensions"]),
    ("list_bookmarks", &["bookmarks"]),
    ("list_tags", &["tags"]),
    ("list_templates", &["templates"]),
    ("list_trash", &["trash"]),
    ("list_automation_projects", &["automation", "projects"]),
    ("list_automation_runs", &["automation", "runs"]),
    ("list_automation_modules", &["automation", "modules"]),
];

/// `value` (a serialized argument struct) as a request body.
fn body_of(value: &impl Serialize) -> Result<Value, ToolError> {
    serde_json::to_value(value).map_err(|e| ToolError::new(Code::Internal, e.to_string()))
}

fn refresh_rate_in_range(rate: Option<u32>) -> Result<(), ToolError> {
    match rate {
        Some(r) if !(24..=480).contains(&r) => Err(ToolError::new(
            Code::OutOfRange,
            format!("refresh_rate must be 24 to 480 Hz, got {r}"),
        )
        .param("refresh_rate")
        .got(json!(r))
        .expected("24 to 480")),
        _ => Ok(()),
    }
}

impl Hub {
    pub(super) async fn launcher_action(
        &self,
        call: &mut Call<'_>,
    ) -> Result<CallToolResult, ToolError> {
        let name = call.action.name;
        let l = &self.launcher;
        if let Some((_, path)) = LISTS.iter().find(|(a, _)| *a == name) {
            call.args::<NoArgs>()?;
            return Ok(json_result(&l.get(path).await?));
        }
        if let Some(r) = BY_ID.iter().find(|r| r.action == name) {
            let IdArgs { id } = call.args()?;
            if r.drops_session {
                self.drop_session(&id).await;
            }
            let path: Vec<&str> = r
                .path
                .iter()
                .map(|s| if *s == "{id}" { id.as_str() } else { s })
                .collect();
            return Ok(json_result(
                &l.api(r.verb.method(), &path, &[], None).await?,
            ));
        }
        let value = match name {
            "health_check" => {
                call.args::<NoArgs>()?;
                l.health().await
            }
            "find_profile_by_name" => {
                let NameArgs { name } = call.args()?;
                let needle = name.trim().to_lowercase();
                let profiles = l.get(&["profiles"]).await?;
                let hits: Vec<&Value> = profiles
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter(|p| {
                        p.get("name")
                            .and_then(Value::as_str)
                            .is_some_and(|n| n.to_lowercase().contains(&needle))
                    })
                    .collect();
                json!({"query": name, "found": hits.len(), "profiles": hits})
            }
            "new_fingerprint" => {
                let FingerprintArgs { platform } = call.args()?;
                self.new_fingerprint(platform).await?
            }
            _ => return self.profile_action(call).await,
        };
        Ok(json_result(&value))
    }

    /// Creating and editing profiles: the actions that take `via_burp`.
    async fn profile_action(&self, call: &mut Call<'_>) -> Result<CallToolResult, ToolError> {
        let l = &self.launcher;
        let value = match call.action.name {
            "create_profile" => {
                let args: CreateProfileArgs = call.args()?;
                refresh_rate_in_range(args.refresh_rate)?;
                let burp = via_burp(
                    &call.ctx,
                    args.via_burp,
                    args.burp_project.as_deref(),
                    args.proxy.is_some() || args.proxy_id.is_some(),
                    &mut call.notes,
                )
                .await?;
                let mut body = body_of(&args)?;
                if let Some(proxy) = burp {
                    body["proxy"] = json!(proxy);
                }
                if args.fingerprint.is_none() {
                    let fresh = self.new_fingerprint(args.platform).await?;
                    body["fingerprint"] = fresh.get("fingerprint").cloned().unwrap_or(Value::Null);
                }
                match &args.folder {
                    Some(folder) => {
                        l.api(
                            Method::POST,
                            &["folders", folder, "profiles"],
                            &[],
                            Some(body),
                        )
                        .await?
                    }
                    None => l.api(Method::POST, &["profiles"], &[], Some(body)).await?,
                }
            }
            "create_temporary_profile" => {
                let args: TempProfileArgs = call.args()?;
                refresh_rate_in_range(args.refresh_rate)?;
                let burp = via_burp(
                    &call.ctx,
                    args.via_burp,
                    args.burp_project.as_deref(),
                    args.proxy.is_some(),
                    &mut call.notes,
                )
                .await?;
                let mut body = body_of(&args)?;
                if let Some(proxy) = burp {
                    body["proxy"] = json!(proxy);
                }
                l.api(Method::POST, &["profiles", "temporary"], &[], Some(body))
                    .await?
            }
            "edit_profile" => {
                // `""` is a value here (unfile, unbind, default colour), which reading the
                // arguments would drop as unset.
                let mut blanks = Vec::new();
                if let Some(raw) = call.arguments.as_mut() {
                    for key in ["folder", "proxy_id", "color"] {
                        if raw.get(key).and_then(Value::as_str) == Some("") {
                            raw.remove(key);
                            blanks.push(key);
                        }
                    }
                }
                let args: EditProfileArgs = call.args()?;
                refresh_rate_in_range(args.refresh_rate)?;
                let burp = via_burp(
                    &call.ctx,
                    args.via_burp,
                    args.burp_project.as_deref(),
                    args.proxy.is_some() || args.proxy_id.is_some(),
                    &mut call.notes,
                )
                .await?;
                let mut body = body_of(&args)?;
                for key in blanks {
                    body[key] = json!("");
                }
                if let Some(proxy) = burp {
                    body["proxy"] = json!(proxy);
                }
                l.api(Method::PATCH, &["profiles", &args.id], &[], Some(body))
                    .await?
            }
            _ => return self.store_action(call).await,
        };
        Ok(json_result(&value))
    }

    /// Starting profiles, folders, proxies, extensions, bookmarks and tags.
    async fn store_action(&self, call: &mut Call<'_>) -> Result<CallToolResult, ToolError> {
        let l = &self.launcher;
        let value = match call.action.name {
            "start_profile" => {
                let StartArgs {
                    id,
                    headless,
                    password,
                } = call.args()?;
                let mut body = json!({"headless": headless.unwrap_or(false)});
                if let Some(password) = password {
                    body["password"] = json!(password);
                }
                l.api(Method::POST, &["profiles", &id, "start"], &[], Some(body))
                    .await?
            }
            "rename_folder" => {
                let RenameFolderArgs { folder, name } = call.args()?;
                l.api(
                    Method::PATCH,
                    &["folders", &folder],
                    &[],
                    Some(json!({"name": name})),
                )
                .await?
            }
            "delete_folder" => {
                let DeleteFolderArgs {
                    folder,
                    delete_profiles,
                } = call.args()?;
                let flag = if delete_profiles == Some(true) {
                    "true"
                } else {
                    "false"
                };
                l.api(
                    Method::DELETE,
                    &["folders", &folder],
                    &[("delete_profiles", flag)],
                    None,
                )
                .await?
            }
            "add_proxy" => {
                let args: AddProxyArgs = call.args()?;
                l.api(Method::POST, &["proxies"], &[], Some(body_of(&args)?))
                    .await?
            }
            "add_extension" => {
                let args: AddExtensionArgs = call.args()?;
                if args.url.is_none() && args.path.is_none() {
                    return Err(ToolError::new(
                        Code::MissingParameter,
                        "browser.add_extension needs 'url' (Web Store page, extension id or .crx/.zip link) or 'path' (local file or folder)",
                    )
                    .param("url")
                    .example(call.action.example()));
                }
                l.api(Method::POST, &["extensions"], &[], Some(body_of(&args)?))
                    .await?
            }
            "save_bookmark" => {
                let args: BookmarkArgs = call.args()?;
                l.api(Method::POST, &["bookmarks"], &[], Some(body_of(&args)?))
                    .await?
            }
            "save_tag" => {
                let args: TagArgs = call.args()?;
                l.api(Method::POST, &["tags"], &[], Some(body_of(&args)?))
                    .await?
            }
            _ => return self.library_action(call).await,
        };
        Ok(json_result(&value))
    }

    /// Profile tags, templates, cookies, automation projects and modules.
    async fn library_action(&self, call: &mut Call<'_>) -> Result<CallToolResult, ToolError> {
        let l = &self.launcher;
        let value = match call.action.name {
            "set_profile_tags" => {
                let ProfileTagsArgs { id, tags } = call.args()?;
                l.api(
                    Method::PUT,
                    &["profiles", &id, "tags"],
                    &[],
                    Some(json!({"tags": tags})),
                )
                .await?
            }
            "save_template" => {
                let args: TemplateArgs = call.args()?;
                l.api(Method::POST, &["templates"], &[], Some(body_of(&args)?))
                    .await?
            }
            "create_profile_from_template" => {
                let args: FromTemplateArgs = call.args()?;
                l.api(
                    Method::POST,
                    &["templates", &args.id, "profiles"],
                    &[],
                    Some(body_of(&args)?),
                )
                .await?
            }
            "import_cookies" => {
                let CookiesArgs { id, cookies } = call.args()?;
                l.api(
                    Method::POST,
                    &["profiles", &id, "cookies"],
                    &[],
                    Some(json!({"cookies": cookies})),
                )
                .await?
            }
            "create_automation_project" => {
                let args: OptionalNameArgs = call.args()?;
                l.api(
                    Method::POST,
                    &["automation", "projects"],
                    &[],
                    Some(body_of(&args)?),
                )
                .await?
            }
            "save_automation_project" => {
                let SaveProjectArgs { id, project } = call.args()?;
                l.api(
                    Method::PUT,
                    &["automation", "projects", &id],
                    &[],
                    Some(project),
                )
                .await?
            }
            "import_automation_project" => {
                let BundleArgs { bundle } = call.args()?;
                l.api(Method::POST, &["automation", "import"], &[], Some(bundle))
                    .await?
            }
            "install_automation_module" => {
                let args: PathArgs = call.args()?;
                l.api(
                    Method::POST,
                    &["automation", "modules"],
                    &[],
                    Some(body_of(&args)?),
                )
                .await?
            }
            other => {
                return Err(ToolError::new(
                    Code::Internal,
                    format!("browser.{other} has no launcher handler"),
                ));
            }
        };
        Ok(json_result(&value))
    }

    async fn new_fingerprint(&self, platform: Option<Platform>) -> Result<Value, ToolError> {
        match platform {
            Some(p) => self.launcher.get(&["fingerprint", "new", p.as_str()]).await,
            None => self.launcher.get(&["fingerprint", "new"]).await,
        }
    }
}

/// The proxy URL `via_burp` asks for, or None without it; its note goes to `notes`.
async fn via_burp(
    ctx: &Ctx<'_>,
    via_burp: Option<bool>,
    burp_project: Option<&str>,
    has_proxy: bool,
    notes: &mut Vec<String>,
) -> Result<Option<String>, ToolError> {
    if via_burp != Some(true) {
        if burp_project.is_some() {
            notes.push("ignored 'burp_project': it goes with via_burp:true".to_owned());
        }
        return Ok(None);
    }
    if has_proxy {
        return Err(ToolError::new(
            Code::InvalidArguments,
            "pass via_burp or proxy/proxy_id, not both",
        )
        .param("via_burp"));
    }
    let (url, note) = burp_proxy(ctx, burp_project).await?;
    notes.push(note);
    Ok(Some(url))
}

/// The proxy listener of this target's running Burp (`project`, or the only one running) as a
/// proxy URL, with a note saying which.
async fn burp_proxy(ctx: &Ctx<'_>, project: Option<&str>) -> Result<(String, String), ToolError> {
    if ctx.remote {
        return Err(ToolError::new(
            Code::NotSupported,
            "via_burp needs a Burp this CLI runs; in remote mode pass proxy instead",
        ));
    }
    let Some(target) = ctx.target else {
        return Err(ToolError::new(
            Code::ConfigError,
            ctx.target_error.unwrap_or("no raijin target here"),
        ));
    };
    let statuses = instance::status_all(target)
        .await
        .map_err(|e| ToolError::new(Code::ToolFailed, format!("{e:#}")))?;
    let mut live: Vec<instance::Status> = statuses
        .into_iter()
        .filter(|s| s.state != State::Stopped && s.proxy.is_some())
        .collect();
    let chosen = match project {
        Some(p) => live
            .into_iter()
            .find(|s| s.project.eq_ignore_ascii_case(p))
            .ok_or_else(|| {
                ToolError::new(
                    Code::BurpNotRunning,
                    format!("the Burp of project {p} is not running; start it with burp_up"),
                )
                .see(json!({"do": "burp_up", "project": p}))
            })?,
        None if live.len() > 1 => {
            let names = live.iter().map(|s| json!(s.project)).collect();
            return Err(ToolError::new(
                Code::ProjectRequired,
                "several Burps of this target run; pick one with burp_project",
            )
            .param("burp_project")
            .allowed(names));
        }
        None => live.pop().ok_or_else(|| {
            ToolError::new(
                Code::BurpNotRunning,
                "no Burp of this target is running; start one with burp_up",
            )
            .see(json!({"do": "burp_up"}))
        })?,
    };
    let Some(proxy) = chosen.proxy else {
        return Err(ToolError::new(
            Code::Internal,
            "a live Burp without a proxy listener",
        ));
    };
    let note = format!(
        "proxy set to Burp's listener http://{proxy} (project {}); HTTPS needs Burp's CA trusted in this browser",
        chosen.project
    );
    Ok((format!("http://{proxy}"), note))
}
