//! Raijin's tool catalog (`catalog/tools.json` in the jar, written by `ToolDomains.catalogJson`) and the
//! playbooks (skills) bundled in this binary: `src/skills/<name>/SKILL.md` plus `references/*.md`.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::mcp::error::norm;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Domain {
    pub name: String,
    pub description: String,
    pub notes: String,
    pub skill: String,
    pub tools: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ToolSpec {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(rename = "inputSchema")]
    pub input_schema: Value,
    /// MCP tool annotations (`readOnlyHint`, `destructiveHint`, ...), when the catalog has them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub annotations: Option<Value>,
    /// A `run` call that works, for an ungrouped tool.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub example: Option<Value>,
    /// A grouped tool's actions, each with its own parameters and example.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub actions: BTreeMap<String, ActionSpec>,
}

/// What one action of a grouped tool takes.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ActionSpec {
    pub params: Vec<String>,
    pub required: Vec<String>,
    /// A `run` call that works: `{"do":"<tool>.<action>", ...}`.
    pub example: Value,
    /// The action's own description (the member tool's), when the catalog has it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The action's own parameter schemas (not the group's merged ones), when the catalog has them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub properties: Option<serde_json::Map<String, Value>>,
}

/// What a call name means in the catalog.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Resolved {
    /// The published tool, the action to add for a grouped call, and a note when the name was not
    /// written exactly.
    Found {
        tool: String,
        action: Option<String>,
        note: Option<String>,
    },
    /// Nothing matches; up to three close call names.
    NotFound { did_you_mean: Vec<String> },
}

/// Hash names that mean `util.hash` with an algorithm (`sha256`), as the extension reads them.
const HASHES: [(&str, &str); 5] = [
    ("md5", "MD5"),
    ("sha1", "SHA_1"),
    ("sha256", "SHA_256"),
    ("sha384", "SHA_384"),
    ("sha512", "SHA_512"),
];

/// The `util.hash` algorithm a hash name (`sha256`, `util.SHA-256`) means.
pub fn hash_algorithm(name: &str) -> Option<&'static str> {
    let key: String = name
        .chars()
        .filter(|c| !matches!(c, '-' | '_' | '.' | ' '))
        .flat_map(char::to_lowercase)
        .collect();
    let key = key.strip_prefix("util").unwrap_or(&key);
    HASHES.iter().find(|(k, _)| *k == key).map(|(_, a)| *a)
}

/// A grouped member's old tool name: the published `tool` and the `action` that replaces it.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Alias {
    pub tool: String,
    pub action: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Catalog {
    pub schema_version: u32,
    pub domains: Vec<Domain>,
    pub tools: Vec<ToolSpec>,
    /// Member name (`scope_list`) -> grouped call (`scope`, action `list`).
    #[serde(default)]
    pub aliases: BTreeMap<String, Alias>,
}

impl Catalog {
    pub fn parse(text: &str) -> anyhow::Result<Self> {
        let catalog: Self = serde_json::from_str(text)?;
        anyhow::ensure!(
            catalog.schema_version == 1,
            "unsupported catalog schema_version {}",
            catalog.schema_version
        );
        Ok(catalog)
    }

    pub fn tool(&self, name: &str) -> Option<&ToolSpec> {
        self.tools.iter().find(|t| t.name == name)
    }

    /// The published tool `name` means, with the action to add for a grouped member: an exact tool
    /// name, an alias (`scope_list` -> `scope`, `list`) or `group.action` (`scope.list`).
    pub fn resolve(&self, name: &str) -> Option<(String, Option<String>)> {
        let name = name.trim();
        if self.tool(name).is_some() {
            return Some((name.to_owned(), None));
        }
        if let Some(alias) = self.aliases.get(name) {
            return Some((alias.tool.clone(), Some(alias.action.clone())));
        }
        let (group, action) = name.split_once('.')?;
        self.tool(group)?;
        Some((group.to_owned(), Some(action.to_owned())))
    }

    /// Every call name: tools, `tool.action` and old member names.
    pub fn call_names(&self) -> Vec<String> {
        let mut names: Vec<String> = self.tools.iter().map(|t| t.name.clone()).collect();
        for tool in &self.tools {
            names.extend(tool.actions.keys().map(|a| format!("{}.{a}", tool.name)));
        }
        names.extend(self.aliases.keys().cloned());
        names
    }

    /// The names a "did you mean" offers: tools and `tool.action`, not old member names.
    pub fn suggestion_names(&self) -> Vec<String> {
        self.tools
            .iter()
            .map(|t| t.name.clone())
            .chain(
                self.tools
                    .iter()
                    .flat_map(|t| t.actions.keys().map(move |a| format!("{}.{a}", t.name))),
            )
            .collect()
    }

    /// What `name` means as the extension resolves it (`ToolNames.resolve`): an exact tool, alias or
    /// `tool.action`, the same with other case and separators, or a hash name (`sha256`). Used to
    /// answer an unknown name while Burp is down.
    pub fn resolve_call(&self, name: &str) -> Resolved {
        let trimmed = name.trim();
        let found = |tool: String, action: Option<String>, note: Option<String>| Resolved::Found {
            tool,
            action,
            note,
        };
        if let Some((tool, action)) = self.resolve(trimmed) {
            match &action {
                Some(a) if self.has_action(&tool, a) => return found(tool, action, None),
                None => return found(tool, None, None),
                Some(a) => {
                    if let Some(real) = self.action_named(&tool, a) {
                        let note = format!("ran '{trimmed}' as {tool}.{real}");
                        return found(tool, Some(real), Some(note));
                    }
                }
            }
        }
        let wanted = norm(trimmed);
        let hits: BTreeSet<(String, Option<String>)> = self
            .call_names()
            .iter()
            .filter(|n| norm(n) == wanted)
            .filter_map(|n| self.resolve(n))
            .collect();
        if hits.len() == 1
            && let Some((tool, action)) = hits.into_iter().next()
        {
            let call = action
                .as_ref()
                .map_or_else(|| tool.clone(), |a| format!("{tool}.{a}"));
            return found(tool, action, Some(format!("ran '{trimmed}' as {call}")));
        }
        if self.tool("util").is_some()
            && let Some(algorithm) = hash_algorithm(trimmed)
        {
            let note = format!("ran '{trimmed}' as util.hash with algorithm {algorithm}");
            return found("util".to_owned(), Some("hash".to_owned()), Some(note));
        }
        let names = self.suggestion_names();
        let did_you_mean = crate::util::suggest(trimmed, names.iter().map(String::as_str), 3)
            .into_iter()
            .map(str::to_owned)
            .collect();
        Resolved::NotFound { did_you_mean }
    }

    /// Whether calling `tool` with `action` may remove or stop something, as the extension judges
    /// it (`ToolNames.destructive`): an action word such as `delete` or `shutdown` for a grouped
    /// call, else the tool's `destructiveHint`.
    pub fn destructive(&self, tool: &str, action: Option<&str>) -> bool {
        const WORDS: [&str; 10] = [
            "delete", "remove", "clear", "shutdown", "stop", "kill", "reset", "drop", "purge",
            "import",
        ];
        match action {
            Some(action) if self.tool(tool).is_some_and(|t| !t.actions.is_empty()) => {
                action.split('_').any(|w| WORDS.contains(&w))
            }
            _ => self.tool(tool).is_some_and(|t| {
                t.annotations
                    .as_ref()
                    .and_then(|a| a.get("destructiveHint"))
                    .and_then(Value::as_bool)
                    == Some(true)
            }),
        }
    }

    fn has_action(&self, tool: &str, action: &str) -> bool {
        self.tool(tool)
            .is_some_and(|t| t.actions.is_empty() || t.actions.contains_key(action))
    }

    /// The action of grouped `tool` that `raw` means: another case or separator, the tool prefix
    /// (`scope_list`), the member name, or a hash name for `util`.
    fn action_named(&self, tool: &str, raw: &str) -> Option<String> {
        let spec = self.tool(tool)?;
        let a = norm(raw);
        let bare = a.strip_prefix(&format!("{tool}_")).unwrap_or(&a).to_owned();
        if let Some(hit) = spec.actions.keys().find(|k| **k == a || **k == bare) {
            return Some(hit.clone());
        }
        if let Some(alias) = self.aliases.get(&a).filter(|alias| alias.tool == tool) {
            return Some(alias.action.clone());
        }
        (tool == "util" && hash_algorithm(raw).is_some()).then(|| "hash".to_owned())
    }

    pub fn domain(&self, name: &str) -> Option<&Domain> {
        self.domains.iter().find(|d| d.name == name)
    }

    /// The domain listing `tool`.
    pub fn domain_of(&self, tool: &str) -> Option<&Domain> {
        self.domains
            .iter()
            .find(|d| d.tools.iter().any(|t| t == tool))
    }
}

/// File name of a skill's entry point inside its folder.
pub const SKILL_FILE: &str = "SKILL.md";

/// The bundled skills, in the order every listing uses (prompts, skills, resources, `guide`).
const BUNDLED: &[(&str, &str)] = &[
    ("overview", include_str!("skills/overview/SKILL.md")),
    ("http-testing", include_str!("skills/http-testing/SKILL.md")),
    (
        "proxy-traffic",
        include_str!("skills/proxy-traffic/SKILL.md"),
    ),
    ("recon-probes", include_str!("skills/recon-probes/SKILL.md")),
    (
        "scanner-audit",
        include_str!("skills/scanner-audit/SKILL.md"),
    ),
    (
        "turbo-scripting",
        include_str!("skills/turbo-scripting/SKILL.md"),
    ),
    (
        "collaborator-oob",
        include_str!("skills/collaborator-oob/SKILL.md"),
    ),
    (
        "findings-reporting",
        include_str!("skills/findings-reporting/SKILL.md"),
    ),
    (
        "offline-history",
        include_str!("skills/offline-history/SKILL.md"),
    ),
];

/// The other files of bundled skills: (skill, path inside its folder, body).
const BUNDLED_FILES: &[(&str, &str, &str)] = &[
    (
        "overview",
        "references/tool-map.md",
        include_str!("skills/overview/references/tool-map.md"),
    ),
    (
        "http-testing",
        "references/sending.md",
        include_str!("skills/http-testing/references/sending.md"),
    ),
    (
        "http-testing",
        "references/pipeline.md",
        include_str!("skills/http-testing/references/pipeline.md"),
    ),
    (
        "http-testing",
        "references/fuzz-race.md",
        include_str!("skills/http-testing/references/fuzz-race.md"),
    ),
    (
        "http-testing",
        "references/rules-sessions.md",
        include_str!("skills/http-testing/references/rules-sessions.md"),
    ),
    (
        "proxy-traffic",
        "references/intercept-rules.md",
        include_str!("skills/proxy-traffic/references/intercept-rules.md"),
    ),
    (
        "proxy-traffic",
        "references/websocket.md",
        include_str!("skills/proxy-traffic/references/websocket.md"),
    ),
    (
        "recon-probes",
        "references/recon.md",
        include_str!("skills/recon-probes/references/recon.md"),
    ),
    (
        "recon-probes",
        "references/probes.md",
        include_str!("skills/recon-probes/references/probes.md"),
    ),
    (
        "recon-probes",
        "references/authz.md",
        include_str!("skills/recon-probes/references/authz.md"),
    ),
    (
        "recon-probes",
        "references/jwt.md",
        include_str!("skills/recon-probes/references/jwt.md"),
    ),
    (
        "scanner-audit",
        "references/custom-checks.md",
        include_str!("skills/scanner-audit/references/custom-checks.md"),
    ),
];

/// One bundled skill: `files[0]` is (`SKILL.md`, its text with front matter), then its references.
#[derive(Debug, Clone)]
pub struct Skill {
    pub name: &'static str,
    /// The front matter's `description`.
    pub description: String,
    pub files: Vec<(&'static str, &'static str)>,
}

impl Skill {
    /// `SKILL.md` as shipped, front matter included.
    pub fn raw(&self) -> &'static str {
        self.files[0].1
    }

    /// `SKILL.md` without its front matter.
    pub fn body(&self) -> &'static str {
        front_matter(self.raw()).2
    }

    /// `skill://<name>/<path>`.
    pub fn uri(&self, path: &str) -> String {
        format!("skill://{}/{path}", self.name)
    }

    /// The body of the file at `path` inside the skill's folder (`SKILL.md`, `references/x.md`).
    pub fn file(&self, path: &str) -> Option<&'static str> {
        self.files.iter().find(|(p, _)| *p == path).map(|(_, b)| *b)
    }
}

/// Every bundled skill, in [`BUNDLED`] order.
pub fn skills() -> Vec<Skill> {
    BUNDLED
        .iter()
        .map(|&(name, raw)| {
            let mut files = vec![(SKILL_FILE, raw)];
            files.extend(
                BUNDLED_FILES
                    .iter()
                    .filter(|(skill, ..)| *skill == name)
                    .map(|&(_, path, body)| (path, body)),
            );
            Skill {
                name,
                description: front_matter(raw).1,
                files,
            }
        })
        .collect()
}

/// Splits `---\nname: …\ndescription: …\n---` front matter off `raw`: (name, description, body).
/// Without front matter the name is `None`, the description empty and the body all of `raw`.
fn front_matter(raw: &str) -> (Option<&str>, String, &str) {
    let Some(rest) = raw.strip_prefix("---\n") else {
        return (None, String::new(), raw);
    };
    let Some(end) = rest.find("\n---") else {
        return (None, String::new(), raw);
    };
    let mut name = None;
    let mut description = String::new();
    for line in rest[..end].lines() {
        if let Some((key, value)) = line.split_once(':') {
            match key.trim() {
                "name" => name = Some(value.trim()),
                "description" => value.trim().clone_into(&mut description),
                _ => {}
            }
        }
    }
    let after = &rest[end + "\n---".len()..];
    let body = after.strip_prefix('\n').unwrap_or(after);
    (name, description, body)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::path::Path;

    use super::*;

    #[test]
    fn front_matter_gives_name_and_description() {
        let (name, description, body) =
            front_matter("---\nname: overview\ndescription: Start here: map.\n---\n# x\n");
        assert_eq!(name, Some("overview"));
        assert_eq!(description, "Start here: map.");
        assert_eq!(body, "# x\n");
        assert_eq!(
            front_matter("# no front matter"),
            (None, String::new(), "# no front matter")
        );
    }

    #[test]
    fn embedded_skills_have_front_matter() {
        for (dir, raw) in BUNDLED {
            let (name, description, _) = front_matter(raw);
            assert_eq!(name, Some(*dir), "{dir}: front matter name");
            assert!(!description.is_empty(), "{dir}: empty description");
            assert!(
                description.len() <= 200,
                "{dir}: description over 200 chars"
            );
        }
        assert_eq!(skills()[0].name, "overview");
        assert!(skills()[0].body().starts_with("# "));
    }

    fn markdown_under(dir: &Path, root: &Path, out: &mut BTreeSet<String>) {
        for entry in std::fs::read_dir(dir).expect("skills dir") {
            let path = entry.expect("entry").path();
            if path.is_dir() {
                markdown_under(&path, root, out);
            } else if path.extension().is_some_and(|e| e == "md") {
                let rel = path.strip_prefix(root).expect("under root");
                out.insert(rel.to_string_lossy().replace('\\', "/"));
            }
        }
    }

    #[test]
    fn every_bundled_file_is_listed() {
        let root = Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/src/skills"));
        let mut on_disk = BTreeSet::new();
        markdown_under(root, root, &mut on_disk);
        let listed: BTreeSet<String> = BUNDLED
            .iter()
            .map(|(name, _)| format!("{name}/{SKILL_FILE}"))
            .chain(
                BUNDLED_FILES
                    .iter()
                    .map(|(name, path, _)| format!("{name}/{path}")),
            )
            .collect();
        assert_eq!(
            on_disk, listed,
            "src/skills and BUNDLED/BUNDLED_FILES differ"
        );
    }

    #[test]
    fn the_parameter_synonyms_match_the_extension() {
        let text = include_str!("../../../../src/main/resources/catalog/tools.json");
        let catalog: Value = serde_json::from_str(text).expect("catalog json");
        let shipped: Vec<Vec<String>> =
            serde_json::from_value(catalog["param_synonyms"].clone()).expect("param_synonyms");
        let ours: Vec<Vec<String>> = crate::mcp::args::PARAM_SYNONYMS
            .iter()
            .map(|g| g.iter().map(|s| (*s).to_owned()).collect())
            .collect();
        assert_eq!(shipped, ours);
    }

    #[test]
    fn the_boolean_words_match_the_extension() {
        let text = include_str!("../../../../src/main/resources/catalog/tools.json");
        let catalog: Value = serde_json::from_str(text).expect("catalog json");
        let shipped: BTreeMap<String, Vec<String>> =
            serde_json::from_value(catalog["boolean_words"].clone()).expect("boolean_words");
        let words = |w: &[&str]| w.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        let ours = BTreeMap::from([
            ("true".to_owned(), words(crate::mcp::args::TRUE_WORDS)),
            ("false".to_owned(), words(crate::mcp::args::FALSE_WORDS)),
        ]);
        assert_eq!(shipped, ours);
    }

    #[test]
    fn calls_resolve_as_the_extension_resolves_them() {
        let text = include_str!("../../../../src/main/resources/catalog/tools.json");
        let catalog = Catalog::parse(text).expect("catalog parses");
        let found = |name: &str| match catalog.resolve_call(name) {
            Resolved::Found { tool, action, .. } => Some((tool, action)),
            Resolved::NotFound { .. } => None,
        };
        let util = |a: &str| Some(("util".to_owned(), Some(a.to_owned())));
        assert_eq!(found("util.hash"), util("hash"));
        assert_eq!(found("util_hash"), util("hash"));
        assert_eq!(found("Util.Hash"), util("hash"));
        assert_eq!(found("sha256"), util("hash"));
        assert_eq!(found("util.sha256"), util("hash"));
        assert_eq!(
            found("proxy_history"),
            Some(("proxy_history".to_owned(), None))
        );
        assert_eq!(found("nope_tool"), None);
        assert_eq!(found("scope.chek"), None);
        let Resolved::NotFound { did_you_mean } = catalog.resolve_call("scope.chek") else {
            panic!("scope.chek is not a call");
        };
        assert_eq!(
            did_you_mean.first().map(String::as_str),
            Some("scope.check")
        );
        assert!(catalog.destructive("burp", Some("shutdown")));
        assert!(!catalog.destructive("scope", Some("check")));
    }

    #[test]
    fn the_repo_catalog_parses() {
        let text = include_str!("../../../../src/main/resources/catalog/tools.json");
        let catalog = Catalog::parse(text).expect("catalog parses");
        assert_eq!(catalog.domains.len(), 10);
        assert!(catalog.tool("http_send_request").is_some());
        assert_eq!(
            catalog.domain_of("collaborator").map(|d| d.name.as_str()),
            Some("oob")
        );
        for domain in &catalog.domains {
            assert!(
                skills().iter().any(|s| s.name == domain.skill),
                "{}: no bundled skill {}",
                domain.name,
                domain.skill
            );
        }
    }
}
