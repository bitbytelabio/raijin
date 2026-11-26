//! Raijin's tool catalog (`catalog/tools.json` in the jar, written by `ToolDomains.catalogJson`) and the
//! playbooks (skills) bundled in this binary: `src/skills/<name>/SKILL.md` plus `references/*.md`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

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
