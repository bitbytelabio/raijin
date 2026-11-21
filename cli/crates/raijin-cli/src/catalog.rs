//! Raijin's tool catalog (`catalog/tools.json` in the jar, written by `ToolDomains.catalogJson`) and skills.

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
}

#[derive(Debug, Clone, Deserialize)]
pub struct Catalog {
    pub schema_version: u32,
    #[serde(default)]
    pub excluded: Vec<String>,
    pub domains: Vec<Domain>,
    pub tools: Vec<ToolSpec>,
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

#[derive(Debug, Clone, Serialize)]
pub struct Skill {
    pub name: String,
    pub description: String,
    /// `raijin` (shipped in the jar) or `cli` (embedded in this binary).
    pub source: &'static str,
    #[serde(skip)]
    pub body: String,
}

impl Skill {
    /// Parses `---\nname: …\ndescription: …\n---` front matter; the name falls back to `fallback`.
    pub fn parse(markdown: &str, fallback: &str, source: &'static str) -> Self {
        let mut name = fallback.to_owned();
        let mut description = String::new();
        if let Some(rest) = markdown.strip_prefix("---\n")
            && let Some(end) = rest.find("\n---")
        {
            for line in rest[..end].lines() {
                if let Some((key, value)) = line.split_once(':') {
                    match key.trim() {
                        "name" => value.trim().clone_into(&mut name),
                        "description" => value.trim().clone_into(&mut description),
                        _ => {}
                    }
                }
            }
        }
        Self {
            name,
            description,
            source,
            body: markdown.to_owned(),
        }
    }
}

/// Skills embedded in the CLI: the gateway loop and the offline review playbook.
pub fn cli_skills() -> Vec<Skill> {
    vec![
        Skill::parse(
            include_str!("skills/raijin-gateway.md"),
            "raijin-gateway",
            "cli",
        ),
        Skill::parse(
            include_str!("skills/offline-history.md"),
            "offline-history",
            "cli",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn front_matter_gives_name_and_description() {
        let skill = Skill::parse(
            "---\nname: overview\ndescription: Start here: map.\n---\n# x\n",
            "f",
            "raijin",
        );
        assert_eq!(skill.name, "overview");
        assert_eq!(skill.description, "Start here: map.");
    }

    #[test]
    fn embedded_skills_have_front_matter() {
        let names: Vec<_> = cli_skills()
            .into_iter()
            .map(|s| (s.name, s.description.is_empty()))
            .collect();
        assert_eq!(
            names,
            [
                ("raijin-gateway".to_owned(), false),
                ("offline-history".to_owned(), false)
            ]
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
    }
}
