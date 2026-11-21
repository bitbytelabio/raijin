//! `history endpoints` / `history_endpoints`: the API map, one group per host + method + path.

use std::collections::{BTreeMap, BTreeSet};

use anyhow::Result;
use serde::Serialize;
use serde_json::Value;

use super::source::{self, Exchange, Kinds, Load};
use super::{Filters, Selection, Warning, header_value, split_message};
use crate::config::Target;

const DEFAULT_LIMIT: usize = 500;
const MAX_LIMIT: usize = 5000;

#[derive(Debug, Clone, Default, clap::Args, serde::Deserialize, schemars::JsonSchema)]
#[serde(default)]
pub struct EndpointsParams {
    #[command(flatten)]
    #[serde(flatten)]
    pub selection: Selection,
    #[command(flatten)]
    #[serde(flatten)]
    pub filters: Filters,
    /// Groups to return (default 500).
    #[arg(short = 'n', long)]
    pub limit: Option<usize>,
}

#[derive(Debug, Default, Serialize)]
pub struct Endpoint {
    pub host: String,
    pub method: String,
    pub path: String,
    pub count: u64,
    pub statuses: BTreeSet<u64>,
    pub query_params: BTreeSet<String>,
    pub body_params: BTreeSet<String>,
    pub projects: BTreeSet<String>,
}

#[derive(Debug, Serialize)]
pub struct EndpointsResult {
    pub total: usize,
    pub endpoints: Vec<Endpoint>,
    pub warnings: Vec<Warning>,
}

type Key = (String, String, String);

pub fn run(target: &Target, params: &EndpointsParams) -> Result<EndpointsResult> {
    let sources = source::discover(target, &params.selection)?;
    let load = Load {
        request: true,
        response: false,
    };
    let (per, warnings) = source::par_map(&sources, |s, notes| {
        let mut groups: BTreeMap<Key, Endpoint> = BTreeMap::new();
        source::for_each_exchange(s, &params.filters, Kinds::ALL, load, notes, |ex| {
            add(&mut groups, &ex);
            Ok(())
        })?;
        Ok(groups)
    });
    let mut merged: BTreeMap<Key, Endpoint> = BTreeMap::new();
    for groups in per {
        for (key, e) in groups {
            let into = merged.entry(key).or_insert_with(|| Endpoint {
                host: e.host.clone(),
                method: e.method.clone(),
                path: e.path.clone(),
                ..Endpoint::default()
            });
            into.count += e.count;
            into.statuses.extend(e.statuses);
            into.query_params.extend(e.query_params);
            into.body_params.extend(e.body_params);
            into.projects.extend(e.projects);
        }
    }
    let total = merged.len();
    let limit = params.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
    let endpoints = merged.into_values().take(limit).collect();
    Ok(EndpointsResult {
        total,
        endpoints,
        warnings,
    })
}

fn add(groups: &mut BTreeMap<Key, Endpoint>, ex: &Exchange) {
    let Some(url) = ex.row.url.as_deref().and_then(|u| url::Url::parse(u).ok()) else {
        return;
    };
    let host = ex
        .row
        .host
        .clone()
        .or_else(|| url.host_str().map(str::to_owned))
        .unwrap_or_default();
    let method = ex.row.method.clone().unwrap_or_default();
    let key = (host.clone(), url.path().to_owned(), method.clone());
    let entry = groups.entry(key).or_insert_with(|| Endpoint {
        host,
        method,
        path: url.path().to_owned(),
        ..Endpoint::default()
    });
    entry.count += 1;
    if let Some(status) = ex.row.status {
        entry.statuses.insert(status);
    }
    entry
        .query_params
        .extend(url.query_pairs().map(|(k, _)| k.into_owned()));
    if let Some(request) = &ex.request {
        entry.body_params.extend(body_params(request));
    }
    entry.projects.insert(ex.row.project.clone());
}

/// Form keys of an urlencoded body, or top-level keys of a JSON object body.
fn body_params(request: &[u8]) -> Vec<String> {
    let body = split_message(request).1;
    if body.is_empty() {
        return Vec::new();
    }
    let content_type = header_value(request, "content-type")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if content_type.contains("application/x-www-form-urlencoded") {
        return url::form_urlencoded::parse(body)
            .map(|(k, _)| k.into_owned())
            .collect();
    }
    match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(map)) => map.keys().cloned().collect(),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn body_params_cover_forms_and_json() {
        let form = b"POST / HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\na=1&b%5B%5D=2";
        assert_eq!(body_params(form), ["a", "b[]"]);
        let json = b"POST / HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"name\":\"x\",\"n\":{\"deep\":1}}";
        assert_eq!(body_params(json), ["name", "n"]);
        assert_eq!(
            body_params(b"GET / HTTP/1.1\r\n\r\n"),
            [] as [std::string::String; 0]
        );
    }
}
