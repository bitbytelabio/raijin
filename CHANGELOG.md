# Changelog

## 1.1.0

- GraphQL: `fingerprint_engine` mode detects the backend engine (Apollo, Hasura, graphql-java, and 25+ others) from malformed-query error signatures.
- GraphQL: `bruteforce_schema` mode reconstructs the schema from "did you mean"/type-mismatch error messages when introspection is disabled, via wordlist-driven probing (`bucket_size`, `depth_limit`, `bruteforce_arguments`).
- GraphQL: every mode accepts `headers` and `auto_headers` (reuse identity headers from the most recent Proxy-history request to the target host).
- GraphQL: `query_templates`/`poi_scan`/`cycles_scan` cache the fetched schema for 10 minutes, bypassable with `refresh_schema`.

## 1.0.0

First release of Raijin: BurpMCP-Ultra 2.3.2 and Turbo Intruder 2.0.1 merged into one extension.

- One MCP server named `burpsuite`: Streamable HTTP at `http://127.0.0.1:9876/mcp` (also 9877), legacy SSE at `/`, dashboard on 9878.
- About 40 tools covering 160+ operations; families of operations are one tool with an `action` parameter ([mapping](docs/dev/tool-consolidation.md)).
- Turbo exposed as `turbo_run` and `turbo_docs`; runs from the script dialog and from agents share one run list (Turbo sub-tab).
- Eight built-in skills, served as MCP prompts (`*_skill`), `skill://<name>/SKILL.md` resources and the `search_skills` / `load_skill` tools.
- JWT key ring (`jwt_keys`, JWT sub-tab) and extended JWT probe modes: sign/verify with ring keys, JWE, embedded JWK, empty HMAC, psychic signatures, `jku`/`x5u`.
- Decoder accepts several data items at once; Montoya API 2026.7.
- UI follows Burp's theme (dark and light); dashboard syncs to Burp's colours.
- Removed: MCP bearer token, Turbo's Jetty MCP server and standalone mode, `albinowaxUtils-all.jar`, the legacy Burp extender API, Jython `callbacks`/`helpers`.
- Namespace `io.bitbytelab.raijin`; Java 21 bytecode; requires Burp Suite 2026.2 or newer.

Earlier history: [BurpMCP-Ultra](docs/dev/ultra/CHANGELOG-burpmcp-ultra.md).
