# Raijin

Burp Suite extension: MCP server (`io.bitbytelab.raijin.{core,transport,bridge,tools,ui}`) plus the Turbo scripting engine (`io.bitbytelab.raijin.turbo`).

## Conventions
- **Extension source is Kotlin** (no `.java`); the `raijin` CLI in `cli/` is Rust.
- Namespace `io.bitbytelab.raijin`; Gradle group `io.bitbytelab`.
- **Montoya API only** (compileOnly). No legacy Burp extender API (`IBurpExtender`, `callbacks`, `helpers`).
- **No MCP auth token on loopback.** Protection is loopback bind + Host/Origin checks (`transport/SecurityConfig.kt`). Exception: a non-loopback bind (operator opt-in `mcp_allow_remote_bind`) or `mcp_require_auth` requires a bearer token, plus optional source-IP and Host allowlists (`transport/RemoteAccess.kt`), enforced by `installLocalhostSecurity` on all three listeners. Details: `docs/dev/ultra/SECURITY.md`.
- **Pentest tool: never restrict what can be sent.** Malformed headers, CR/LF, raw bytes and odd Content-Length values must reach the wire as written. Use `safety/RequestHygiene.kt` for wire encoding and Content-Length, `safety/SafeRegex.kt` for every user-supplied regex.
- Tool handlers return through `toolJsonResult` / `toolError` (`tools/ToolResultHelpers.kt`, sets `isError`) and read arguments with `core/JsonHelpers.kt`; closed parameters declare an `enum` (`EnumValidation`). Oversized limits are clamped and reported (`asClampedInt`, `<param>_clamped_to`), not rejected.
- UI colours come from Burp (`ui/RaijinTheme.kt`); never hardcode backgrounds/foregrounds. Semantic colours (success/error/...) live in `RaijinTheme` with dark and light variants. Slow UI work runs on `ui/UiTasks.kt`, off the EDT, and whatever the tab starts is released on unload through `ui/Disposer.kt`.
- Use neutral wording in user-facing text: "run", not "attack". Exceptions: "single-packet attack", security threat descriptions.

## Build
```bash
./gradlew build        # needs a JDK 25 toolchain; output build/libs/raijin.jar
./gradlew test
```

## Layout
- `bridge/*Bridge.kt` wrap Burp APIs; `tools/<area>/*Tools.kt` register MCP tools one by one onto a scratch server, and `tools/ToolConsolidation.kt` (the group table) folds them into `action` tools on the real one (add a new tool there: `GROUPS` or `KEEP`, plus one domain in `tools/ToolDomains.kt` and a regenerated `catalog/tools.json`; tests fail otherwise); `transport/ToolRegistry.kt` wires them.
- MCP SDK `io.modelcontextprotocol:kotlin-sdk-server` 0.16 (built with Kotlin 2.4 and Ktor 3.5; Raijin runs Ktor 3.6). Each listener (9876, 9877) serves one shared `Server` over Streamable HTTP at `/mcp` (`ConnectionInfo.MCP_PATH`, `installStreamableHttp`) and legacy SSE at `/` (`transport/McpServerManager.kt`). SDK handlers take a `ClientConnection` receiver: call a stored one as `handler(this, request)`.
- Skills (usage guides served over MCP): markdown in `src/main/resources/skills/`, listed in `skills/SkillCatalog.kt`, exposed as MCP prompts under their kebab-case `name` (`http-testing`, `overview`, ...; `transport/PromptRegistry.kt`, no `_skill` suffix). Claude Code and omp list prompts as slash commands and only ask when `McpServerManager.serverCapabilities()` declares `prompts`. Also served as `skill://<name>/SKILL.md` resources (`transport/ResourceRegistry.kt`) and via `search_skills` / `load_skill` tools (`tools/skills/SkillTools.kt`).
- Turbo MCP tools: `tools/turbo/TurboTools.kt` over `bridge/TurboBridge.kt`; runs are shared with the GUI via `TurboModule.runManager`.
- Jython scripts reach engine classes through the injected `turbo` object (`turbo/TurboPython.kt`); `import io...` does not work in Jython (it resolves `io` to Python's stdlib).
- Turbo user docs ship as resources in `src/main/resources/turbo-docs/`; every file there is a `turbo_docs(action=get_docs)` topic (`McpResourceHandlers.docTopics`; a test fails if the two differ). Dev notes are in `docs/dev/`.
- `cli/`: Cargo workspace for the `raijin` CLI (`crates/raijin-cli`: per-target Burp launch, `raijin mcp` stdio gateway, offline `.burp` history) and vendored `crates/amber` (see NOTICE). Workspace version equals `build.gradle.kts` `version`. The gateway reads `catalog/tools.json` from the jar; regenerate it with `RAIJIN_UPDATE_CATALOG=1 ./gradlew test --tests '*ToolCatalogTest'`. Check: `cargo test --locked && cargo clippy --locked -- -D warnings` in `cli/`.
