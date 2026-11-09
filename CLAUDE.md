# Raijin

Burp Suite extension: MCP server (`io.bitbytelab.raijin.{core,transport,bridge,tools,ui}`) plus the Turbo scripting engine (`io.bitbytelab.raijin.turbo`).

## Conventions
- **All source is Kotlin.** No `.java` files.
- Namespace `io.bitbytelab.raijin`; Gradle group `io.bitbytelab`.
- **Montoya API only** (compileOnly). No legacy Burp extender API (`IBurpExtender`, `callbacks`, `helpers`).
- **No MCP auth token.** Protection is loopback bind + Host/Origin checks (`transport/SecurityConfig.kt`).
- UI colours come from Burp (`ui/RaijinTheme.kt`); never hardcode backgrounds/foregrounds. Semantic colours (success/error/...) live in `RaijinTheme` with dark and light variants.
- Use neutral wording in user-facing text: "run", not "attack". Exceptions: "single-packet attack", security threat descriptions.

## Build
```bash
./gradlew build        # needs a JDK 21 toolchain; output build/libs/raijin.jar
./gradlew test
```

## Layout
- `bridge/*Bridge.kt` wrap Burp APIs; `tools/<area>/*Tools.kt` register MCP tools one by one onto a scratch server, and `tools/ToolConsolidation.kt` (the group table) folds them into `action` tools on the real one (add a new tool there: `GROUPS` or `KEEP`; a test fails otherwise); `transport/ToolRegistry.kt` wires them.
- Skills (usage guides served over MCP): markdown in `src/main/resources/skills/`, listed in `skills/SkillCatalog.kt`, exposed by `tools/skills/SkillTools.kt` (tool `skill`) and as `raijin://skills/<name>` resources.
- Turbo MCP tools: `tools/turbo/TurboTools.kt` over `bridge/TurboBridge.kt`; runs are shared with the GUI via `TurboModule.runManager`.
- Jython scripts reach engine classes through the injected `turbo` object (`turbo/TurboPython.kt`); `import io...` does not work in Jython (it resolves `io` to Python's stdlib).
- Turbo user docs ship as resources in `src/main/resources/turbo-docs/`; dev notes are in `docs/dev/`.
