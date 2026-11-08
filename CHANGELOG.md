# Changelog

## 1.0.0

First release of Raijin: BurpMCP-Ultra 2.3.2 and Turbo Intruder 2.0.1 merged into one extension.

- One MCP server (`raijin`, SSE on 9876/9877) with Turbo exposed as `turbo_*` tools.
- Turbo runs from the script dialog and from agents share one run list (Turbo sub-tab).
- UI follows Burp's theme (dark and light); dashboard syncs to Burp's colours.
- Removed: MCP bearer token, Turbo's Jetty MCP server and standalone mode, `albinowaxUtils-all.jar`, the legacy Burp extender API, Jython `callbacks`/`helpers`.
- Namespace `io.bitbytelab.raijin`; Java 21 bytecode.

Earlier history: [BurpMCP-Ultra](docs/dev/ultra/CHANGELOG-burpmcp-ultra.md).
