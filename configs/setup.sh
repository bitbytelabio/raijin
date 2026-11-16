#!/bin/bash
# Raijin Setup Script
# Builds the extension, optionally installs the Caddy proxy, and prints the MCP client config.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=========================================="
echo " Raijin Setup"
echo "=========================================="

# Step 1: Build (needs a JDK 21 toolchain; also runs the tests)
echo ""
echo "[1/4] Building extension (./gradlew build)..."
cd "$PROJECT_DIR"
./gradlew build
JAR_PATH="$PROJECT_DIR/build/libs/raijin.jar"
if [ ! -f "$JAR_PATH" ]; then
    echo "  Build finished but $JAR_PATH is missing." >&2
    exit 1
fi
echo "  Built: $JAR_PATH"

# Step 2: Caddy (optional, Profile A of configs/Caddyfile: a local proxy on 127.0.0.1:9900-9902)
echo ""
echo "[2/4] Caddy reverse proxy (optional)"
MCP_URL="http://127.0.0.1:9876/mcp"
DASHBOARD_URL="http://127.0.0.1:9878"
if command -v caddy &>/dev/null; then
    read -p "  Configure Caddy? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if command -v systemctl &>/dev/null; then
            sudo cp "$SCRIPT_DIR/Caddyfile" /etc/caddy/Caddyfile
            sudo systemctl restart caddy
            echo "  Caddy configured and restarted"
        else
            echo "  No systemd here; start Caddy yourself with:"
            echo "    caddy run --config $SCRIPT_DIR/Caddyfile"
        fi
        MCP_URL="http://127.0.0.1:9900/mcp"
        DASHBOARD_URL="http://127.0.0.1:9902"
    fi
else
    echo "  Caddy not installed. Using direct connection."
    echo "  Install with: sudo apt install caddy  (or: brew install caddy)"
fi

# Step 3: Claude Code MCP config
echo ""
echo "[3/4] Claude Code MCP configuration"
CLAUDE_CONFIG="$HOME/.claude.json"
if [ -f "$CLAUDE_CONFIG" ]; then
    echo "  Found existing $CLAUDE_CONFIG"
    echo "  Add this to your mcpServers section:"
else
    echo "  Create $CLAUDE_CONFIG with:"
fi
echo ""
echo "  {"
echo "    \"mcpServers\": {"
echo "      \"burpsuite\": {"
echo "        \"type\": \"http\","
echo "        \"url\": \"$MCP_URL\""
echo "      }"
echo "    }"
echo "  }"
echo ""
echo "  NOTE: Streamable HTTP at /mcp (legacy SSE still answers at '/'). On loopback no token is needed."
echo "  Remote / VM access (bearer token, IP allowlist, SSH tunnel, Caddy TLS): docs/dev/ultra/SECURITY.md"
echo "  Or, with Claude Code:  claude mcp add --transport http burpsuite $MCP_URL"
echo ""

# Step 4: Summary
echo "[4/4] Setup complete!"
echo ""
echo "  Next steps:"
echo "  1. Load $JAR_PATH into Burp Suite (Extensions > Add)"
echo "  2. Configure Claude Code MCP as shown above"
echo "  3. Open $DASHBOARD_URL for the dashboard"
echo "  4. Start hunting!"
echo ""
echo "=========================================="
