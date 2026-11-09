#!/bin/bash
# Raijin Setup Script
# Builds the extension, configures Caddy, and sets up Claude Code MCP config.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

echo "=========================================="
echo " Raijin Setup"
echo "=========================================="

# Step 1: Build
echo ""
echo "[1/4] Building extension..."
cd "$PROJECT_DIR"
./gradlew shadowJar
JAR_PATH="$PROJECT_DIR/build/libs/$(ls build/libs/ | grep -v sources | head -1)"
echo "  Built: $JAR_PATH"

# Step 2: Caddy (optional)
echo ""
echo "[2/4] Caddy reverse proxy (optional)"
if command -v caddy &>/dev/null; then
    read -p "  Configure Caddy? (y/N) " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        sudo cp "$SCRIPT_DIR/Caddyfile" /etc/caddy/Caddyfile
        sudo systemctl restart caddy
        echo "  Caddy configured and restarted"
        MCP_URL="http://127.0.0.1:9900/mcp"
    else
        MCP_URL="http://127.0.0.1:9876/mcp"
    fi
else
    echo "  Caddy not installed. Using direct connection."
    echo "  Install with: sudo apt install caddy"
    MCP_URL="http://127.0.0.1:9876/mcp"
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
echo "  NOTE: Streamable HTTP at /mcp (legacy SSE still answers at '/'). No token is needed."
echo "  Or, with Claude Code:  claude mcp add --transport http burpsuite $MCP_URL"
echo ""

# Step 4: Summary
echo "[4/4] Setup complete!"
echo ""
echo "  Next steps:"
echo "  1. Load $JAR_PATH into Burp Suite (Extensions > Add)"
echo "  2. Configure Claude Code MCP as shown above"
echo "  3. Open http://127.0.0.1:9878 for the dashboard"
echo "  4. Start hunting!"
echo ""
echo "=========================================="
