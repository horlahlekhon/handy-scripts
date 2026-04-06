#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CLAUDE_DIR="$HOME/.claude"

# ── colours ──────────────────────────────────────────────────────────────────
G='\033[0;32m'; Y='\033[1;33m'; B='\033[0;34m'; R='\033[0;31m'; N='\033[0m'
ok()   { echo -e "${G}✓${N} $*"; }
info() { echo -e "${B}→${N} $*"; }
warn() { echo -e "${Y}!${N} $*"; }
fail() { echo -e "${R}✗${N} $*" >&2; exit 1; }

# ── checks ────────────────────────────────────────────────────────────────────
command -v claude  >/dev/null || fail "claude CLI not found — install Claude Code first"
command -v python3 >/dev/null || fail "python3 not found"

echo ""
echo "Installing Claude Code config from: $REPO_DIR"
echo "─────────────────────────────────────────────"

# ── 1. Install plugin (skills) ────────────────────────────────────────────────
info "Registering plugin marketplace..."
if claude plugin marketplace add "$REPO_DIR" --scope user 2>/dev/null; then
  ok "Marketplace registered"
else
  warn "Marketplace already registered or failed — continuing"
fi

info "Installing plugin (skills)..."
if claude plugin install olalekan-config --scope user 2>/dev/null; then
  ok "Plugin installed — skills available globally via /skill-name"
else
  warn "Plugin install failed."
  warn "Run manually after this script: claude plugin install olalekan-config --scope user"
  warn "Or add to every session: claude --plugin-dir '$REPO_DIR'"
fi

# ── 2. Rules ──────────────────────────────────────────────────────────────────
info "Installing rules..."
mkdir -p "$CLAUDE_DIR/rules"
cp -r "$REPO_DIR/rules/"* "$CLAUDE_DIR/rules/"
ok "Rules installed → $CLAUDE_DIR/rules/"

# ── 3. CLAUDE.md (global instructions) ───────────────────────────────────────
info "Installing CLAUDE.md..."
if [ -f "$CLAUDE_DIR/CLAUDE.md" ]; then
  cp "$CLAUDE_DIR/CLAUDE.md" "$CLAUDE_DIR/CLAUDE.md.bak"
  warn "Existing CLAUDE.md backed up to CLAUDE.md.bak"
fi
cp "$REPO_DIR/CLAUDE.md" "$CLAUDE_DIR/CLAUDE.md"
ok "CLAUDE.md installed → $CLAUDE_DIR/CLAUDE.md"

# ── 4. MCP servers (no credentials required) ─────────────────────────────────
info "Adding no-credential MCP servers..."

# Read server config from template and add via claude mcp add-json
# Only servers that work out of the box (no API keys needed)
add_mcp() {
  local name="$1"
  local json="$2"
  if claude mcp get "$name" &>/dev/null; then
    warn "MCP '$name' already configured — skipping"
  else
    if claude mcp add-json "$name" "$json" --scope user 2>/dev/null; then
      ok "MCP '$name' added"
    else
      warn "Failed to add MCP '$name' — add manually"
    fi
  fi
}

add_mcp "sequential-thinking" \
  '{"type":"stdio","command":"npx","args":["-y","@modelcontextprotocol/server-sequential-thinking"]}'

add_mcp "memory" \
  '{"type":"stdio","command":"npx","args":["-y","@modelcontextprotocol/server-memory"]}'

add_mcp "omega-memory" \
  '{"type":"stdio","command":"uvx","args":["omega-memory","serve"]}'

add_mcp "token-optimizer" \
  '{"type":"stdio","command":"npx","args":["-y","token-optimizer-mcp"]}'

# ── 5. Print manual MCP setup instructions ────────────────────────────────────
echo ""
echo "─────────────────────────────────────────────"
echo "MCPs requiring credentials — add manually:"
echo ""
echo "  claude mcp add-json github '{\"type\":\"stdio\",\"command\":\"npx\",\"args\":[\"-y\",\"@modelcontextprotocol/server-github\"],\"env\":{\"GITHUB_PERSONAL_ACCESS_TOKEN\":\"<your-pat>\"}}'"
echo "  → PAT scopes needed: repo, read:org"
echo "  → Create at: https://github.com/settings/tokens"
echo ""
echo "  claude mcp add-json exa-web-search '{\"type\":\"stdio\",\"command\":\"npx\",\"args\":[\"-y\",\"exa-mcp-server\"],\"env\":{\"EXA_API_KEY\":\"<your-key>\"}}'"
echo "  → API key from: https://exa.ai"
echo ""
echo "  claude mcp add-json jira '{\"type\":\"stdio\",\"command\":\"uvx\",\"args\":[\"mcp-atlassian==0.21.0\"],\"env\":{\"JIRA_URL\":\"<url>\",\"JIRA_EMAIL\":\"<email>\",\"JIRA_API_TOKEN\":\"<token>\"}}'"
echo "  → Token from: https://id.atlassian.com/manage-profile/security/api-tokens"
echo ""
echo "  claude mcp add-json firecrawl '{\"type\":\"stdio\",\"command\":\"npx\",\"args\":[\"-y\",\"firecrawl-mcp\"],\"env\":{\"FIRECRAWL_API_KEY\":\"<your-key>\"}}'"
echo "  → API key from: https://firecrawl.dev"
echo ""
echo "  claude mcp add-json supabase '{\"type\":\"stdio\",\"command\":\"npx\",\"args\":[\"-y\",\"@supabase/mcp-server-supabase@latest\",\"--project-ref=<ref>\"],\"env\":{\"SUPABASE_URL\":\"<url>\",\"SUPABASE_SERVICE_ROLE_KEY\":\"<key>\"}}'"
echo ""
echo "  claude mcp add-json filesystem '{\"type\":\"stdio\",\"command\":\"npx\",\"args\":[\"-y\",\"@modelcontextprotocol/server-filesystem\",\"$HOME/projects\"]}'"
echo "  → Change \$HOME/projects to your actual projects root"
echo ""
echo "─────────────────────────────────────────────"
echo "Full server reference: $REPO_DIR/mcp/mcp-servers.json"
echo ""
ok "Done. Restart Claude Code to apply all changes."

