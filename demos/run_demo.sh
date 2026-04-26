#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# WRAITH DEF CON Demo — One-command demo runner
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"

echo -e "${RED}"
echo "  ██╗    ██╗██████╗  █████╗ ██╗████████╗██╗  ██╗"
echo "  ██║    ██║██╔══██╗██╔══██╗██║╚══██╔══╝██║  ██║"
echo "  ██║ █╗ ██║██████╔╝███████║██║   ██║   ███████║"
echo "  ██║███╗██║██╔══██╗██╔══██║██║   ██║   ██╔══██║"
echo "  ╚███╔███╔╝██║  ██║██║  ██║██║   ██║   ██║  ██║"
echo "   ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝   ╚═╝   ╚═╝  ╚═╝"
echo -e "${NC}"
echo "  DEF CON Demo — Live Vulnerability Discovery"
echo ""

# Step 1: Start vulnerable demo app in background
echo -e "${YELLOW}[1/4] Starting vulnerable demo application...${NC}"
cd "$SCRIPT_DIR/vulnerable_flask_app"
pip install -q flask >/dev/null 2>&1 || true
python app.py &
DEMO_PID=$!
sleep 2
echo -e "${GREEN}  ✓ Demo app running on http://localhost:5001${NC}"

# Step 2: Install WRAITH
echo -e "${YELLOW}[2/4] Installing WRAITH CLI...${NC}"
cd "$ROOT_DIR"
pip install -e . >/dev/null 2>&1
echo -e "${GREEN}  ✓ WRAITH installed${NC}"

# Step 3: Run full scan
echo -e "${YELLOW}[3/4] Running WRAITH scan...${NC}"
echo ""
wraith scan "$SCRIPT_DIR/vulnerable_flask_app" \
    --url http://localhost:5001 \
    --type full \
    --output "$ROOT_DIR/demo_output"

# Step 4: Run LLM red team
echo -e "${YELLOW}[4/4] Running LLM red team test...${NC}"
echo ""
wraith llm-redteam http://localhost:5001/api/chat \
    --output "$ROOT_DIR/demo_output"

# Cleanup
kill $DEMO_PID 2>/dev/null || true

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Demo complete! Reports in: demo_output/${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════${NC}"
echo ""
echo "  📊 report.json   — Full structured report"
echo "  📝 report.md     — Markdown report"
echo "  🌐 report.html   — HTML report (open in browser)"
echo ""
