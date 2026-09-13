#!/usr/bin/env bash
# ═══════════════════════════════════════════════════
#  ReconAI Installer — Kali Linux
# ═══════════════════════════════════════════════════
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════╗"
    echo "║            ReconAI Installer v1.0             ║"
    echo "╚═══════════════════════════════════════════════╝"
    echo -e "${NC}"
}

info()    { echo -e "${GREEN}[+]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[-]${NC} $1"; }

check_tool() {
    if command -v "$1" &>/dev/null; then
        info "$1 found: $(command -v "$1")"
    else
        warn "$1 not found (optional)"
    fi
}

banner

# Check Python
if ! command -v python3 &>/dev/null; then
    error "Python 3 is required but not found."
    echo "  Install: sudo apt install python3 python3-pip python3-venv"
    exit 1
fi

PYTHON_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
info "Python $PYTHON_VER detected"

# Create virtual environment
if [ ! -d ".venv" ]; then
    info "Creating virtual environment..."
    python3 -m venv .venv
else
    info "Virtual environment already exists"
fi

info "Activating virtual environment..."
source .venv/bin/activate

# Upgrade pip
info "Upgrading pip..."
pip install --upgrade pip --quiet

# Install dependencies
info "Installing dependencies..."
pip install -r requirements.txt --quiet

# Install reconai in development mode
info "Installing ReconAI..."
pip install -e . --quiet

echo ""
info "Checking security tools..."
echo "─────────────────────────────────"
check_tool nmap
check_tool amass
check_tool subfinder
check_tool httpx
check_tool nuclei
check_tool whatweb
check_tool waybackurls
check_tool wafw00f
check_tool trufflehog
check_tool naabu
check_tool masscan
check_tool gobuster
check_tool ffuf
check_tool dig
check_tool whois
check_tool katana
check_tool sqlmap
check_tool dalfox
check_tool paramspider
check_tool dnsx
echo "─────────────────────────────────"

echo ""
info "Checking wordlists..."
[ -d "/usr/share/wordlists" ]   && info "/usr/share/wordlists found"   || warn "/usr/share/wordlists not found"
[ -d "/usr/share/seclists" ]    && info "/usr/share/seclists found"    || warn "/usr/share/seclists not found (install: sudo apt install seclists)"

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         ReconAI installed successfully!       ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════╝${NC}"
echo ""
echo "  Activate:  source .venv/bin/activate"
echo "  Usage:     reconai --help"
echo "  Doctor:    reconai doctor"
echo ""
