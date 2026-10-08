# ReconAI Installation & Environment Guide

## 1. System Requirements

- **Python Runtime**: Python 3.10 or higher (Python 3.11+ recommended).
- **Supported Operating Systems**:
  - **Linux**: Kali Linux, Ubuntu 22.04+, Debian 12+, Fedora, Arch Linux.
  - **macOS**: macOS Monterey (12)+ on Apple Silicon (M1/M2/M3) or Intel.
  - **Windows**: Windows 10/11 (native PowerShell or Windows Subsystem for Linux - WSL2).
- **Memory**: 4 GB RAM minimum (8 GB+ recommended for deep concurrent web crawling).

---

## 2. Core Python Installation

### Step 1: Clone the Codebase
```bash
git clone https://github.com/tiwarirst/reconai.git
cd reconai
```

### Step 2: Initialize Virtual Environment
It is strongly recommended to install ReconAI inside an isolated Python virtual environment:

```bash
# On Linux / macOS:
python3 -m venv .venv
source .venv/bin/activate

# On Windows (PowerShell):
python -m venv .venv
.venv\Scripts\Activate.ps1

# On Windows (Command Prompt):
python -m venv .venv
.venv\Scripts\activate.bat
```

### Step 3: Install Core Dependencies
```bash
pip install --upgrade pip setuptools wheel
pip install -r requirements.txt
pip install -e .
```

### Step 4: Verify Installation
```bash
reconai --version
reconai doctor
```

---

## 3. External Tool Ecosystem Setup

> **Fail-Safe Guarantee**: All external tools are strictly optional. If a tool binary is not installed, ReconAI automatically invokes its built-in pure-Python fallback without failing your scan. Installing external binaries provides raw speed enhancements for large scopes.

### 3.1 Linux (Debian / Ubuntu / Kali)

```bash
# System packages
sudo apt update && sudo apt install -y \
    nmap \
    sqlmap \
    whatweb \
    whois \
    dnsutils \
    masscan

# Go environment (if not already installed)
sudo apt install -y golang-go

# ProjectDiscovery & Go Security Utilities
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/pentest-io/subzy@latest
go install -v github.com/sensepost/gowitness@latest

# Python-based Security Tools
pip install arjun wafw00f cloud-enum

# Secret Scanning
# Gitleaks:
sudo apt install gitleaks || go install github.com/zricethezav/gitleaks/v8@latest
# TruffleHog:
go install github.com/trufflesecurity/trufflehog/v3@latest

# Ensure Go binaries are in PATH
export PATH=$PATH:$(go env GOPATH)/bin
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
```

### 3.2 macOS (via Homebrew)

```bash
# Core tools
brew install nmap sqlmap whatweb whois gitleaks ffuf

# Go tools
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/hahwul/dalfox/v2@latest
go install -v github.com/pentest-io/subzy@latest

# Python tools
pip install arjun wafw00f cloud-enum
```

### 3.3 Windows 10 / 11

ReconAI runs natively on Windows PowerShell. External tools can be installed via `winget`, `choco`, or compiled Go binaries:

```powershell
# Using winget / chocolatey:
winget install Insecure.Nmap
choco install gitleaks

# Go-based tools (requires Go installed: winget install GoLang.Go):
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/pentest-io/subzy@latest

# Ensure Go binary directory is in user PATH:
# Usually: $env:USERPROFILE\go\bin
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";$env:USERPROFILE\go\bin", "User")
```

---

## 4. Wordlist Packs Setup

For maximum fuzzing and directory brute-forcing coverage:

```bash
# SecLists (Standard security wordlists)
# On Debian / Ubuntu / Kali:
sudo apt install -y seclists

# On macOS / Manual:
git clone --depth 1 https://github.com/danielmiessler/SecLists.git /opt/seclists
```

ReconAI automatically checks standard wordlist paths (`/usr/share/seclists/`, `/usr/share/wordlists/`) and falls back to internal top-1000 dictionary models if external wordlists are absent.

---

## 5. Local or Remote Ollama Setup (AI Capabilities)

To enable AI copilot and autonomous red team attack planning:

### Local Machine
1. Install Ollama:
   - **Linux / macOS**: `curl -fsSL https://ollama.ai/install.sh | sh`
   - **Windows**: Download installer from [ollama.com/download](https://ollama.com/download)
2. Pull recommended security weights:
   ```bash
   ollama pull llama3
   ollama pull deepseek-r1:7b
   ```
3. Test connectivity:
   ```bash
   curl http://localhost:11434/api/tags
   ```

### Remote GPU Machine
If your AI weights reside on a dedicated GPU rig in your home lab or cloud:
```bash
# On GPU machine:
export OLLAMA_HOST=0.0.0.0:11434
ollama serve

# On ReconAI host:
reconai scan example.com --ai --ai-url http://<GPU_IP>:11434 --ai-model deepseek-r1:7b
```

---

## 6. Verifying Everything

Run the environment doctor to get an interactive table of your setup:

```bash
reconai doctor
```

Run test suite:

```bash
python -m pytest tests/ -v
```
