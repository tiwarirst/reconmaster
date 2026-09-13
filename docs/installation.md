# Installation Guide

## Prerequisites

- **OS**: Kali Linux (recommended) or any Debian/Ubuntu-based system
- **Python**: 3.10+

## Automated Installation

```bash
git clone https://github.com/yourorg/reconai
cd reconai
chmod +x install.sh
./install.sh
source .venv/bin/activate
```

The installer checks for all tool dependencies and wordlists automatically.

## Tool Dependencies

All tools are optional — ReconAI will skip modules for unavailable tools.

| Tool | Purpose | Install |
|------|---------|---------|
| nmap | Port scanning | `sudo apt install nmap` |
| amass | Subdomain enum | `sudo apt install amass` |
| subfinder | Subdomain enum | `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest` |
| nuclei | Vulnerability scan | `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest` |
| naabu | Fast port scan | `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| katana | Web crawling | `go install github.com/projectdiscovery/katana/cmd/katana@latest` |
| dnsx | DNS resolution | `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest` |
| ffuf | Dir fuzzing | `sudo apt install ffuf` |
| whatweb | Tech detection | `sudo apt install whatweb` |
| wafw00f | WAF detection | `pip install wafw00f` |
| trufflehog | Secret scanning | Download from GitHub releases |
| dalfox | XSS scanning | `go install github.com/hahwul/dalfox/v2@latest` |
| sqlmap | SQL injection | `sudo apt install sqlmap` |
| waybackurls | Historical URLs | `go install github.com/tomnomnom/waybackurls@latest` |
| paramspider | Parameter mining | `pip install paramspider` |

## Wordlists

```bash
sudo apt install seclists
```

## Optional: AI Analysis (Ollama)

```bash
# Install Ollama
curl -fsSL https://ollama.ai/install.sh | sh

# Pull a model
ollama pull llama3
```

Then run scans with `--ai` flag.
