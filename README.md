# ReconAI

ReconAI is a modular, authorized reconnaissance and attack-surface intelligence platform designed for Kali Linux.

## Features

- **Blazing Fast**: Asynchronous execution engine never blocks.
- **Modular**: Add new integrations by writing a single Python class.
- **Secure by Design**: Strict scope enforcement ensures you only scan authorized targets.
- **Structured Data**: Uses SQLite for fast data correlation and persistence.
- **No Paid APIs**: Built to rely on open-source tools and local execution.

## Installation (Kali Linux)

```bash
git clone https://github.com/tiwarirst/reconai
cd reconai
./install.sh
source .venv/bin/activate
```

## Quick Start

Check your environment:
```bash
reconai doctor
```

Run a standard scan:
```bash
reconai scan example.com --mode standard
```

Run a passive-only scan:
```bash
reconai scan example.com --mode passive
```

## Scan Modes

- `passive`: DNS, WHOIS, Certificate Transparency. No target interaction.
- `light`: Passive + lightweight HTTP probing to find active web servers.
- `standard`: Light + fast port scanning and technology fingerprinting.
- `deep`: Standard + web crawling, directory discovery, and vulnerability intelligence.

## Output

All results are saved in `output/<target>/<scan_id>/`:
- `reconai.db`: SQLite database containing all discovered assets.
- `reports/report.md`: Human-readable Markdown summary.
- `reports/report.json`: Full JSON dump of all structured data.
- `logs/`: Application and error logs.
