# Quick Start Guide

## Basic Usage

```bash
# Activate environment
source .venv/bin/activate

# Verify everything is ready
reconai doctor

# Passive scan (no target interaction)
reconai scan example.com --mode passive

# Standard scan (recommended starting point)
reconai scan example.com --mode standard

# Deep scan (full toolchain: crawler, fuzzing, vuln scan)
reconai scan example.com --mode deep

# Browser scan (for SPA/React apps)
reconai scan example.com --mode browser
```

## Scan Modes

| Mode | Tools Used | Speed | Aggressiveness |
|------|-----------|-------|----------------|
| passive | DNS, WHOIS, crt.sh, Wayback | Fast | Zero |
| light | Passive + HTTP probing | Fast | Very Low |
| standard | Light + Naabu, Nmap, WhatWeb, Headers, WAF | Medium | Low |
| deep | Standard + Katana, FFuF, Nuclei, SQLMap, Dalfox, Secrets | Slow | Medium |
| browser | Standard + Playwright browser | Medium | Low |

## Port Scan Profiles

```bash
# Quick: Top 100 ports (default)
reconai scan example.com --profile quick

# Standard: Top 1000 ports  
reconai scan example.com --profile standard

# Service: Top 1000 + script scan
reconai scan example.com --profile service

# Full: All 65535 ports (very slow!)
reconai scan example.com --profile full
```

## Comparing Scans

```bash
# Run two scans
reconai scan example.com  # Scan ID printed at end
reconai scan example.com

# Compare (replace IDs with actual ones from output)
reconai compare 20240101_120000_abc123 20240115_120000_def456
```

## Reports

After every scan, reports are saved to `output/<target>/<scan_id>/reports/`:
- `report.html` — Beautiful interactive report (open in browser)
- `report.md` — Markdown summary
- `report.json` — Full structured data (for scripting/pipelines)

## Testing Without a Real Target

ReconAI ships with a safe test target:

```bash
reconai scan scanme.nmap.org --mode standard
```

`scanme.nmap.org` is maintained by the Nmap project and explicitly authorized for testing.
