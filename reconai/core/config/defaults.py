"""Default configuration values for ReconAI.

All timeouts, concurrency limits, and operational defaults live here.
These can be overridden via YAML config files or CLI flags.
"""
from __future__ import annotations

# ── Timeouts (seconds) ──────────────────────────────────────
TIMEOUTS = {
    "dns_query": 10,
    "whois_rdap": 20,
    "http_probe": 30,
    "nmap_quick": 60,
    "nmap_standard": 120,
    "nmap_service": 180,
    "nmap_full": 600,
    "web_crawler": 90,
    "directory_discovery": 90,
    "technology_detection": 30,
    "browser_page": 45,
    "http_request": 15,
    "certificate_query": 20,
    "subdomain_tool": 120,
    "whois_lookup": 20,
    "cloud_bucket_enum": 180,   # Bucket permutation probing (~150 names × 3 providers)
    "cloud_enum_tool": 120,     # External cloud_enum tool run
    "cloud_metadata_ssrf": 90,  # SSRF probing (capped at 100 URLs)
    "cloud_iam_analysis": 60,   # Read-only IAM validation calls
    "default": 60,
}

# ── Concurrency ─────────────────────────────────────────────
CONCURRENCY = {
    "dns": 20,
    "http": 20,
    "crawler": 10,
    "browser": 2,
    "subdomain": 5,
    "port_scan": 3,
    "directory": 10,
    "cloud_bucket": 15,   # Concurrent bucket probes (DNS-first keeps rate-limit impact low)
    "cloud_ssrf": 5,      # Conservative — direct target probing
    "default": 10,
}

# ── Rate Limits (requests per second) ───────────────────────
RATE_LIMITS = {
    "http": 20,
    "dns": 50,
    "crawler": 10,
    "directory": 15,
    "default": 10,
}

# ── Scan Limits ─────────────────────────────────────────────
SCAN_LIMITS = {
    "max_depth": 2,
    "max_pages": 500,
    "max_urls": 5000,
    "max_subdomains": 10000,
    "max_ports_per_host": 65535,
    "max_directory_depth": 3,
    "max_js_files": 200,
    "max_requests_per_module": 10000,
}

# ── Scan Profiles ───────────────────────────────────────────
SCAN_PROFILES = {
    "quick": {
        "nmap_args": ["-T4", "--top-ports", "100", "-sV", "--version-light"],
        "description": "Fast scan of top 100 ports with light version detection",
    },
    "standard": {
        "nmap_args": ["-T3", "--top-ports", "1000", "-sV"],
        "description": "Standard scan of top 1000 ports with version detection",
    },
    "service": {
        "nmap_args": ["-T3", "-sV", "-sC", "--top-ports", "1000"],
        "description": "Service/version detection with default scripts on top 1000 ports",
    },
    "full": {
        "nmap_args": ["-T3", "-p-", "-sV", "-sC"],
        "description": "Full port range scan — use only when explicitly requested",
    },
}

# ── Scan Modes ──────────────────────────────────────────────
# Module names must EXACTLY match the `config.name` field in each @register_module class
SCAN_MODES = {
    "passive": {
        "modules": [
            "dns_enum", "whois", "cert_transparency", "archive_urls",
            "paramspider", "dnsx", "email_security", "saas_enum",
        ],
        "description": "Passive reconnaissance only — no direct target interaction",
    },
    "light": {
        "modules": [
            "dns_enum", "whois", "cert_transparency", "archive_urls",
            "dnsx", "http_probe", "email_security", "saas_enum",
        ],
        "description": "Passive recon + lightweight HTTP probing",
    },
    "standard": {
        "modules": [
            "dns_enum", "whois", "cert_transparency", "archive_urls",
            "dnsx", "http_probe", "naabu_ports", "ports", "cdn_classifier",
            "technologies", "headers", "waf_detection", "email_security",
            "saas_enum", "directory_discovery", "crawler", "api_miner", "dev_artifacts",
            "screenshot",
        ],
        "description": "Standard reconnaissance — passive + active ports + tech + web crawl + directory + screenshots",
    },
    "deep": {
        "modules": [
            "dns_enum", "whois", "cert_transparency", "archive_urls",
            "paramspider", "dnsx", "email_security", "saas_enum",
            "http_probe", "naabu_ports", "ports", "cdn_classifier", "subdomains_active",
            "technologies", "headers", "waf_detection",
            "crawler", "ffuf_dir", "directory_discovery",
            "api_miner", "dev_artifacts",
            "katana_crawler", "js_analysis",
            "nuclei_vuln", "secrets", "sqlmap", "dalfox",
            "vuln_intelligence", "screenshot",
            # Cloud enumeration
            "bucket_enum", "cloud_enum_module", "metadata_ssrf", "iam_analyzer",
        ],
        "description": "Deep reconnaissance — full active scan, fuzzing, vuln detection, and cloud enumeration",
    },
    "browser": {
        "modules": [
            "dns_enum", "whois", "cert_transparency", "dnsx",
            "http_probe", "naabu_ports", "ports",
            "technologies", "headers", "waf_detection",
            "browser_recon", "host_browser_crawler", "js_analysis", "screenshot",
        ],
        "description": "Standard recon + real browser crawling (connects to your running Chrome via CDP)",
    },
    "authenticated": {
        "modules": [
            "dns_enum", "whois", "cert_transparency", "dnsx",
            "http_probe",
            "technologies", "headers",
            "host_browser_crawler", "js_analysis",
            "nuclei_vuln", "screenshot",
        ],
        "description": "Authenticated crawl using your real browser sessions (requires Chrome CDP on port 9222)",
    },
    "cloud": {
        "modules": [
            # Phase 1: Establish DNS/subdomain landscape
            "dns_enum", "whois", "cert_transparency", "dnsx", "email_security", "saas_enum",
            # Phase 2: Light HTTP probing & CDN classification
            "http_probe", "cdn_classifier",
            # Phase 3: Cloud-specific enumeration
            "bucket_enum",          # Multi-cloud storage bucket brute-force
            "cloud_enum_module",    # CNAME fingerprinting + dangling DNS takeover
            # Phase 4: Credential discovery and exploitation paths
            "secrets",              # Find leaked credentials in JS/responses
            "metadata_ssrf",        # SSRF -> cloud metadata credential theft
            "iam_analyzer",         # Validate discovered credentials + blast radius
            # Phase 5: Standard vuln scan on discovered attack surface
            "nuclei_vuln",
        ],
        "description": (
            "Cloud-focused recon -- multi-provider bucket discovery, CNAME-based service "
            "fingerprinting, subdomain takeover detection, SSRF->metadata credential theft, "
            "and IAM credential validation."
        ),
    },
    "subs": {
        "modules": [
            "dns_enum", "cert_transparency", "archive_urls", "dnsx", "subdomains_active",
        ],
        "description": "Dedicated Subdomain Intelligence Pipeline — passive & active multi-engine subdomain discovery",
    },
    "ports": {
        "modules": [
            "dns_enum", "dnsx", "naabu_ports", "ports", "cdn_classifier",
        ],
        "description": "Dedicated Port & Service Pipeline — high-speed port scanning, banner grabbing, and CDN classification",
    },
    "web": {
        "modules": [
            "http_probe", "technologies", "headers", "waf_detection", "crawler",
            "directory_discovery", "api_miner", "dev_artifacts", "screenshot",
        ],
        "description": "Dedicated Web Attack Surface Pipeline — deep crawling, tech stack fingerprinting, directory discovery, and visual screenshots",
    },
    "vuln": {
        "modules": [
            "http_probe", "api_miner", "dev_artifacts", "nuclei_vuln", "secrets",
            "dalfox", "sqlmap", "vuln_intelligence",
        ],
        "description": "Dedicated Vulnerability Pipeline — automated vulnerability assessment, exposed secret scanning, and exploit intelligence",
    },
}

# ── Kali Wordlist Paths ─────────────────────────────────────
WORDLISTS = {
    "subdomains": [
        "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt",
        "/usr/share/seclists/Discovery/DNS/namelist.txt",
        "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt",
        "/usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt",
    ],
    "directories": [
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
        "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-small.txt",
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
    ],
    "files": [
        "/usr/share/seclists/Discovery/Web-Content/raft-small-files.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ],
    "parameters": [
        "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt",
    ],
}

# ── Priority Keywords ───────────────────────────────────────
PRIORITY_KEYWORDS = {
    "critical": ["admin", "api", "auth", "login", "dashboard", "internal", "staging", "dev", "test", "debug"],
    "high": ["mail", "vpn", "remote", "gateway", "portal", "manage", "control", "monitor"],
    "normal": ["www", "web", "app", "shop", "blog", "docs", "support", "help"],
    "low": ["cdn", "static", "assets", "img", "images", "media", "fonts", "cache"],
}

# ── Output Settings ─────────────────────────────────────────
OUTPUT = {
    "base_dir": "output",
    "save_raw": True,
    "save_normalized": True,
    "save_logs": True,
    "report_formats": ["html", "json", "md"],
}

# ── Cache Settings ──────────────────────────────────────────
CACHE = {
    "enabled": True,
    "ttl_dns": 3600,
    "ttl_http": 1800,
    "ttl_certificate": 86400,
    "ttl_technology": 3600,
    "ttl_default": 1800,
}

# ── DNS Record Types ────────────────────────────────────────
DNS_RECORD_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "PTR", "SRV"]

# ── Security Headers to Check ───────────────────────────────
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy",
]

# ── Interesting DNS Record Explanations ─────────────────────
DNS_EXPLANATIONS = {
    "MX": "Identifies mail infrastructure and email service providers",
    "TXT": "May reveal SPF records, DKIM, domain verification tokens, and provider info",
    "CAA": "Identifies permitted certificate authorities for the domain",
    "CNAME": "May reveal infrastructure relationships, CDN providers, or hosting",
    "NS": "Identifies authoritative nameservers and DNS hosting provider",
    "SOA": "Contains zone administration info including primary nameserver and admin contact",
    "SRV": "May reveal internal services like LDAP, SIP, XMPP configurations",
    "PTR": "Reverse DNS — maps IP back to hostname, useful for infrastructure mapping",
}
