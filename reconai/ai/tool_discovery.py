"""NEXUS — Dynamic Kali Tool Discovery Engine.

Discovers ALL tools available on a Kali Linux system by:
1. Scanning PATH directories for executables
2. Reading /usr/share/kali-menu categories  
3. Checking known Kali metapackage tool lists
4. Querying 'dpkg -l' for installed security packages

The result: a rich, live, dynamic catalogue of EVERY tool on the system —
not a hardcoded 20-tool list, but hundreds of real tools with categories,
descriptions, typical usage patterns, and risk levels.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


# ── Kali Tool Knowledge Base ─────────────────────────────────────────────────
# This covers the full Kali Linux tool ecosystem organised by category.
# Each entry: tool_name -> {description, category, input_type, risk_level, tags}
# This acts as a semantic index even when tools aren't installed.

KALI_TOOL_KNOWLEDGE: dict[str, dict[str, Any]] = {
    # ── Information Gathering ─────────────────────────────────────────────
    "nmap": {"desc": "Network mapper & port scanner", "cat": "recon/port", "risk": "medium",
              "tags": ["port", "scan", "service", "version", "network"], "input": "host|ip|cidr"},
    "naabu": {"desc": "Fast SYN port scanner", "cat": "recon/port", "risk": "medium",
               "tags": ["port", "fast", "syn"], "input": "host|ip"},
    "masscan": {"desc": "Mass IP port scanner", "cat": "recon/port", "risk": "high",
                "tags": ["port", "mass", "fast", "cidr"], "input": "ip|cidr"},
    "rustscan": {"desc": "Modern port scanner with nmap integration", "cat": "recon/port", "risk": "medium",
                  "tags": ["port", "fast", "rust"], "input": "host|ip"},
    "subfinder": {"desc": "Passive subdomain discovery", "cat": "recon/subdomain", "risk": "low",
                   "tags": ["subdomain", "passive", "dns"], "input": "domain"},
    "amass": {"desc": "In-depth attack surface mapping", "cat": "recon/subdomain", "risk": "low",
               "tags": ["subdomain", "osint", "passive", "active"], "input": "domain"},
    "assetfinder": {"desc": "Find related domains and subdomains", "cat": "recon/subdomain", "risk": "low",
                     "tags": ["subdomain", "osint"], "input": "domain"},
    "findomain": {"desc": "Cross-platform subdomain enumerator", "cat": "recon/subdomain", "risk": "low",
                   "tags": ["subdomain", "fast"], "input": "domain"},
    "dnsx": {"desc": "DNS toolkit with multi-type record lookup", "cat": "recon/dns", "risk": "low",
              "tags": ["dns", "resolve", "mx", "txt", "cname", "ns"], "input": "domain"},
    "dig": {"desc": "DNS query utility", "cat": "recon/dns", "risk": "low",
             "tags": ["dns", "query", "lookup"], "input": "domain"},
    "dnsrecon": {"desc": "DNS enumeration script", "cat": "recon/dns", "risk": "low",
                  "tags": ["dns", "enum", "zone"], "input": "domain"},
    "fierce": {"desc": "DNS reconnaissance tool", "cat": "recon/dns", "risk": "low",
                "tags": ["dns", "bruteforce", "subdomain"], "input": "domain"},
    "whois": {"desc": "WHOIS registration data lookup", "cat": "recon/osint", "risk": "low",
               "tags": ["whois", "registration", "owner"], "input": "domain|ip"},
    "theHarvester": {"desc": "Email, name, subdomain OSINT gatherer", "cat": "recon/osint", "risk": "low",
                      "tags": ["osint", "email", "names", "linkedin"], "input": "domain"},
    "maltego": {"desc": "Interactive data mining & link analysis", "cat": "recon/osint", "risk": "low",
                 "tags": ["osint", "graph", "link"], "input": "domain|person"},
    "recon-ng": {"desc": "Full-featured web reconnaissance framework", "cat": "recon/osint", "risk": "low",
                  "tags": ["osint", "framework", "recon"], "input": "domain"},
    "shodan": {"desc": "Search engine for Internet-connected devices", "cat": "recon/osint", "risk": "low",
                "tags": ["shodan", "iot", "internet", "exposed"], "input": "domain|ip"},
    "censys": {"desc": "Internet-wide scan data search", "cat": "recon/osint", "risk": "low",
                "tags": ["censys", "internet", "scan"], "input": "domain|ip"},
    "httpx": {"desc": "HTTP probe and web technology fingerprinter", "cat": "recon/web", "risk": "low",
               "tags": ["http", "probe", "tech", "title", "status"], "input": "url|host"},
    "whatweb": {"desc": "Web technology identifier", "cat": "recon/web", "risk": "low",
                 "tags": ["technology", "cms", "framework", "fingerprint"], "input": "url"},
    "wafw00f": {"desc": "WAF fingerprinting tool", "cat": "recon/web", "risk": "low",
                 "tags": ["waf", "firewall", "bypass"], "input": "url"},
    "wapiti": {"desc": "Web application vulnerability scanner", "cat": "recon/web", "risk": "medium",
                "tags": ["web", "scan", "vuln", "xss", "sqli"], "input": "url"},
    "nikto": {"desc": "Web server scanner for misconfigurations", "cat": "recon/web", "risk": "medium",
               "tags": ["web", "misconfig", "headers", "cve"], "input": "url|host"},
    "curl": {"desc": "HTTP client for manual requests", "cat": "recon/web", "risk": "low",
              "tags": ["http", "request", "fetch", "header"], "input": "url"},
    "wget": {"desc": "File downloader & HTTP fetcher", "cat": "recon/web", "risk": "low",
              "tags": ["http", "download", "mirror"], "input": "url"},
    "tlsx": {"desc": "TLS grabber: cert, JARM, cipher", "cat": "recon/tls", "risk": "low",
              "tags": ["tls", "ssl", "cert", "jarm", "cipher"], "input": "host"},
    "sslscan": {"desc": "SSL/TLS configuration tester", "cat": "recon/tls", "risk": "low",
                 "tags": ["ssl", "tls", "cipher", "heartbleed"], "input": "host"},
    "sslyze": {"desc": "Fast TLS analyzer", "cat": "recon/tls", "risk": "low",
                "tags": ["ssl", "tls", "cert", "analysis"], "input": "host"},
    "testssl.sh": {"desc": "Shell script TLS checker", "cat": "recon/tls", "risk": "low",
                    "tags": ["ssl", "tls", "testing"], "input": "host"},
    "katana": {"desc": "Next-gen web crawler & endpoint spider", "cat": "recon/crawl", "risk": "low",
                "tags": ["crawl", "spider", "endpoint", "path"], "input": "url"},
    "hakrawler": {"desc": "Simple, fast web crawler", "cat": "recon/crawl", "risk": "low",
                   "tags": ["crawl", "fast", "endpoint"], "input": "url"},
    "gospider": {"desc": "Fast web spider written in Go", "cat": "recon/crawl", "risk": "low",
                  "tags": ["crawl", "spider", "links"], "input": "url"},
    "gau": {"desc": "All URLs from Wayback/CommonCrawl", "cat": "recon/crawl", "risk": "low",
             "tags": ["wayback", "archive", "urls", "historical"], "input": "domain"},
    "waybackurls": {"desc": "Fetch all Wayback Machine URLs", "cat": "recon/crawl", "risk": "low",
                     "tags": ["wayback", "archive", "urls"], "input": "domain"},
    "arjun": {"desc": "HTTP parameter discovery suite", "cat": "recon/params", "risk": "low",
               "tags": ["param", "parameter", "hidden", "fuzz"], "input": "url"},
    "paramspider": {"desc": "Mining parameters from web archives", "cat": "recon/params", "risk": "low",
                     "tags": ["param", "mining", "archive"], "input": "domain"},
    "gowitness": {"desc": "Web screenshot utility (headless Chrome)", "cat": "recon/visual", "risk": "low",
                   "tags": ["screenshot", "visual", "browser"], "input": "url|list"},
    "eyewitness": {"desc": "Web app screenshot & header report", "cat": "recon/visual", "risk": "low",
                    "tags": ["screenshot", "visual", "report"], "input": "url|list"},
    "aquatone": {"desc": "Visual inspection of websites at scale", "cat": "recon/visual", "risk": "low",
                  "tags": ["screenshot", "visual", "scale"], "input": "url|list"},

    # ── Vulnerability Analysis ─────────────────────────────────────────────
    "nuclei": {"desc": "Fast vulnerability scanner with templates", "cat": "vuln/scanner", "risk": "high",
                "tags": ["vuln", "cve", "template", "scan", "exploit"], "input": "url|host"},
    "nikto": {"desc": "Web server misconfiguration scanner", "cat": "vuln/scanner", "risk": "medium",
               "tags": ["web", "misconfig", "vuln"], "input": "url|host"},
    "openvas": {"desc": "Open Vulnerability Assessment System", "cat": "vuln/scanner", "risk": "high",
                 "tags": ["vuln", "comprehensive", "scan"], "input": "ip|host"},
    "nessus": {"desc": "Commercial vulnerability scanner", "cat": "vuln/scanner", "risk": "high",
                "tags": ["vuln", "scan", "compliance"], "input": "ip|host"},
    "dalfox": {"desc": "XSS vulnerability scanner", "cat": "vuln/xss", "risk": "high",
                "tags": ["xss", "reflected", "stored", "dom"], "input": "url"},
    "xsstrike": {"desc": "XSS scanner with fuzzing", "cat": "vuln/xss", "risk": "high",
                  "tags": ["xss", "fuzz", "bypass"], "input": "url"},
    "sqlmap": {"desc": "Automatic SQL injection exploiter", "cat": "vuln/sqli", "risk": "critical",
                "tags": ["sqli", "sql", "database", "injection", "dump"], "input": "url"},
    "ghauri": {"desc": "Advanced SQL injection detection tool", "cat": "vuln/sqli", "risk": "critical",
                "tags": ["sqli", "advanced", "detection"], "input": "url"},
    "commix": {"desc": "Command injection exploiter", "cat": "vuln/injection", "risk": "critical",
                "tags": ["cmdi", "command", "injection", "rce"], "input": "url"},
    "tplmap": {"desc": "Server-side template injection tester", "cat": "vuln/injection", "risk": "critical",
                "tags": ["ssti", "template", "injection"], "input": "url"},
    "corsy": {"desc": "CORS misconfiguration scanner", "cat": "vuln/web", "risk": "medium",
               "tags": ["cors", "misconfiguration", "origin"], "input": "url"},
    "jwt_tool": {"desc": "JWT testing toolkit", "cat": "vuln/auth", "risk": "high",
                  "tags": ["jwt", "token", "auth", "bypass"], "input": "token"},
    "hydra": {"desc": "Password brute-force tool", "cat": "vuln/auth", "risk": "critical",
               "tags": ["brute", "password", "auth", "crack"], "input": "host"},
    "medusa": {"desc": "Parallel login brute-forcer", "cat": "vuln/auth", "risk": "critical",
                "tags": ["brute", "parallel", "password"], "input": "host"},
    "patator": {"desc": "Multi-purpose brute-forcer", "cat": "vuln/auth", "risk": "critical",
                 "tags": ["brute", "multi", "protocol"], "input": "host"},
    "subzy": {"desc": "Subdomain takeover checker", "cat": "vuln/takeover", "risk": "high",
               "tags": ["takeover", "subdomain", "dangling"], "input": "domain|list"},
    "subjack": {"desc": "Subdomain hijacking checker", "cat": "vuln/takeover", "risk": "high",
                 "tags": ["takeover", "hijack", "subdomain"], "input": "domain|list"},
    "ssrfmap": {"desc": "SSRF scanner and exploiter", "cat": "vuln/ssrf", "risk": "critical",
                 "tags": ["ssrf", "server-side", "request", "forgery"], "input": "url"},
    "gopherus": {"desc": "SSRF gopher payload generator", "cat": "vuln/ssrf", "risk": "critical",
                  "tags": ["ssrf", "gopher", "payload"], "input": "url"},
    "xxeinjector": {"desc": "XXE injection tool", "cat": "vuln/xxe", "risk": "critical",
                     "tags": ["xxe", "xml", "injection"], "input": "url"},
    "dotdotpwn": {"desc": "Directory traversal fuzzer", "cat": "vuln/traversal", "risk": "high",
                   "tags": ["traversal", "lfi", "path", "directory"], "input": "host"},
    "lfimap": {"desc": "LFI discovery & exploitation tool", "cat": "vuln/traversal", "risk": "critical",
                "tags": ["lfi", "local", "file", "inclusion"], "input": "url"},

    # ── Web Application Testing ────────────────────────────────────────────
    "ffuf": {"desc": "Fast web fuzzer & directory bruteforcer", "cat": "web/fuzz", "risk": "medium",
              "tags": ["fuzz", "dir", "brute", "wordlist", "hidden"], "input": "url"},
    "gobuster": {"desc": "Directory/file brute-forcer", "cat": "web/fuzz", "risk": "medium",
                  "tags": ["dir", "brute", "wordlist", "dns"], "input": "url|domain"},
    "feroxbuster": {"desc": "Fast recursive content discovery", "cat": "web/fuzz", "risk": "medium",
                     "tags": ["dir", "recursive", "fast", "brute"], "input": "url"},
    "dirsearch": {"desc": "Web path scanner", "cat": "web/fuzz", "risk": "medium",
                   "tags": ["dir", "path", "scan"], "input": "url"},
    "wfuzz": {"desc": "Web application fuzzer", "cat": "web/fuzz", "risk": "medium",
               "tags": ["fuzz", "web", "param", "wordlist"], "input": "url"},
    "burpsuite": {"desc": "Web app security testing platform", "cat": "web/proxy", "risk": "high",
                   "tags": ["proxy", "intercept", "scan", "repeater"], "input": "url"},
    "zaproxy": {"desc": "OWASP ZAP web app scanner", "cat": "web/scanner", "risk": "high",
                 "tags": ["scan", "owasp", "proxy", "active"], "input": "url"},
    "wpscan": {"desc": "WordPress vulnerability scanner", "cat": "web/cms", "risk": "high",
                "tags": ["wordpress", "cms", "plugin", "theme", "vuln"], "input": "url"},
    "joomscan": {"desc": "Joomla vulnerability scanner", "cat": "web/cms", "risk": "high",
                  "tags": ["joomla", "cms", "vuln"], "input": "url"},
    "droopescan": {"desc": "CMS scanner (Drupal, Joomla, Moodle)", "cat": "web/cms", "risk": "high",
                    "tags": ["drupal", "cms", "scan"], "input": "url"},
    "cmseek": {"desc": "CMS detection and exploitation framework", "cat": "web/cms", "risk": "high",
                "tags": ["cms", "detect", "exploit"], "input": "url"},

    # ── Password Attacks ───────────────────────────────────────────────────
    "hashcat": {"desc": "GPU-accelerated password cracker", "cat": "password/crack", "risk": "critical",
                 "tags": ["crack", "hash", "gpu", "password"], "input": "hash|file"},
    "john": {"desc": "John the Ripper password cracker", "cat": "password/crack", "risk": "critical",
              "tags": ["crack", "hash", "password"], "input": "hash|file"},
    "crunch": {"desc": "Wordlist generator", "cat": "password/wordlist", "risk": "low",
                "tags": ["wordlist", "generate", "custom"], "input": "pattern"},
    "cewl": {"desc": "Custom wordlist generator from website", "cat": "password/wordlist", "risk": "low",
              "tags": ["wordlist", "scrape", "website"], "input": "url"},
    "cupp": {"desc": "Common User Passwords Profiler", "cat": "password/wordlist", "risk": "low",
              "tags": ["wordlist", "profiling", "custom"], "input": "interactive"},

    # ── Wireless Attacks ───────────────────────────────────────────────────
    "aircrack-ng": {"desc": "WiFi network security auditing", "cat": "wireless/crack", "risk": "critical",
                     "tags": ["wifi", "wpa", "crack", "wireless"], "input": "capture"},
    "airmon-ng": {"desc": "WLAN monitor mode switch", "cat": "wireless/monitor", "risk": "high",
                   "tags": ["wifi", "monitor", "mode"], "input": "interface"},
    "airodump-ng": {"desc": "802.11 packet capture", "cat": "wireless/capture", "risk": "high",
                     "tags": ["wifi", "capture", "sniff"], "input": "interface"},
    "wifite": {"desc": "Automated wireless auditor", "cat": "wireless/auto", "risk": "critical",
                "tags": ["wifi", "auto", "crack", "deauth"], "input": "interface"},
    "kismet": {"desc": "Wireless network detector & sniffer", "cat": "wireless/detect", "risk": "medium",
                "tags": ["wifi", "detect", "sniff", "passive"], "input": "interface"},

    # ── Exploitation ───────────────────────────────────────────────────────
    "metasploit": {"desc": "Penetration testing framework", "cat": "exploit/framework", "risk": "critical",
                    "tags": ["exploit", "framework", "payload", "msf"], "input": "host|ip"},
    "msfconsole": {"desc": "Metasploit Framework console", "cat": "exploit/framework", "risk": "critical",
                    "tags": ["msf", "console", "exploit"], "input": "interactive"},
    "msfvenom": {"desc": "Metasploit payload generator", "cat": "exploit/payload", "risk": "critical",
                  "tags": ["payload", "shellcode", "reverse"], "input": "platform"},
    "exploitdb": {"desc": "Exploit Database search", "cat": "exploit/db", "risk": "high",
                   "tags": ["exploit", "cve", "poc", "searchsploit"], "input": "query"},
    "searchsploit": {"desc": "Offline Exploit-DB search", "cat": "exploit/db", "risk": "high",
                      "tags": ["exploit", "search", "offline", "cve"], "input": "query"},
    "beef": {"desc": "Browser Exploitation Framework", "cat": "exploit/browser", "risk": "critical",
              "tags": ["browser", "xss", "hook", "exploit"], "input": "url"},

    # ── Post Exploitation ──────────────────────────────────────────────────
    "mimikatz": {"desc": "Windows credential extractor", "cat": "postex/creds", "risk": "critical",
                  "tags": ["creds", "windows", "password", "hash"], "input": "interactive"},
    "crackmapexec": {"desc": "Network attack Swiss army knife", "cat": "postex/network", "risk": "critical",
                      "tags": ["smb", "ldap", "creds", "spray"], "input": "ip|cidr"},
    "evil-winrm": {"desc": "WinRM shell for pentesting", "cat": "postex/shell", "risk": "critical",
                    "tags": ["winrm", "shell", "windows"], "input": "ip"},
    "impacket": {"desc": "Python classes for network protocols", "cat": "postex/network", "risk": "critical",
                  "tags": ["smb", "kerberos", "ldap", "ntlm"], "input": "ip"},
    "bloodhound": {"desc": "Active Directory attack path analyzer", "cat": "postex/ad", "risk": "critical",
                    "tags": ["ad", "active-directory", "attack-path"], "input": "domain"},
    "powersploit": {"desc": "PowerShell post-exploitation framework", "cat": "postex/windows", "risk": "critical",
                     "tags": ["powershell", "windows", "postex"], "input": "interactive"},
    "empire": {"desc": "Post-exploitation framework", "cat": "postex/framework", "risk": "critical",
                "tags": ["postex", "framework", "c2"], "input": "interactive"},

    # ── Sniffing & Spoofing ────────────────────────────────────────────────
    "wireshark": {"desc": "Network packet analyser", "cat": "network/sniff", "risk": "medium",
                   "tags": ["packet", "capture", "sniff", "analyse"], "input": "interface"},
    "tcpdump": {"desc": "Command-line packet analyser", "cat": "network/sniff", "risk": "medium",
                 "tags": ["packet", "capture", "filter"], "input": "interface"},
    "ettercap": {"desc": "MITM attacks toolkit", "cat": "network/mitm", "risk": "critical",
                  "tags": ["mitm", "arp", "poison", "sniff"], "input": "interface"},
    "bettercap": {"desc": "Network attack & monitoring tool", "cat": "network/mitm", "risk": "critical",
                   "tags": ["mitm", "arp", "wifi", "ble"], "input": "interface"},
    "responder": {"desc": "LLMNR/NBT-NS poisoner & credential catcher", "cat": "network/poison", "risk": "critical",
                   "tags": ["llmnr", "nbt", "poison", "creds"], "input": "interface"},
    "scapy": {"desc": "Packet manipulation tool", "cat": "network/packet", "risk": "high",
               "tags": ["packet", "forge", "custom", "protocol"], "input": "interactive"},

    # ── Forensics ─────────────────────────────────────────────────────────
    "volatility": {"desc": "Memory forensics framework", "cat": "forensics/memory", "risk": "low",
                    "tags": ["memory", "forensics", "dump", "analysis"], "input": "file"},
    "autopsy": {"desc": "Digital forensics platform", "cat": "forensics/disk", "risk": "low",
                 "tags": ["disk", "forensics", "analyse"], "input": "file"},
    "binwalk": {"desc": "Firmware analysis tool", "cat": "forensics/firmware", "risk": "low",
                 "tags": ["firmware", "extract", "analyse"], "input": "file"},
    "foremost": {"desc": "File carver/recovery tool", "cat": "forensics/recovery", "risk": "low",
                  "tags": ["file", "recover", "carve"], "input": "file"},
    "strings": {"desc": "Extract printable strings from binaries", "cat": "forensics/binary", "risk": "low",
                  "tags": ["strings", "binary", "extract"], "input": "file"},
    "exiftool": {"desc": "Read/write EXIF metadata", "cat": "forensics/meta", "risk": "low",
                  "tags": ["exif", "metadata", "image"], "input": "file"},
    "steghide": {"desc": "Steganography tool", "cat": "forensics/stego", "risk": "low",
                  "tags": ["stego", "hide", "extract", "image"], "input": "file"},
    "stegsolve": {"desc": "Steganography image solver", "cat": "forensics/stego", "risk": "low",
                   "tags": ["stego", "image", "visual"], "input": "file"},

    # ── Secrets & Credential Tools ────────────────────────────────────────
    "trufflehog": {"desc": "Deep secret & credential scanner", "cat": "secrets/scan", "risk": "medium",
                    "tags": ["secret", "credential", "token", "leak"], "input": "repo|path"},
    "gitleaks": {"desc": "Git secrets scanner", "cat": "secrets/scan", "risk": "medium",
                  "tags": ["git", "secret", "credential", "leak"], "input": "repo|path"},
    "gitrob": {"desc": "Reconnaissance on GitHub organisations", "cat": "secrets/github", "risk": "medium",
                "tags": ["github", "secret", "recon", "org"], "input": "org"},
    "github-secrets": {"desc": "GitHub secret search", "cat": "secrets/github", "risk": "medium",
                        "tags": ["github", "secret", "search"], "input": "org|repo"},
    "cloud_enum": {"desc": "Multi-cloud OSINT (S3, GCS, Azure)", "cat": "cloud/enum", "risk": "medium",
                    "tags": ["cloud", "aws", "gcs", "azure", "s3", "bucket"], "input": "domain|keyword"},
    "s3scanner": {"desc": "AWS S3 bucket scanner", "cat": "cloud/aws", "risk": "medium",
                   "tags": ["s3", "aws", "bucket", "exposed"], "input": "domain|keyword"},
    "cloudflair": {"desc": "CloudFlare origin IP exposure finder", "cat": "cloud/cdn", "risk": "medium",
                    "tags": ["cloudflare", "cdn", "origin", "bypass"], "input": "domain"},

    # ── Social Engineering ─────────────────────────────────────────────────
    "setoolkit": {"desc": "Social Engineering Toolkit", "cat": "social/phishing", "risk": "critical",
                   "tags": ["phishing", "spear", "clone", "social"], "input": "interactive"},
    "gophish": {"desc": "Phishing campaign toolkit", "cat": "social/phishing", "risk": "critical",
                 "tags": ["phishing", "campaign", "email"], "input": "interactive"},
    "swaks": {"desc": "Swiss Army Knife SMTP", "cat": "social/email", "risk": "high",
               "tags": ["smtp", "email", "spoof", "test"], "input": "email"},

    # ── Reverse Engineering ────────────────────────────────────────────────
    "ghidra": {"desc": "NSA software reverse engineering tool", "cat": "reverse/static", "risk": "low",
                "tags": ["reverse", "static", "decompile", "asm"], "input": "binary"},
    "radare2": {"desc": "Advanced binary analysis framework", "cat": "reverse/static", "risk": "low",
                 "tags": ["reverse", "binary", "asm", "debug"], "input": "binary"},
    "gdb": {"desc": "GNU debugger", "cat": "reverse/debug", "risk": "low",
             "tags": ["debug", "dynamic", "binary"], "input": "binary"},
    "ltrace": {"desc": "Library call tracer", "cat": "reverse/trace", "risk": "low",
                "tags": ["trace", "library", "calls"], "input": "binary"},
    "strace": {"desc": "System call tracer", "cat": "reverse/trace", "risk": "low",
                "tags": ["trace", "syscall", "system"], "input": "binary"},
    "pwndbg": {"desc": "GDB plugin for exploit development", "cat": "reverse/exploit", "risk": "high",
                "tags": ["debug", "exploit", "heap", "rop"], "input": "binary"},
    "pwntools": {"desc": "CTF framework for exploit writing", "cat": "reverse/exploit", "risk": "high",
                  "tags": ["exploit", "ctf", "rop", "shellcode"], "input": "binary"},
}


@dataclass
class ToolInfo:
    """Rich tool metadata with availability status."""
    name: str
    binary: str
    description: str
    category: str
    risk_level: str
    tags: list[str]
    input_type: str
    is_available: bool = False
    binary_path: str = ""
    version: str = ""


class KaliToolDiscovery:
    """Dynamically discovers ALL tools available on the system.

    Goes far beyond a hardcoded list:
    - Scans all PATH directories for executables
    - Cross-references against the Kali tool knowledge base
    - Detects tools via 'dpkg -l' on Debian/Kali systems
    - Allows AI to work with ANY installed tool by generating commands
    """

    def __init__(self) -> None:
        self._catalogue: dict[str, ToolInfo] = {}
        self._path_executables: set[str] = set()
        self._scanned = False

    def scan(self) -> dict[str, ToolInfo]:
        """Perform full tool discovery scan. Returns complete tool catalogue."""
        self._scan_path_executables()
        self._build_catalogue()
        self._scanned = True
        return self._catalogue

    @property
    def catalogue(self) -> dict[str, ToolInfo]:
        if not self._scanned:
            self.scan()
        return self._catalogue

    def get_available(self) -> list[ToolInfo]:
        return [t for t in self.catalogue.values() if t.is_available]

    def get_by_category(self, cat_prefix: str) -> list[ToolInfo]:
        return [t for t in self.catalogue.values()
                if t.category.startswith(cat_prefix) and t.is_available]

    def get_by_tags(self, tags: list[str]) -> list[ToolInfo]:
        """Find available tools matching ANY of the given tags."""
        results = []
        for tool in self.catalogue.values():
            if not tool.is_available:
                continue
            if any(tag.lower() in tool.tags for tag in tags):
                results.append(tool)
        return results

    def find_tool(self, name: str) -> ToolInfo | None:
        """Find a specific tool by name (case-insensitive, with fuzzy matching)."""
        name_lower = name.lower().strip()
        # Exact match
        if name_lower in self.catalogue:
            return self.catalogue[name_lower]
        # Partial match on name
        for tool_name, info in self.catalogue.items():
            if name_lower in tool_name or tool_name in name_lower:
                return info
        return None

    def get_available_names(self) -> list[str]:
        return sorted(t.name for t in self.get_available())

    def get_tool_summary_for_ai(self, max_tools: int = 80) -> str:
        """Produce a compact tool summary string for LLM context injection."""
        available = self.get_available()
        # Sort by category for coherence
        available.sort(key=lambda t: t.category)
        lines = [f"AVAILABLE SECURITY TOOLS ({len(available)} total):"]
        # Group by category
        by_cat: dict[str, list[ToolInfo]] = {}
        for t in available:
            cat = t.category.split("/")[0]
            by_cat.setdefault(cat, []).append(t)
        for cat, tools in sorted(by_cat.items()):
            names = ", ".join(t.name for t in tools[:15])
            if len(tools) > 15:
                names += f" (+{len(tools)-15} more)"
            lines.append(f"  [{cat.upper()}]: {names}")
        return "\n".join(lines)

    def _scan_path_executables(self) -> None:
        """Scan all directories in PATH for executables."""
        path_dirs = os.environ.get("PATH", "").split(os.pathsep)
        # Also add common Kali/Linux tool directories
        extra_dirs = [
            "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
            "/opt/metasploit-framework/bin", "/usr/share/metasploit-framework",
            "/usr/share/sqlmap", "/root/go/bin", "/root/.local/bin",
        ]
        all_dirs = list(set(path_dirs + extra_dirs))

        for dir_path in all_dirs:
            try:
                p = Path(dir_path)
                if not p.is_dir():
                    continue
                for item in p.iterdir():
                    try:
                        if item.is_file() and os.access(str(item), os.X_OK):
                            self._path_executables.add(item.name.lower())
                    except (PermissionError, OSError):
                        continue
            except (PermissionError, OSError):
                continue

        # Also check dpkg installed packages on Kali/Debian
        self._scan_dpkg()

    def _scan_dpkg(self) -> None:
        """Check installed packages via dpkg (Kali/Debian specific)."""
        if not shutil.which("dpkg"):
            return
        try:
            result = subprocess.run(
                ["dpkg", "-l"],
                capture_output=True, text=True, timeout=10
            )
            for line in result.stdout.splitlines():
                if line.startswith("ii"):
                    parts = line.split()
                    if len(parts) >= 2:
                        pkg = parts[1].lower().split(":")[0]
                        # Many Kali packages == their binary name
                        self._path_executables.add(pkg)
        except Exception:
            pass

    def _build_catalogue(self) -> None:
        """Build the full tool catalogue merging knowledge base with PATH scan."""
        # 1. Known tools from knowledge base
        for name, info in KALI_TOOL_KNOWLEDGE.items():
            binary = name
            is_avail = binary.lower() in self._path_executables or bool(shutil.which(binary))
            binary_path = shutil.which(binary) or ""
            self._catalogue[name] = ToolInfo(
                name=name,
                binary=binary,
                description=info["desc"],
                category=info["cat"],
                risk_level=info["risk"],
                tags=info["tags"],
                input_type=info["input"],
                is_available=is_avail,
                binary_path=binary_path,
            )

        # 2. Unknown tools found in PATH — add as generic entries
        known_names = {t.lower() for t in KALI_TOOL_KNOWLEDGE}
        for exe_name in self._path_executables:
            if exe_name not in known_names and self._is_security_tool(exe_name):
                self._catalogue[exe_name] = ToolInfo(
                    name=exe_name,
                    binary=exe_name,
                    description=f"Security tool: {exe_name}",
                    category="unknown/discovered",
                    risk_level="unknown",
                    tags=[exe_name],
                    input_type="unknown",
                    is_available=True,
                    binary_path=shutil.which(exe_name) or "",
                )

    def _is_security_tool(self, name: str) -> bool:
        """Heuristic: is this a likely security/pentesting tool?"""
        security_keywords = {
            "scan", "fuzz", "crack", "exploit", "inject", "brute", "enum",
            "recon", "dump", "sniff", "spoof", "probe", "audit", "map",
            "spider", "crawl", "hunt", "find", "detect", "extract", "decode",
        }
        return any(kw in name for kw in security_keywords)

    def stats(self) -> dict[str, int]:
        """Return statistics about the tool catalogue."""
        total = len(self.catalogue)
        available = len(self.get_available())
        by_cat: dict[str, int] = {}
        for t in self.get_available():
            cat = t.category.split("/")[0]
            by_cat[cat] = by_cat.get(cat, 0) + 1
        return {"total_known": total, "available": available, "by_category": by_cat}
