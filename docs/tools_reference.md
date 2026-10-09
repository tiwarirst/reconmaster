# ReconAI Offensive Tools & Fallbacks Reference

## 1. Overview

ReconAI integrates 24+ industry-standard offensive reconnaissance, web auditing, and vulnerability discovery utilities.

Each integration follows the **stateless adapter pattern** ([reconai/integrations/](file:///c:/Users/rishu%20tiwari/OneDrive/Desktop/reconmaster/reconai/integrations/)):
1. **Detection**: Automatically detects binary presence via system `$PATH` or custom `tools.<name>.path` in [config.yaml](file:///c:/Users/rishu%20tiwari/OneDrive/Desktop/reconmaster/config.yaml).
2. **Execution**: Builds validated arguments and executes via memory-safe, non-blocking async subprocesses.
3. **Parsing**: Translates stdout/JSON/XML into normalized database records.
4. **Autonomous Fallback**: If the external binary is missing, the corresponding module automatically executes a pure-Python fallback.

---

## 2. Complete Tools Directory

### 2.1 HTTP & Web Asset Probing

#### `httpx` (ProjectDiscovery)
- **Role**: Fast multi-purpose HTTP toolkit for probing alive web servers and gathering tech signatures.
- **Flags Used**: `-tech-detect -status-code -title -follow-redirects -silent -json`
- **Config Key**: `tools.httpx` (threads, rate_limit, timeout, extra_args)
- **Pure-Python Fallback**: `httpx.AsyncClient` HTTP/2 probing with certificate inspection and redirect tracking.
- **Install**: `go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest`

#### `tlsx` (ProjectDiscovery)
- **Role**: TLS/SSL certificate analyzer, Subject Alternative Name (SAN) subdomain extractor, JARM fingerprinting.
- **Flags Used**: `-san -cn -resp-version -jarm -expired -silent -json`
- **Config Key**: `tools.tlsx` (threads, timeout, extra_args)
- **Pure-Python Fallback**: Python `socket` + `ssl` context handshake extracting SANs, expiration, and deprecated TLS ciphers.
- **Install**: `go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest`

#### `whatweb`
- **Role**: Next-generation web scanner identifying content management systems, blogging platforms, and JS libraries.
- **Flags Used**: `--color=never --no-errors -a 1`
- **Config Key**: `tools.whatweb` (timeout)
- **Pure-Python Fallback**: Built-in HTTP header and HTML regex pattern matching engine.
- **Install**: `sudo apt install whatweb`

#### `wafw00f`
- **Role**: Web Application Firewall fingerprinting tool.
- **Flags Used**: `-a -f json`
- **Config Key**: `tools.wafw00f` (timeout)
- **Pure-Python Fallback**: Built-in WAF signature checks (Cloudflare, AWS WAF, Akamai, Imperva, Sucuri).
- **Install**: `pip install wafw00f`

---

### 2.2 Subdomain & DNS Intelligence

#### `subfinder` (ProjectDiscovery)
- **Role**: Passive multi-source subdomain discovery.
- **Flags Used**: `-all -silent -json`
- **Config Key**: `tools.subfinder` (threads, timeout, extra_args)
- **Pure-Python Fallback**: Direct HTTP queries to crt.sh, HackerTarget, and AlienVault OTX APIs.
- **Install**: `go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest`

#### `dnsx` (ProjectDiscovery)
- **Role**: Multi-purpose high-speed DNS resolver and wildcard filtering engine.
- **Flags Used**: `-resp -rcode noerror -silent -json`
- **Config Key**: `tools.dnsx` (threads, timeout, extra_args)
- **Pure-Python Fallback**: `dnspython` asynchronous resolver pool.
- **Install**: `go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest`

#### `amass` (OWASP)
- **Role**: In-depth network mapping and external asset discovery.
- **Flags Used**: `enum -passive -silent -json`
- **Config Key**: `tools.amass` (timeout, extra_args)
- **Pure-Python Fallback**: Multi-engine passive certificate and DNS enumeration.
- **Install**: `sudo apt install amass` or `go install -v github.com/owasp-amass/amass/v4/...@master`

---

### 2.3 Port & Service Discovery

#### `naabu` (ProjectDiscovery)
- **Role**: Fast port scanner written in Go with low SYN packet overhead.
- **Flags Used**: `-top-ports 1000 -rate 1000 -silent -json`
- **Config Key**: `tools.naabu` (rate_limit, timeout, extra_args)
- **Pure-Python Fallback**: Async TCP connect port scanner.
- **Install**: `go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest`

#### `nmap`
- **Role**: Comprehensive service versioning, OS detection, and NSE scripting.
- **Flags Used**: `-T3 -sV --version-light` (or profile-driven `-sC -sV`)
- **Config Key**: `tools.nmap` (timeout, extra_args)
- **Pure-Python Fallback**: Socket banner grabbing and service probe matching.
- **Install**: `sudo apt install nmap` (Windows: `winget install Insecure.Nmap`)

---

### 2.4 Web Crawling & Parameter Mining

#### `katana` (ProjectDiscovery)
- **Role**: Next-generation web crawler with JavaScript rendering support.
- **Flags Used**: `-depth 3 -automatic-form-fill -silent -json`
- **Config Key**: `tools.katana` (threads, timeout, extra_args)
- **Pure-Python Fallback**: Async BeautifulSoup HTML parser and JavaScript regex link extractor.
- **Install**: `go install -v github.com/projectdiscovery/katana/cmd/katana@latest`

#### `arjun`
- **Role**: Hidden HTTP parameter discovery suite.
- **Flags Used**: `--passive -t 5 --json`
- **Config Key**: `tools.arjun` (threads, timeout, extra_args)
- **Pure-Python Fallback**: Differential parameter response analysis engine.
- **Install**: `pip install arjun` (or `sudo apt install arjun`)

#### `ffuf`
- **Role**: High-speed web fuzzer for directory brute-forcing and route discovery.
- **Flags Used**: `-t 20 -mc 200,204,301,302,307,401,403 -o ... -of json`
- **Config Key**: `tools.ffuf` (threads, rate_limit, timeout, extra_args)
- **Pure-Python Fallback**: Async HTTP directory prober against top common web wordlists.
- **Install**: `go install -v github.com/ffuf/ffuf/v2@latest`

#### `gau` (lc)
- **Role**: GetAllUrls fetching historical endpoints from AlienVault, Wayback, and CommonCrawl.
- **Flags Used**: `--subs --threads 5`
- **Config Key**: `tools.gau` (threads, timeout, extra_args)
- **Pure-Python Fallback**: Direct HTTP queries to Wayback CDX API and AlienVault OTX indicator endpoints.
- **Install**: `go install -v github.com/lc/gau/v2/cmd/gau@latest`

#### `waybackurls` (tomnomnom)
- **Role**: Archive URL harvester from Archive.org.
- **Flags Used**: Position-based `<domain>`
- **Config Key**: `tools.waybackurls` (timeout)
- **Pure-Python Fallback**: Direct Wayback Machine CDX API query.
- **Install**: `go install -v github.com/tomnomnom/waybackurls@latest`

---

### 2.5 Vulnerability & Exploit Auditing

#### `nuclei` (ProjectDiscovery)
- **Role**: Template-based vulnerability scanner covering thousands of CVEs and exposures.
- **Flags Used**: `-severity info,low,medium,high,critical -rate-limit 150 -stats -jsonl`
- **Config Key**: `tools.nuclei` (rate_limit, timeout, extra_args)
- **Pure-Python Fallback**: Heuristic exposure and pattern matching checks.
- **Install**: `go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`

#### `dalfox`
- **Role**: Parameter analysis and XSS scanner with DOM verification.
- **Flags Used**: `--skip-bav --silence --format json`
- **Config Key**: `tools.dalfox` (threads, timeout, extra_args)
- **Pure-Python Fallback**: Context-aware HTML entity reflection scanner.
- **Install**: `go install -v github.com/hahwul/dalfox/v2@latest`

#### `sqlmap`
- **Role**: Automated SQL injection detection and database fingerprinting.
- **Flags Used**: `--batch --level=1 --risk=1`
- **Config Key**: `tools.sqlmap` (timeout, extra_args)
- **Pure-Python Fallback**: Heuristic SQL error and syntax anomaly detector.
- **Install**: `sudo apt install sqlmap` or `pip install sqlmap`

#### `subzy`
- **Role**: Automated subdomain takeover checker across 20+ service fingerprints.
- **Flags Used**: `--hide_fails --concurrency 15`
- **Config Key**: `tools.subzy` (threads, timeout, extra_args)
- **Pure-Python Fallback**: CNAME response inspector matching dangling AWS S3, GitHub Pages, Heroku, etc.
- **Install**: `go install -v github.com/PentestPad/subzy@latest`

#### `gitleaks`
- **Role**: Ultra-fast secret detection using regex rules.
- **Flags Used**: `detect --no-git --report-format json`
- **Config Key**: `tools.gitleaks` (timeout, extra_args)
- **Pure-Python Fallback**: High-entropy token and regex pattern analyzer.
- **Install**: `brew install gitleaks` or `go install -v github.com/zricethezav/gitleaks/v8@latest`

#### `trufflehog`
- **Role**: Deep secret scanning with live verification against target providers.
- **Flags Used**: `filesystem --json`
- **Config Key**: `tools.trufflehog` (timeout)
- **Pure-Python Fallback**: Shannon entropy secret analyzer.
- **Install**: `go install -v github.com/trufflesecurity/trufflehog/v3@latest`

#### `gowitness`
- **Role**: Headless Chrome web screenshot utility for visual reconnaissance.
- **Flags Used**: `file -f <urls> --screenshot-path <out> --timeout 15`
- **Config Key**: `tools.gowitness` (timeout, extra_args)
- **Pure-Python Fallback**: System Chrome/Edge automation via DevTools Protocol (CDP).
- **Install**: `go install -v github.com/sensepost/gowitness@latest`

#### `cloud_enum`
- **Role**: Multi-cloud public resource enumeration (AWS S3, Azure Blob, Google Cloud Storage).
- **Flags Used**: `-k <keyword> -l <logfile> --disable-aws/azure/gcp`
- **Config Key**: `tools.cloud_enum` (threads, timeout)
- **Pure-Python Fallback**: Direct HTTP probes against standard cloud bucket URL conventions.
- **Install**: `pip install cloud-enum`
