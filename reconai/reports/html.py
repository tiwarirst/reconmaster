"""HTML Report Generator for ReconAI."""
from __future__ import annotations

import base64
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

if TYPE_CHECKING:
    from reconai.core.database.manager import DatabaseManager


_HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconAI Report — {target}</title>
<style>
  :root {{
    --bg:#0d1117;--card:#161b22;--border:#30363d;--text:#c9d1d9;--accent:#58a6ff;
    --critical:#f85149;--high:#d29922;--medium:#3fb950;--low:#8b949e;
  }}
  * {{ box-sizing:border-box; margin:0; padding:0; }}
  body {{ background:var(--bg); color:var(--text); font-family:'Segoe UI',-apple-system,BlinkMacSystemFont,Roboto,sans-serif; padding:2rem; }}
  h1 {{ color:var(--accent); font-size:2rem; margin-bottom:0.25rem; }}
  h2 {{ color:var(--accent); font-size:1.25rem; margin:2.5rem 0 1rem; border-bottom:1px solid var(--border); padding-bottom:0.5rem; }}
  .meta {{ color:var(--low); font-size:0.85rem; margin-bottom:2rem; }}
  .score-box {{ display:inline-block; padding:1rem 2rem; border-radius:8px; background:var(--card); border:2px solid var(--border); margin-bottom:2rem; text-align:center; }}
  .score-box .score {{ font-size:3rem; font-weight:700; color:var(--accent); }}
  .score-box .grade {{ font-size:1.5rem; color:var(--high); }}
  .stats-grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:1rem; margin-bottom:2rem; }}
  .stat-card {{ background:var(--card); border:1px solid var(--border); border-radius:8px; padding:1rem; text-align:center; }}
  .stat-card .val {{ font-size:2rem; font-weight:700; color:var(--accent); }}
  .stat-card .lbl {{ font-size:0.8rem; color:var(--low); }}
  table {{ width:100%; border-collapse:collapse; background:var(--card); border-radius:8px; overflow:hidden; margin-bottom:2rem; }}
  th {{ background:var(--border); padding:0.75rem 1rem; text-align:left; font-size:0.85rem; color:var(--text); }}
  td {{ padding:0.75rem 1rem; border-top:1px solid var(--border); font-size:0.85rem; }}
  tr:hover {{ background:rgba(88,166,255,0.03); }}
  .sev-critical {{ color:var(--critical); font-weight:700; }}
  .sev-high {{ color:var(--high); font-weight:700; }}
  .sev-medium {{ color:var(--medium); }}
  .sev-low {{ color:var(--low); }}
  .sev-info {{ color:var(--low); opacity:.7; }}
  .badge {{ display:inline-block; padding:2px 8px; border-radius:4px; font-size:0.75rem; font-weight:700; text-transform:uppercase; }}
  .badge-aws {{ background:#ff9900; color:#111; }}
  .badge-gcp {{ background:#4285f4; color:#fff; }}
  .badge-azure {{ background:#0089d6; color:#fff; }}
  .badge-other {{ background:var(--border); color:var(--text); }}
  .badge-method {{ display:inline-block; padding:2px 6px; border-radius:4px; font-weight:700; font-size:0.75rem; }}
  .badge-get {{ background:rgba(63,185,80,0.15); color:#3fb950; }}
  .badge-post {{ background:rgba(88,166,255,0.15); color:#58a6ff; }}
  .badge-status {{ display:inline-block; padding:2px 6px; border-radius:4px; font-weight:700; font-size:0.75rem; }}
  .status-2xx {{ color:#3fb950; background:rgba(63,185,80,0.1); }}
  .status-3xx {{ color:#58a6ff; background:rgba(88,166,255,0.1); }}
  .status-4xx {{ color:#d29922; background:rgba(210,153,34,0.1); }}
  .status-5xx {{ color:#f85149; background:rgba(248,81,73,0.1); }}
  .public-tag {{ color:var(--critical); font-weight:700; }}
  .writable-tag {{ background:var(--critical); color:#fff; padding:2px 6px; border-radius:4px; font-weight:700; }}
  .chain-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(340px,1fr)); gap:1rem; margin-bottom:2rem; }}
  .chain-card {{ background:var(--card); border:1px solid var(--border); border-left:4px solid var(--accent); border-radius:8px; padding:1.25rem; font-size:0.85rem; }}
  .chain-card.has-findings {{ border-left:4px solid var(--critical); }}
  .chain-host {{ font-size:1.05rem; font-weight:700; color:#fff; margin-bottom:0.5rem; word-break:break-all; }}
  .chain-meta {{ margin-bottom:0.35rem; color:var(--low); }}
  .chain-tag {{ display:inline-block; background:rgba(88,166,255,0.15); color:var(--accent); padding:2px 6px; border-radius:4px; margin:2px; font-size:0.75rem; }}
  .chain-tag-port {{ background:rgba(63,185,80,0.15); color:var(--medium); }}
  .chain-tag-find {{ background:rgba(248,81,73,0.15); color:var(--critical); font-weight:700; }}
  .gallery-grid {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(300px,1fr)); gap:1.25rem; margin-bottom:2rem; }}
  .screenshot-card {{ background:var(--card); border:1px solid var(--border); border-radius:8px; overflow:hidden; transition:transform 0.2s, border-color 0.2s; }}
  .screenshot-card:hover {{ transform:translateY(-3px); border-color:var(--accent); }}
  .screenshot-card a {{ display:block; text-decoration:none; }}
  .screenshot-card img {{ width:100%; height:190px; object-fit:cover; display:block; border-bottom:1px solid var(--border); background:#000; }}
  .screenshot-caption {{ padding:0.75rem 1rem; font-size:0.8rem; color:var(--text); word-break:break-all; }}
  .url-link {{ color:var(--accent); text-decoration:none; word-break:break-all; }}
  .url-link:hover {{ text-decoration:underline; }}
</style>
</head>
<body>
<h1>&#128270; ReconAI Attack Surface Report</h1>
<div class="meta">
  <strong>Target:</strong> {target} &nbsp;|&nbsp;
  <strong>Scan ID:</strong> {scan_id} &nbsp;|&nbsp;
  <strong>Date:</strong> {date} &nbsp;|&nbsp;
  <strong>Duration:</strong> {duration}s
</div>

<h2>Risk Assessment</h2>
<div class="score-box">
  <div class="score">{risk_score}</div>
  <div>/100</div>
  <div class="grade">Grade: {risk_grade}</div>
</div>

<h2>Attack Surface Overview</h2>
<div class="stats-grid">
  {stats_cards}
</div>

<h2>🔗 Correlated Attack Surface & Topology Paths</h2>
{correlation_section}

<h2>Security Findings ({findings_count})</h2>
{findings_table}

<h2>📸 Visual Screenshots Gallery ({screenshot_count})</h2>
{screenshots_gallery}

<h2>🕷️ Crawled Web Endpoints & URLs ({url_count})</h2>
{urls_table}

<h2>🔌 Discovered API Routes & Endpoints ({api_count})</h2>
{apis_table}

<h2>Cloud Assets & Storage ({cloud_count})</h2>
{cloud_table}

<h2>Subdomains ({sub_count})</h2>
{subdomains_table}

<h2>Open Ports ({ports_count})</h2>
{ports_table}

<h2>Technologies Detected ({techs_count})</h2>
{techs_table}

<footer style="margin-top:4rem;color:var(--low);font-size:0.75rem;text-align:center;">
  Generated by ReconAI &mdash; Comprehensive Attack Surface Reconnaissance Platform
</footer>
</body>
</html>"""


def _stat_card(label: str, value: int | str) -> str:
    return f'<div class="stat-card"><div class="val">{value}</div><div class="lbl">{label}</div></div>'


def _sev_class(severity: str) -> str:
    return f"sev-{severity.lower()}"


def generate_html_report(db: "DatabaseManager", scan_id: str, out_dir: Path) -> Path:
    """Generate a full HTML report with visual screenshot gallery, crawled URLs, and API endpoints."""
    from reconai.reports.scoring import RiskScoringEngine

    scan = db.get_scan(scan_id)
    if not scan:
        raise ValueError(f"Scan {scan_id} not found")

    stats = db.get_scan_stats(scan_id)
    findings = db.get_findings(scan_id)
    subs = db.get_subdomains(scan_id)
    ports = db.get_ports(scan_id)
    techs = db.get_technologies(scan_id)
    cloud_assets = db.get_cloud_assets(scan_id)
    urls = db.get_urls(scan_id)
    apis = db.get_api_endpoints(scan_id)
    risk = RiskScoringEngine(db, scan_id).calculate_score()

    # Search for captured PNG screenshots in out_dir.parent / "screenshots" and recursive folders
    screenshots_base = out_dir.parent / "screenshots"
    png_files: list[Path] = []
    if screenshots_base.exists():
        png_files = list(screenshots_base.rglob("*.png"))

    # Stats cards
    stats_cards = "".join([
        _stat_card("Subdomains", stats.get("subdomains", 0)),
        _stat_card("Open Ports", stats.get("ports", 0)),
        _stat_card("Crawled URLs", len(urls)),
        _stat_card("API Endpoints", len(apis)),
        _stat_card("Screenshots", len(png_files)),
        _stat_card("Technologies", stats.get("technologies", 0)),
        _stat_card("Findings", stats.get("findings", 0)),
        _stat_card("Cloud Assets", stats.get("cloud_assets", 0)),
    ])

    # 1. Findings table
    if findings:
        rows = "".join(
            f'<tr><td class="{_sev_class(f["severity"])}">{f["severity"].upper()}</td>'
            f'<td><strong>{f["title"]}</strong></td><td><code>{f["affected_asset"]}</code></td>'
            f'<td>{f["confidence"]}</td></tr>'
            for f in findings
        )
        findings_table = f'<table><tr><th>Severity</th><th>Title</th><th>Affected Asset</th><th>Confidence</th></tr>{rows}</table>'
    else:
        findings_table = "<p style='color:var(--low);'>No security vulnerabilities discovered.</p>"

    # 2. Visual Screenshots Gallery
    if png_files:
        card_htmls = []
        for p in png_files[:24]:  # Top 24 screenshots
            rel_path = f"../screenshots/{p.relative_to(screenshots_base).as_posix()}"
            caption = p.stem.replace("_", " ")[:60]
            card_htmls.append(
                f'<div class="screenshot-card">'
                f'<a href="{rel_path}" target="_blank">'
                f'<img src="{rel_path}" alt="{caption}" loading="lazy">'
                f'<div class="screenshot-caption">{caption}</div>'
                f'</a></div>'
            )
        screenshots_gallery = f'<div class="gallery-grid">{"".join(card_htmls)}</div>'
        if len(png_files) > 24:
            screenshots_gallery += f'<p style="color:var(--low);">... and {len(png_files) - 24} more screenshots saved in output directory.</p>'
    else:
        screenshots_gallery = "<p style='color:var(--low);'>No visual screenshots captured for this scan.</p>"

    # 3. Crawled Web Endpoints & URLs table
    if urls:
        u_rows = []
        for u in urls[:150]:  # Cap at top 150 in HTML
            status = u.get("status_code")
            if status is not None:
                st_int = int(status)
                st_cls = f"status-{st_int // 100}xx"
                st_badge = f'<span class="badge-status {st_cls}">{st_int}</span>'
            else:
                st_badge = '<span class="badge-status" style="color:var(--low);">—</span>'

            method = str(u.get("method") or "GET").upper()
            m_badge = f'<span class="badge-method badge-{method.lower()}">{method}</span>'
            url_str = str(u.get("url") or "")
            source = str(u.get("source") or "crawler")
            content_type = str(u.get("content_type") or "").split(";")[0]

            u_rows.append(
                f'<tr>'
                f'<td>{m_badge}</td>'
                f'<td>{st_badge}</td>'
                f'<td><a class="url-link" href="{url_str}" target="_blank" rel="noopener">{url_str}</a></td>'
                f'<td><code>{content_type}</code></td>'
                f'<td><span class="badge badge-other">{source}</span></td>'
                f'</tr>'
            )
        urls_table = (
            '<table><tr><th>Method</th><th>Status</th><th>URL</th><th>Type</th><th>Source</th></tr>'
            + "".join(u_rows) + '</table>'
        )
        if len(urls) > 150:
            urls_table += f'<p style="color:var(--low);">... showing top 150 of {len(urls)} URLs (full list available in report.json and csv/urls.csv).</p>'
    else:
        urls_table = "<p style='color:var(--low);'>No web URLs crawled.</p>"

    # 4. Discovered API Endpoints table
    if apis:
        api_rows = []
        for a in apis[:100]:
            method = str(a.get("method") or "GET").upper()
            m_badge = f'<span class="badge-method badge-{method.lower()}">{method}</span>'
            path = str(a.get("path") or "/")
            full_url = str(a.get("full_url") or "")
            api_type = str(a.get("api_type") or "REST")
            source = str(a.get("source") or "api_miner")
            link = f'<a class="url-link" href="{full_url}" target="_blank">{path}</a>' if full_url else f'<code>{path}</code>'

            api_rows.append(
                f'<tr>'
                f'<td>{m_badge}</td>'
                f'<td>{link}</td>'
                f'<td><code>{a.get("host", "")}</code></td>'
                f'<td><span class="badge badge-other">{api_type}</span></td>'
                f'<td><span class="badge badge-other">{source}</span></td>'
                f'</tr>'
            )
        apis_table = (
            '<table><tr><th>Method</th><th>Endpoint Path</th><th>Host</th><th>Type</th><th>Source</th></tr>'
            + "".join(api_rows) + '</table>'
        )
    else:
        apis_table = "<p style='color:var(--low);'>No distinct API endpoints detected.</p>"

    # 5. Cloud Assets table
    if cloud_assets:
        def _prov_badge(prov: str) -> str:
            p = prov.lower()
            badge_cls = f"badge-{p}" if p in ("aws", "gcp", "azure") else "badge-other"
            return f'<span class="badge {badge_cls}">{prov.upper()}</span>'

        c_rows = []
        for c in cloud_assets:
            pub_tag = '<span class="public-tag">🚨 PUBLIC</span>' if c.get("is_public") else '<span style="color:var(--low);">Private</span>'
            writ_tag = '<span class="writable-tag">⚠️ WRITABLE</span>' if c.get("is_writable") else '<span style="color:var(--low);">Read-Only</span>'
            url = c.get("url", "")
            link = f'<a href="{url}" target="_blank" style="color:var(--accent);text-decoration:none;">{c.get("asset_name")}</a>' if url else c.get("asset_name")
            c_rows.append(
                f'<tr><td>{_prov_badge(c.get("provider", ""))}</td>'
                f'<td>{c.get("asset_type", "").replace("_", " ").title()}</td>'
                f'<td>{link}</td>'
                f'<td>{pub_tag}</td>'
                f'<td>{writ_tag}</td></tr>'
            )
        cloud_table = (
            '<table><tr><th>Provider</th><th>Type</th><th>Asset Name / URL</th>'
            '<th>Exposure</th><th>Permission</th></tr>' + "".join(c_rows) + '</table>'
        )
    else:
        cloud_table = "<p style='color:var(--low);'>No cloud assets or storage buckets discovered.</p>"

    # 6. Subdomains table
    if subs:
        rows = "".join(f'<tr><td><code>{s["subdomain"]}</code></td><td>{"&#9989;" if s.get("is_alive") else ""}</td></tr>' for s in subs[:100])
        subdomains_table = f'<table><tr><th>Subdomain</th><th>Alive</th></tr>{rows}</table>'
        if len(subs) > 100:
            subdomains_table += f'<p style="color:var(--low);">... and {len(subs)-100} more in JSON report.</p>'
    else:
        subdomains_table = "<p style='color:var(--low);'>No subdomains discovered.</p>"

    # 7. Ports table
    if ports:
        rows = "".join(
            f'<tr><td><code>{p["host"]}</code></td><td><strong>{p["port"]}</strong>/{p["protocol"]}</td>'
            f'<td>{p["service"]}</td><td>{p["product"]} {p["version"]}</td></tr>'
            for p in ports
        )
        ports_table = f'<table><tr><th>Host</th><th>Port</th><th>Service</th><th>Product/Version</th></tr>{rows}</table>'
    else:
        ports_table = "<p style='color:var(--low);'>No open ports discovered.</p>"

    # 8. Technologies table
    if techs:
        rows = "".join(
            f'<tr><td><code>{t["host"]}</code></td><td><strong>{t["name"]}</strong></td>'
            f'<td>{t["version"] or "—"}</td><td>{t["category"]}</td></tr>'
            for t in techs
        )
        techs_table = f'<table><tr><th>Host</th><th>Technology</th><th>Version</th><th>Category</th></tr>{rows}</table>'
    else:
        techs_table = "<p style='color:var(--low);'>No technologies detected.</p>"

    # 9. Correlation Chains
    from reconai.core.correlation.engine import CorrelationEngine
    correlation_engine = CorrelationEngine(db, scan_id)
    chains = correlation_engine.get_correlated_chains()
    if chains:
        card_htmls = []
        for ch in chains[:30]:
            has_finds = bool(ch.get("findings"))
            card_cls = "chain-card has-findings" if has_finds else "chain-card"
            ips_html = "".join(f'<span class="chain-tag">{ip}</span>' for ip in ch.get("ips", [])) or '<span style="color:var(--low);">No IP</span>'
            ports_html = "".join(f'<span class="chain-tag chain-tag-port">{p}</span>' for p in ch.get("ports", [])) or '<span style="color:var(--low);">None</span>'
            tech_html = "".join(f'<span class="chain-tag">{t}</span>' for t in ch.get("technologies", [])) or '<span style="color:var(--low);">None</span>'
            
            finds_html = ""
            if has_finds:
                finds_html = '<div style="margin-top:0.5rem;"><strong>🚨 Correlated Findings:</strong><br>' + "".join(
                    f'<span class="chain-tag chain-tag-find">[{f["severity"].upper()}] {f["title"]}</span>'
                    for f in ch["findings"]
                ) + '</div>'

            card_htmls.append(
                f'<div class="{card_cls}">'
                f'<div class="chain-host">🌐 {ch["host"]}</div>'
                f'<div class="chain-meta"><strong>IPs:</strong> {ips_html}</div>'
                f'<div class="chain-meta"><strong>Ports:</strong> {ports_html}</div>'
                f'<div class="chain-meta"><strong>Technologies:</strong> {tech_html}</div>'
                f'{finds_html}'
                f'</div>'
            )
        correlation_section = f'<div class="chain-grid">{"".join(card_htmls)}</div>'
    else:
        correlation_section = "<p style='color:var(--low);'>No correlated attack surface chains discovered.</p>"

    html = _HTML_TEMPLATE.format(
        target=scan["target"],
        scan_id=scan_id,
        date=scan["started_at"],
        duration=f"{scan.get('duration', 0):.1f}",
        risk_score=risk.get("score", 0),
        risk_grade=risk.get("grade", "N/A"),
        stats_cards=stats_cards,
        correlation_section=correlation_section,
        findings_count=len(findings),
        findings_table=findings_table,
        screenshot_count=len(png_files),
        screenshots_gallery=screenshots_gallery,
        url_count=len(urls),
        urls_table=urls_table,
        api_count=len(apis),
        apis_table=apis_table,
        cloud_count=len(cloud_assets),
        cloud_table=cloud_table,
        sub_count=len(subs),
        subdomains_table=subdomains_table,
        ports_count=len(ports),
        ports_table=ports_table,
        techs_count=len(techs),
        techs_table=techs_table,
    )

    out_file = out_dir / "report.html"
    out_file.write_text(html, encoding="utf-8")
    return out_file
