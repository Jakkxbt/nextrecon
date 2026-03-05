#!/usr/bin/env python3
"""
nextrecon — Next.js & JS Bundle Recon Tool
Extracts __NEXT_DATA__, env vars, secrets, API endpoints, routes, and more.
By CobraSEC
"""

import re
import sys
import json
import argparse
from pathlib import Path
from datetime import datetime
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich import box
from rich.text import Text

# ── Config ────────────────────────────────────────────────────────────────────

BANNER = r"""[bold red]
 ███╗   ██╗███████╗██╗  ██╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ████╗  ██║██╔════╝╚██╗██╔╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██╔██╗ ██║█████╗   ╚███╔╝    ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║╚██╗██║██╔══╝   ██╔██╗    ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║ ╚████║███████╗██╔╝ ██╗   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝[/bold red]
[dim red]  Next.js & JS Bundle Recon  ·  CobraSEC  ·  BYOK  ·  NO LEASH[/dim red]
"""

console = Console()

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

TIMEOUT = 15
MAX_CHUNKS = 50  # Max JS chunks to download per target

# ── Secret Patterns ──────────────────────────────────────────────────────────

SECRETS = {
    # Cloud / Infra
    "AWS Access Key":       (r"AKIA[0-9A-Z]{16}", "CRITICAL"),
    "AWS Secret Key":       (r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]", "CRITICAL"),
    "GCP API Key":          (r"AIza[0-9A-Za-z\-_]{35}", "CRITICAL"),
    "Firebase Config":      (r"\"apiKey\"\s*:\s*\"AIza[0-9A-Za-z\-_]{35}\"", "CRITICAL"),
    "Firebase Database":    (r"https://[a-z0-9\-]+\.firebaseio\.com", "HIGH"),
    "Firebase Storage":     (r"gs://[a-z0-9\-]+\.appspot\.com", "HIGH"),
    # Payment
    "Stripe Secret Key":    (r"sk_live_[0-9a-zA-Z]{24,}", "CRITICAL"),
    "Stripe Publishable":   (r"pk_live_[0-9a-zA-Z]{24,}", "HIGH"),
    "Stripe Test Secret":   (r"sk_test_[0-9a-zA-Z]{24,}", "MEDIUM"),
    "PayPal Client ID":     (r"(?i)paypal.{0,10}client.{0,10}['\"][A-Za-z0-9\-_]{20,}['\"]", "HIGH"),
    # Auth / Identity
    "JWT Token":            (r"eyJ[A-Za-z0-9_/+\-]{20,}\.[A-Za-z0-9_/+\-]{20,}\.[A-Za-z0-9_/+\-]{20,}", "HIGH"),
    "Auth0 Client ID":      (r"(?i)auth0.{0,20}client.{0,20}['\"][A-Za-z0-9\-_]{20,}['\"]", "MEDIUM"),
    "Okta Client ID":       (r"(?i)okta.{0,20}['\"][0-9a-zA-Z]{20,}['\"]", "MEDIUM"),
    # Messaging / Email
    "Sendgrid API Key":     (r"SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}", "CRITICAL"),
    "Twilio Account SID":   (r"AC[a-z0-9]{32}", "HIGH"),
    "Twilio Auth Token":    (r"(?i)twilio.{0,20}['\"][a-z0-9]{32}['\"]", "HIGH"),
    "Mailgun API Key":      (r"key-[0-9a-zA-Z]{32}", "HIGH"),
    "Mailchimp API Key":    (r"[0-9a-f]{32}-us[0-9]{1,2}", "HIGH"),
    "Slack Webhook":        (r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+", "HIGH"),
    "Slack Token":          (r"xox[baprs]\-[0-9A-Za-z\-]{10,}", "HIGH"),
    # Analytics / Monitoring
    "Sentry DSN":           (r"https://[a-f0-9]{32}@[a-z0-9.]+\.sentry\.io/\d+", "MEDIUM"),
    "Mixpanel Token":       (r"(?i)mixpanel.{0,20}['\"][a-f0-9]{32}['\"]", "MEDIUM"),
    "Segment Write Key":    (r"(?i)segment.{0,20}['\"][A-Za-z0-9]{20,}['\"]", "MEDIUM"),
    "Amplitude Key":        (r"(?i)amplitude.{0,20}apiKey.{0,20}['\"][a-f0-9]{32}['\"]", "MEDIUM"),
    "Hotjar Site ID":       (r"(?i)hotjar.{0,20}['\"][0-9]{5,}['\"]", "LOW"),
    # Maps / Location
    "Google Maps Key":      (r"AIza[0-9A-Za-z\-_]{35}", "HIGH"),
    "Mapbox Token":         (r"pk\.eyJ1[a-zA-Z0-9_.]{40,}", "HIGH"),
    "Mapbox Secret":        (r"sk\.eyJ1[a-zA-Z0-9_.]{40,}", "CRITICAL"),
    # Search
    "Algolia App ID":       (r"(?i)algolia.{0,20}appId.{0,20}['\"][A-Z0-9]{10}['\"]", "MEDIUM"),
    "Algolia API Key":      (r"(?i)algolia.{0,20}apiKey.{0,20}['\"][a-z0-9]{32}['\"]", "MEDIUM"),
    # Dev / SCM
    "GitHub Token":         (r"ghp_[a-zA-Z0-9]{36}", "CRITICAL"),
    "GitHub Actions":       (r"ghs_[a-zA-Z0-9]{36}", "CRITICAL"),
    "NPM Token":            (r"npm_[A-Za-z0-9]{36}", "CRITICAL"),
    # Infra / DB
    "MongoDB URI":          (r"mongodb(\+srv)?://[^\"'\s]{10,}", "CRITICAL"),
    "PostgreSQL URI":       (r"postgres(ql)?://[^\"'\s]{10,}", "CRITICAL"),
    "MySQL URI":            (r"mysql://[^\"'\s]{10,}", "CRITICAL"),
    "Redis URI":            (r"redis://[^\"'\s]{10,}", "HIGH"),
    "S3 Bucket":            (r"s3://[a-z0-9\-\.]{3,63}", "MEDIUM"),
    "S3 URL":               (r"https://[a-z0-9\-\.]+\.s3\.amazonaws\.com", "LOW"),
    # Chat / Support
    "Intercom App ID":      (r"(?i)intercom.{0,20}['\"][a-z0-9]{8}['\"]", "MEDIUM"),
    "Zendesk Key":          (r"(?i)zendesk.{0,20}['\"][a-zA-Z0-9]{20,}['\"]", "MEDIUM"),
    "Freshdesk Key":        (r"(?i)freshdesk.{0,20}['\"][a-zA-Z0-9]{20,}['\"]", "MEDIUM"),
    # Crypto / Web3
    "Private Key (ETH)":    (r"(?i)(private.?key|mnemonic).{0,20}['\"][0-9a-fA-F]{64}['\"]", "CRITICAL"),
    "Infura Project ID":    (r"(?i)infura.{0,20}['\"][a-f0-9]{32}['\"]", "HIGH"),
    "Alchemy API Key":      (r"(?i)alchemy.{0,20}['\"][a-zA-Z0-9\-_]{32,}['\"]", "HIGH"),
    # Generic
    "Generic Secret":       (r"(?i)(secret|password|passwd|api.?key|api.?secret|access.?token)\s*[:=]\s*['\"][A-Za-z0-9+/\-_]{16,}['\"]", "MEDIUM"),
    "Bearer Token":         (r"[Bb]earer\s+[A-Za-z0-9\-_]{20,}", "MEDIUM"),
    "Basic Auth":           (r"[Bb]asic\s+[A-Za-z0-9+/=]{20,}", "MEDIUM"),
    "Private IP":           (r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b", "LOW"),
}

# ── Env Var Patterns ─────────────────────────────────────────────────────────

ENV_PATTERNS = [
    r'NEXT_PUBLIC_[A-Z0-9_]+\s*(?::|=)\s*["\']([^"\'\\]{1,200})["\']',
    r'"(NEXT_PUBLIC_[A-Z0-9_]+)"\s*:\s*"([^"\\]{1,200})"',
    r'REACT_APP_[A-Z0-9_]+\s*(?::|=)\s*["\']([^"\'\\]{1,200})["\']',
    r'"(REACT_APP_[A-Z0-9_]+)"\s*:\s*"([^"\\]{1,200})"',
    r'process\.env\.(NEXT_PUBLIC_[A-Z0-9_]+)',
    r'process\.env\.(REACT_APP_[A-Z0-9_]+)',
    r'process\.env\.([A-Z][A-Z0-9_]{3,})',
]

# ── Endpoint Patterns ─────────────────────────────────────────────────────────

ENDPOINT_PATTERNS = [
    r'["\'](\/(api|graphql|v\d|internal|admin|auth|oauth|webhook)[\/\w\-\.\{\}:?=&%]{2,100})["\']',
    r'["\']https?:\/\/[a-zA-Z0-9\-\.]+(?:\/[\w\-\.\/\{\}:?=&%]{2,100})["\']',
    r'fetch\s*\(["\']([^"\']+)["\']',
    r'axios\.[a-z]+\s*\(["\']([^"\']+)["\']',
    r'\.get\s*\(["\']([\/\w\-\.]{3,100})["\']',
    r'\.post\s*\(["\']([\/\w\-\.]{3,100})["\']',
    r'baseURL\s*[:=]\s*["\']([^"\']+)["\']',
    r'baseUrl\s*[:=]\s*["\']([^"\']+)["\']',
    r'API_URL\s*[:=]\s*["\']([^"\']+)["\']',
    r'GRAPHQL_URL\s*[:=]\s*["\']([^"\']+)["\']',
    r'WS_URL\s*[:=]\s*["\']([^"\']+)["\']',
    r'wss?:\/\/[a-zA-Z0-9\-\.\/\{\}:?=&%]{5,100}',
]

# ── Severity Colours ─────────────────────────────────────────────────────────

SEVERITY_STYLE = {
    "CRITICAL": "bold red",
    "HIGH":     "bold yellow",
    "MEDIUM":   "yellow",
    "LOW":      "dim cyan",
    "INFO":     "dim white",
}


# ── HTTP Helpers ──────────────────────────────────────────────────────────────

def get(url: str, session: requests.Session, timeout: int = TIMEOUT) -> requests.Response | None:
    try:
        r = session.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        return r
    except Exception:
        return None


# ── Extraction Functions ──────────────────────────────────────────────────────

def extract_next_data(html: str) -> dict | None:
    match = re.search(r'<script id="__NEXT_DATA__" type="application/json">(.*?)</script>', html, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            return None
    return None


def extract_build_id(html: str, next_data: dict | None) -> str | None:
    if next_data:
        return next_data.get("buildId")
    match = re.search(r'/_next/static/([a-zA-Z0-9_\-]{8,})/[_a-z]', html)
    return match.group(1) if match else None


def extract_next_version(html: str) -> str | None:
    match = re.search(r'"nextExport"\s*:\s*true.*?"version"\s*:\s*"([^"]+)"', html, re.DOTALL)
    if match:
        return match.group(1)
    match = re.search(r'next/dist/[^"]+?(\d+\.\d+\.\d+)', html)
    return match.group(1) if match else None


def get_chunk_urls(html: str, base_url: str, build_id: str | None) -> list[str]:
    """Extract all _next/static JS chunk URLs from page HTML."""
    chunks = set()
    # From script tags
    for src in re.findall(r'<script[^>]+src=["\']([^"\']+)["\']', html):
        if "_next/static" in src or src.endswith(".js"):
            chunks.add(urljoin(base_url, src))
    # From __NEXT_F / chunk manifest patterns
    for path in re.findall(r'["\'](\/_next\/static\/[^"\']+\.js)["\']', html):
        chunks.add(urljoin(base_url, path))
    return list(chunks)


def get_build_manifest(session: requests.Session, base_url: str, build_id: str) -> dict | None:
    """Fetch _buildManifest.js to get all page routes."""
    url = f"{base_url.rstrip('/')}/_next/static/{build_id}/_buildManifest.js"
    r = get(url, session)
    if not r or r.status_code != 200:
        return None
    # Parse the self.__BUILD_MANIFEST={...} object
    match = re.search(r'self\.__BUILD_MANIFEST\s*=\s*(\{.*?\});', r.text, re.DOTALL)
    if match:
        try:
            # Clean up for JSON parsing
            raw = match.group(1)
            raw = re.sub(r',\s*}', '}', raw)
            raw = re.sub(r',\s*]', ']', raw)
            return json.loads(raw)
        except Exception:
            return {"raw": r.text[:2000]}
    return None


def get_middleware_manifest(session: requests.Session, base_url: str, build_id: str) -> dict | None:
    url = f"{base_url.rstrip('/')}/_next/static/{build_id}/_middlewareManifest.js"
    r = get(url, session)
    if r and r.status_code == 200:
        return {"raw": r.text[:3000]}
    return None


def check_next_data_endpoints(session: requests.Session, base_url: str, build_id: str, routes: list[str]) -> list[str]:
    """Check /_next/data/{buildId}/route.json endpoints."""
    found = []
    for route in routes[:20]:  # cap at 20 to avoid hammering
        if route in ("/", "/_app", "/_error", "/_document"):
            continue
        url = f"{base_url.rstrip('/')}/_next/data/{build_id}{route}.json"
        r = get(url, session)
        if r and r.status_code == 200:
            found.append(url)
    return found


def check_source_maps(session: requests.Session, chunk_urls: list[str]) -> list[str]:
    """Check if .map files exist for JS chunks."""
    found = []
    def check(url):
        map_url = url + ".map"
        r = get(map_url, session)
        if r and r.status_code == 200 and "sources" in r.text[:200]:
            return map_url
        return None

    with ThreadPoolExecutor(max_workers=10) as ex:
        futures = {ex.submit(check, u): u for u in chunk_urls[:30]}
        for f in as_completed(futures):
            result = f.result()
            if result:
                found.append(result)
    return found


def check_exposed_files(session: requests.Session, base_url: str) -> list[tuple[str, str]]:
    """Check for commonly exposed sensitive files."""
    checks = [
        ("/.env", "Environment file"),
        ("/.env.local", "Environment file (local)"),
        ("/.env.production", "Environment file (production)"),
        ("/.env.development", "Environment file (development)"),
        ("/next.config.js", "Next.js config"),
        ("/next.config.ts", "Next.js config (TS)"),
        ("/.git/config", "Git config"),
        ("/.git/HEAD", "Git HEAD"),
        ("/package.json", "Package.json"),
        ("/yarn.lock", "Yarn lockfile"),
        ("/package-lock.json", "NPM lockfile"),
        ("/graphql", "GraphQL endpoint"),
        ("/api/graphql", "GraphQL API"),
        ("/graphiql", "GraphiQL IDE"),
        ("/swagger.json", "Swagger/OpenAPI spec"),
        ("/openapi.json", "OpenAPI spec"),
        ("/api-docs", "API docs"),
        ("/api/__health", "Health check"),
        ("/api/health", "Health check"),
        ("/api/debug", "Debug endpoint"),
        ("/api/admin", "Admin API"),
        ("/api/internal", "Internal API"),
        ("/_next/static/development/_devPagesManifest.json", "Dev pages manifest"),
        ("/_next/static/development/_buildManifest.js", "Dev build manifest"),
    ]

    found = []
    def check(path, label):
        url = urljoin(base_url, path)
        r = get(url, session)
        if r and r.status_code in (200, 301, 302, 403):
            return (url, label, r.status_code)
        return None

    with ThreadPoolExecutor(max_workers=15) as ex:
        futures = {ex.submit(check, p, l): (p, l) for p, l in checks}
        for f in as_completed(futures):
            result = f.result()
            if result:
                found.append(result)
    return sorted(found, key=lambda x: x[2])


def download_chunks(session: requests.Session, urls: list[str]) -> dict[str, str]:
    """Download JS chunks concurrently."""
    contents = {}
    def fetch(url):
        r = get(url, session)
        if r and r.status_code == 200 and r.text:
            return url, r.text
        return url, None

    with ThreadPoolExecutor(max_workers=15) as ex:
        futures = {ex.submit(fetch, u): u for u in urls[:MAX_CHUNKS]}
        for f in as_completed(futures):
            url, content = f.result()
            if content:
                contents[url] = content
    return contents


def scan_for_secrets(text: str, source: str = "") -> list[dict]:
    """Run all secret patterns against text."""
    findings = []
    seen = set()
    for name, (pattern, severity) in SECRETS.items():
        for match in re.finditer(pattern, text):
            val = match.group(0)[:200]
            key = f"{name}:{val}"
            if key not in seen:
                seen.add(key)
                # Get context (line)
                start = max(0, match.start() - 50)
                end = min(len(text), match.end() + 50)
                context = text[start:end].replace("\n", " ").strip()
                findings.append({
                    "type": name,
                    "severity": severity,
                    "value": val,
                    "context": context,
                    "source": source,
                })
    return findings


def scan_for_env_vars(text: str) -> list[tuple[str, str]]:
    """Extract environment variable names and values."""
    found = {}
    for pattern in ENV_PATTERNS:
        for match in re.finditer(pattern, text):
            groups = match.groups()
            if len(groups) == 2:
                name, val = groups[0], groups[1]
                found[name] = val[:200]
            elif len(groups) == 1:
                found[groups[0]] = "[referenced — value not inline]"
    return list(found.items())


def scan_for_endpoints(text: str) -> list[str]:
    """Extract API endpoints and URLs."""
    found = set()
    for pattern in ENDPOINT_PATTERNS:
        for match in re.finditer(pattern, text):
            val = match.group(1) if match.lastindex else match.group(0)
            val = val.strip().rstrip('",;')
            if len(val) > 3 and not val.endswith((".js", ".css", ".png", ".svg", ".woff")):
                found.add(val)
    return sorted(found)


def crawl_links(session: requests.Session, base_url: str, html: str) -> list[str]:
    """Find internal links to crawl for more JS chunks."""
    base = urlparse(base_url)
    links = set()
    for href in re.findall(r'href=["\']([^"\'#?]+)["\']', html):
        parsed = urlparse(href)
        if not parsed.scheme:
            href = urljoin(base_url, href)
            parsed = urlparse(href)
        if parsed.netloc == base.netloc and not href.endswith((".js", ".css", ".png", ".jpg", ".svg")):
            links.add(href)
    return list(links)[:20]  # cap crawl


# ── Output Helpers ────────────────────────────────────────────────────────────

def sev_badge(sev: str) -> str:
    colours = {
        "CRITICAL": "[bold white on red] CRITICAL [/bold white on red]",
        "HIGH":     "[bold black on yellow] HIGH     [/bold black on yellow]",
        "MEDIUM":   "[yellow] MEDIUM  [/yellow]",
        "LOW":      "[dim cyan] LOW     [/dim cyan]",
        "INFO":     "[dim white] INFO    [/dim white]",
    }
    return colours.get(sev, sev)


def print_section(title: str):
    console.print()
    console.print(Rule(f"[bold red]{title}[/bold red]", style="dim red"))


def print_finding(f: dict):
    badge = sev_badge(f["severity"])
    console.print(f"  {badge} [bold white]{f['type']}[/bold white]")
    console.print(f"  [dim white]Value:[/dim white] [yellow]{f['value'][:120]}[/yellow]")
    if f.get("source"):
        console.print(f"  [dim white]Source:[/dim white] [dim]{f['source'].split('/')[-1]}[/dim]")
    console.print()


# ── Report Writer ─────────────────────────────────────────────────────────────

def save_report(target: str, results: dict, output_dir: str | None = None):
    domain = urlparse(target).netloc.replace(":", "_")
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"nextrecon_{domain}_{ts}.md"

    if output_dir:
        path = Path(output_dir).expanduser().resolve() / filename
    else:
        path = Path.home() / "bughunt" / "nextrecon" / filename

    path.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        f"# NextRecon Report — {target}",
        f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"**Build ID:** {results.get('build_id', 'unknown')}",
        f"**Next.js Version:** {results.get('version', 'unknown')}",
        "",
    ]

    if results.get("next_data"):
        lines += ["## __NEXT_DATA__", "```json", json.dumps(results["next_data"], indent=2)[:5000], "```", ""]

    if results.get("secrets"):
        lines += ["## Secrets / Credentials", ""]
        for f in results["secrets"]:
            lines += [f"### {sev_badge(f['severity']).replace('[','').split(']')[0]} — {f['type']}", f"- **Value:** `{f['value'][:100]}`", f"- **Source:** {f.get('source', '')}", ""]

    if results.get("env_vars"):
        lines += ["## Environment Variables", ""]
        for name, val in results["env_vars"]:
            lines += [f"- `{name}` = `{val[:100]}`"]
        lines.append("")

    if results.get("endpoints"):
        lines += ["## API Endpoints", ""]
        for ep in results["endpoints"]:
            lines += [f"- `{ep}`"]
        lines.append("")

    if results.get("routes"):
        lines += ["## Page Routes", ""]
        for r in results["routes"]:
            lines += [f"- `{r}`"]
        lines.append("")

    if results.get("exposed_files"):
        lines += ["## Exposed Files", ""]
        for url, label, code in results["exposed_files"]:
            lines += [f"- [{code}] `{url}` — {label}"]
        lines.append("")

    if results.get("source_maps"):
        lines += ["## Source Maps Found", ""]
        for url in results["source_maps"]:
            lines += [f"- `{url}`"]
        lines.append("")

    if results.get("next_data_endpoints"):
        lines += ["## /_next/data/ Endpoints", ""]
        for url in results["next_data_endpoints"]:
            lines += [f"- `{url}`"]
        lines.append("")

    path.write_text("\n".join(lines))
    return str(path)


# ── Main Engine ───────────────────────────────────────────────────────────────

def run(target: str, crawl: bool = True, output_dir: str | None = None, no_banner: bool = False):
    if not no_banner:
        console.print(BANNER)

    if not target.startswith("http"):
        target = "https://" + target

    base_url = "/".join(target.split("/")[:3])
    results = {"target": target, "secrets": [], "env_vars": [], "endpoints": set(), "routes": []}

    session = requests.Session()
    session.headers.update(HEADERS)

    console.print(Panel(
        f"[dim white]Target:[/dim white] [bold red]{target}[/bold red]",
        border_style="red", expand=False, title="[bold red][ TARGET ][/bold red]"
    ))
    console.print()

    # ── Fetch main page ───────────────────────────────────────────────────────
    console.print("[dim red]  [*] Fetching target...[/dim red]")
    r = get(target, session)
    if not r:
        console.print("[bold red][!] Failed to reach target.[/bold red]")
        return

    html = r.text
    all_js_text = html

    # ── Detect Next.js ────────────────────────────────────────────────────────
    is_next = "__NEXT_DATA__" in html or "_next/static" in html or "/_next/" in html
    next_data = extract_next_data(html)
    build_id = extract_build_id(html, next_data)
    version = extract_next_version(html)

    info_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    info_table.add_column(style="dim white")
    info_table.add_column(style="bold white")
    info_table.add_row("Next.js Detected", "[bold green]YES[/bold green]" if is_next else "[dim red]NO[/dim red]")
    info_table.add_row("Build ID", build_id or "[dim]unknown[/dim]")
    info_table.add_row("Version", version or "[dim]unknown[/dim]")
    info_table.add_row("Status", str(r.status_code))
    info_table.add_row("Server", r.headers.get("Server", "[dim]hidden[/dim]"))
    info_table.add_row("X-Powered-By", r.headers.get("X-Powered-By", "[dim]hidden[/dim]"))
    info_table.add_row("WAF / CDN", _detect_waf(r))
    console.print(info_table)

    results["build_id"] = build_id
    results["version"] = version

    # ── __NEXT_DATA__ ─────────────────────────────────────────────────────────
    if next_data:
        print_section("__NEXT_DATA__")
        console.print(f"  [dim green]Found! Keys: {', '.join(next_data.keys())}[/dim green]")
        results["next_data"] = next_data

        # Look for secrets inline in __NEXT_DATA__
        nd_str = json.dumps(next_data)
        secrets_in_nd = scan_for_secrets(nd_str, "__NEXT_DATA__")
        if secrets_in_nd:
            console.print(f"  [bold red][!] {len(secrets_in_nd)} potential secret(s) in __NEXT_DATA__:[/bold red]")
            for f in secrets_in_nd:
                print_finding(f)
            results["secrets"].extend(secrets_in_nd)

        # Show pageProps keys
        pp = next_data.get("props", {}).get("pageProps", {})
        if pp:
            console.print(f"  [dim white]pageProps keys:[/dim white] {', '.join(str(k) for k in list(pp.keys())[:20])}")

        # Show env/config keys often embedded
        for key in ["env", "config", "publicRuntimeConfig", "serverRuntimeConfig"]:
            val = next_data.get(key) or next_data.get("props", {}).get(key)
            if val:
                console.print(f"  [yellow][!] Found '{key}' in __NEXT_DATA__:[/yellow]")
                console.print(f"  [dim]{json.dumps(val, indent=2)[:500]}[/dim]")

    # ── Collect JS chunks ─────────────────────────────────────────────────────
    print_section("JS CHUNK COLLECTION")
    chunk_urls = get_chunk_urls(html, base_url, build_id)

    # Add known chunk paths if build_id is known
    if build_id:
        for extra in [
            f"/_next/static/{build_id}/_buildManifest.js",
            f"/_next/static/{build_id}/_ssgManifest.js",
            f"/_next/static/chunks/main.js",
            f"/_next/static/chunks/webpack.js",
            f"/_next/static/chunks/framework.js",
            f"/_next/static/chunks/pages/_app.js",
            f"/_next/static/chunks/pages/index.js",
            f"/_next/static/chunks/pages/_error.js",
        ]:
            chunk_urls.append(urljoin(base_url, extra))

    # Crawl additional pages for more chunks
    if crawl:
        console.print(f"  [dim green]  [*] Crawling linked pages for more chunks...[/dim green]")
        internal_links = crawl_links(session, target, html)
        for link in internal_links[:10]:
            pr = get(link, session)
            if pr and pr.status_code == 200:
                extra_chunks = get_chunk_urls(pr.text, base_url, build_id)
                chunk_urls.extend(extra_chunks)

    chunk_urls = list(set(chunk_urls))
    console.print(f"  [dim white]Chunks to download:[/dim white] [bold white]{len(chunk_urls)}[/bold white]")

    # ── Download chunks ───────────────────────────────────────────────────────
    console.print(f"  [dim green]  [*] Downloading chunks (max {MAX_CHUNKS})...[/dim green]")
    chunks = download_chunks(session, chunk_urls)
    console.print(f"  [dim white]Downloaded:[/dim white] [bold white]{len(chunks)}[/bold white]")

    for content in chunks.values():
        all_js_text += content

    # ── Build manifest / routes ───────────────────────────────────────────────
    print_section("ROUTES")
    page_routes = []
    if build_id:
        manifest = get_build_manifest(session, base_url, build_id)
        if manifest:
            for key, val in manifest.items():
                if key not in ("__rewrites", "sortedPages") and isinstance(val, list):
                    pass
            # sortedPages has all routes
            page_routes = manifest.get("sortedPages", [])
            if not page_routes and "raw" in manifest:
                page_routes = re.findall(r'"(/[^"]*)"', manifest["raw"])

    # Also extract routes from bundle text
    bundle_routes = re.findall(r'"(/(?:api|dashboard|admin|user|account|profile|settings|auth)[^"]{0,100})"', all_js_text)
    page_routes = list(set(page_routes + bundle_routes))

    if page_routes:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        table.add_column(style="dim white", no_wrap=True)
        for route in sorted(page_routes)[:50]:
            style = "bold red" if any(x in route for x in ["admin", "internal", "debug", "secret"]) else "white"
            table.add_row(f"[{style}]{route}[/{style}]")
        console.print(table)
        results["routes"] = page_routes
    else:
        console.print("  [dim]No routes found[/dim]")

    # ── /_next/data/ endpoint probing ─────────────────────────────────────────
    if build_id and page_routes:
        print_section("/_next/data/ ENDPOINTS")
        console.print("  [dim green]  [*] Probing data endpoints...[/dim green]")
        data_eps = check_next_data_endpoints(session, base_url, build_id, page_routes)
        if data_eps:
            for ep in data_eps:
                console.print(f"  [bold green][+][/bold green] [white]{ep}[/white]")
        else:
            console.print("  [dim]None accessible[/dim]")
        results["next_data_endpoints"] = data_eps

    # ── Environment Variables ─────────────────────────────────────────────────
    print_section("ENVIRONMENT VARIABLES")
    env_vars = scan_for_env_vars(all_js_text)
    if env_vars:
        table = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
        table.add_column("Variable", style="bold yellow")
        table.add_column("Value", style="white")
        for name, val in sorted(set(env_vars)):
            table.add_row(name, val[:80])
        console.print(table)
        results["env_vars"] = env_vars
    else:
        console.print("  [dim]None found[/dim]")

    # ── Secrets ───────────────────────────────────────────────────────────────
    print_section("SECRETS / CREDENTIALS")
    all_secrets = scan_for_secrets(all_js_text, "js_bundles")
    if all_secrets:
        for f in sorted(all_secrets, key=lambda x: ["CRITICAL","HIGH","MEDIUM","LOW","INFO"].index(x["severity"])):
            print_finding(f)
        results["secrets"].extend(all_secrets)
    else:
        console.print("  [dim green]  [+] No secrets found in JS bundles[/dim green]")

    # ── API Endpoints ─────────────────────────────────────────────────────────
    print_section("API ENDPOINTS & URLS")
    endpoints = scan_for_endpoints(all_js_text)
    interesting = [e for e in endpoints if any(x in e.lower() for x in [
        "api", "graphql", "auth", "oauth", "token", "admin", "internal",
        "webhook", "ws://", "wss://", "upload", "export", "import"
    ])]
    if interesting:
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        table.add_column(style="cyan")
        for ep in interesting[:100]:
            table.add_row(ep)
        console.print(table)
    elif endpoints:
        for ep in endpoints[:30]:
            console.print(f"  [dim cyan]{ep}[/dim cyan]")
    else:
        console.print("  [dim]None found[/dim]")
    results["endpoints"] = list(endpoints)

    # ── Exposed Files ─────────────────────────────────────────────────────────
    print_section("EXPOSED FILES & ENDPOINTS")
    console.print("  [dim green]  [*] Probing for exposed files...[/dim green]")
    exposed = check_exposed_files(session, base_url)
    if exposed:
        table = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
        table.add_column("Status", style="bold", width=8)
        table.add_column("URL", style="white")
        table.add_column("Type", style="dim white")
        for url, label, code in sorted(exposed, key=lambda x: x[2]):
            style = "bold green" if code == 200 else "yellow" if code in (301, 302) else "dim red"
            table.add_row(f"[{style}]{code}[/{style}]", url, label)
        console.print(table)
    else:
        console.print("  [dim]Nothing exposed[/dim]")
    results["exposed_files"] = exposed

    # ── Source Maps ───────────────────────────────────────────────────────────
    print_section("SOURCE MAPS")
    console.print("  [dim green]  [*] Checking for source maps...[/dim green]")
    source_maps = check_source_maps(session, list(chunks.keys()))
    if source_maps:
        for sm in source_maps:
            console.print(f"  [bold red][!] SOURCE MAP EXPOSED:[/bold red] [white]{sm}[/white]")
    else:
        console.print("  [dim]No source maps found[/dim]")
    results["source_maps"] = source_maps

    # ── Summary ───────────────────────────────────────────────────────────────
    print_section("SUMMARY")
    total_secrets = len(results["secrets"])
    critical = sum(1 for s in results["secrets"] if s["severity"] == "CRITICAL")
    high = sum(1 for s in results["secrets"] if s["severity"] == "HIGH")

    summary = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    summary.add_column(style="dim white")
    summary.add_column(style="bold white")
    summary.add_row("Secrets Found", f"[bold red]{total_secrets}[/bold red] ({critical} CRITICAL, {high} HIGH)")
    summary.add_row("Env Vars", str(len(results["env_vars"])))
    summary.add_row("API Endpoints", str(len(results["endpoints"])))
    summary.add_row("Page Routes", str(len(results["routes"])))
    summary.add_row("Exposed Files", str(len(results["exposed_files"])))
    summary.add_row("Source Maps", str(len(results["source_maps"])))
    summary.add_row("JS Chunks Analysed", str(len(chunks)))
    console.print(summary)

    # ── Save report ───────────────────────────────────────────────────────────
    report_path = save_report(target, results, output_dir)
    console.print()
    console.print(Panel(
        f"[dim white]Report saved to:[/dim white] [bold green]{report_path}[/bold green]",
        border_style="green", expand=False
    ))


def _detect_waf(r: requests.Response) -> str:
    headers = {k.lower(): v.lower() for k, v in r.headers.items()}
    server = headers.get("server", "")
    via = headers.get("via", "")
    cf = headers.get("cf-ray", "")
    xcdn = headers.get("x-cdn", "")
    if cf or "cloudflare" in server:
        return "[dim yellow]Cloudflare[/dim yellow]"
    if "akamai" in via or "akamai" in server:
        return "[dim yellow]Akamai[/dim yellow]"
    if "fastly" in via or "fastly" in server:
        return "[dim yellow]Fastly[/dim yellow]"
    if "awselb" in server or "aws" in via:
        return "[dim yellow]AWS[/dim yellow]"
    if "imperva" in server or "incapsula" in server:
        return "[dim yellow]Imperva[/dim yellow]"
    if "sucuri" in server:
        return "[dim yellow]Sucuri[/dim yellow]"
    return "[dim]unknown[/dim]"


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="nextrecon — Next.js & JS Bundle Recon Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  nextrecon https://target.com
  nextrecon https://target.com -o ~/bughunt/target/
  nextrecon https://target.com --no-crawl
  nextrecon -l targets.txt -o ~/bughunt/results/
        """
    )
    parser.add_argument("target", nargs="?", help="Target URL")
    parser.add_argument("-l", "--list", metavar="FILE", help="File with list of targets (one per line)")
    parser.add_argument("-o", "--output", metavar="DIR", help="Output directory for reports")
    parser.add_argument("--no-crawl", action="store_true", help="Disable page crawling (faster)")
    parser.add_argument("--no-banner", action="store_true", help="Suppress banner")
    args = parser.parse_args()

    if not args.target and not args.list:
        parser.print_help()
        sys.exit(1)

    targets = []
    if args.list:
        targets = [l.strip() for l in open(args.list) if l.strip()]
    elif args.target:
        targets = [args.target]

    for i, t in enumerate(targets):
        if i > 0:
            console.print("\n" + "═" * 80 + "\n")
        run(t, crawl=not args.no_crawl, output_dir=args.output, no_banner=(args.no_banner or i > 0))


if __name__ == "__main__":
    main()
