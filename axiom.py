#!/usr/bin/env python3
"""
axiom — Context-Aware Reconnaissance & Attack-Surface Discovery Engine.

Four parallel pipelines:
  1. The Archivist     — JS bundle parsing, route extraction, source-map analysis
  2. The Skeleton Key  — Tech-stack-adaptive recursive directory brute-force
  3. The Leak Detector — Regex-based secret scanning on discovered text assets
  4. The Pathfinder    — Soft-404 clustering via structural-similarity filtering

Usage:
    axiom https://target.com --scope "*.target.com" [--depth 3] [--concurrency 30]
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urljoin, urlparse
from typing import Optional

import httpx
from bs4 import BeautifulSoup

# ── Colour helpers ──────────────────────────────────────────────────────────
C = {
    "G": "\033[92m",  # green  (200)
    "B": "\033[94m",  # blue   (redirect)
    "R": "\033[91m",  # red    (error)
    "Y": "\033[93m",  # yellow (backups/secrets)
    "W": "\033[0m",   # reset
}
_STATUS_COL = {2: C["G"], 3: C["B"], 4: C["R"], 5: C["R"]}


def _colour(status: int) -> str:
    return _STATUS_COL.get(status // 100, C["W"])


# ── Data types ──────────────────────────────────────────────────────────────

@dataclass
class Finding:
    url: str
    status: int
    content_type: str
    found_in: str       # "wordlist" | "js_bundle" | "recursive"
    secrets: list[str] = field(default_factory=list)
    body_hash: str = ""   # structural hash for soft-404 clustering

    def to_jsonl(self) -> str:
        return json.dumps({
            "url": self.url,
            "status": self.status,
            "content_type": self.content_type,
            "found_in": self.found_in,
            "secrets": self.secrets,
        })


@dataclass
class Fingerprint:
    stack: str              # PHP | Node/React | .NET | Java | Unknown
    server: str = ""
    cookies: list[str] = field(default_factory=list)
    powered_by: str = ""
    evidence: list[str] = field(default_factory=list)


# ── Wordlist loader ─────────────────────────────────────────────────────────

def _load_wordlist(name: str) -> list[str]:
    """Load a wordlist file, stripping comments and blank lines."""
    base = Path(__file__).resolve().parent / "wordlists"
    path = base / name
    if not path.exists():
        return []
    entries: list[str] = []
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(line.lstrip("/"))  # store without leading slash
    return entries


def _safe_text(resp) -> str:
    """Read response body safely, falling back to replacement characters on decode errors."""
    try:
        return resp.text
    except UnicodeDecodeError:
        return resp.content.decode("utf-8", errors="replace")


# File-like extensions — paths ending with these are files, not directories
_FILE_EXT_RE = re.compile(r"\.(env|php|phtml|asp|aspx|ashx|js|json|xml|bak|old|map|html?|css|png|jpg|gif|svg|ico|txt|yml|yaml|toml|ini|cfg|conf|log|zip|tar|gz|sql|db)$", re.IGNORECASE)


# ── 1. FINGERPRINT ──────────────────────────────────────────────────────────

async def fingerprint(client: httpx.AsyncClient, base_url: str) -> Fingerprint:
    """Send a single GET to `/` and classify the tech stack."""
    fp = Fingerprint(stack="Unknown")
    try:
        resp = await client.get(base_url, follow_redirects=True)
    except httpx.RequestError:
        return fp

    # Headers
    server = resp.headers.get("Server", "")
    fp.server = server
    powered = resp.headers.get("X-Powered-By", "")
    fp.powered_by = powered

    # Cookies — join all Set-Cookie headers (servers may send multiple)
    set_cookies = resp.headers.get("Set-Cookie", "")
    # httpx stores multi-value headers as comma-joined; also try get_list
    try:
        all_cookies = resp.headers.get_list("Set-Cookie")
        set_cookies = "; ".join(all_cookies)
    except Exception:
        pass  # fall back to the .get() value
    fp.cookies = [c.strip() for c in set_cookies.split(";")]
    # Also track the raw cookie string for classification
    cookie_str = set_cookies

    # Body for content-based clues
    body = _safe_text(resp)[:8192]

    # Classification rules — strongest signal first
    score: dict[str, int] = defaultdict(int)

    # PHP signals
    if "PHPSESSID" in cookie_str:
        score["PHP"] += 3
    if ".php" in body or "wp-content" in body or "wp-admin" in body:
        score["PHP"] += 3
    if "X-Powered-By: PHP" in powered or "PHP" in powered:
        score["PHP"] += 2
    if "laravel" in body.lower() or "symfony" in body.lower():
        score["PHP"] += 2

    # .NET signals
    if "ASP.NET_SessionId" in cookie_str or "ASP.NET" in cookie_str:
        score[".NET"] += 3
    if ".aspx" in body or ".ashx" in body or ".axd" in body:
        score[".NET"] += 3
    if "ASP.NET" in powered or "ASP.NET" in server:
        score[".NET"] += 2
    if "X-AspNet-Version" in resp.headers:
        score[".NET"] += 2

    # Java signals
    if "JSESSIONID" in cookie_str:
        score["Java"] += 3
    if "Servlet" in powered or "JSP" in powered:
        score["Java"] += 2
    if ".jsp" in body or ".do" in body:
        score["Java"] += 2
    if "Apache-Coyote" in server or "JBoss" in server or "Tomcat" in server:
        score["Java"] += 2

    # Node/React signals — weakest, but still useful
    if "_next/static" in body or "__NEXT_DATA__" in body or "chunk-" in body:
        score["Node/React"] += 3
    if "react" in body.lower() and ("bundle.js" in body or "/static/js/" in body):
        score["Node/React"] += 2
    if "node" in powered.lower():
        score["Node/React"] += 2
    if "express" in powered.lower():
        score["Node/React"] += 2

    # Decide
    if score:
        fp.stack = max(score, key=lambda k: score[k])  # type: ignore[arg-type]
        fp.evidence = [f"{k}:{v}" for k, v in sorted(score.items(), key=lambda x: -x[1])]

    print(f"  {C['B']}[*]{C['W']} Fingerprint → {C['Y']}{fp.stack}{C['W']} (evidence: {', '.join(fp.evidence) or 'none'})")
    return fp


# ── 2. THE ARCHIVIST (JS parsing) ───────────────────────────────────────────

# Simple regex-based route extraction from JS — AST walking via esprima is
# ideal, but a well-tuned regex covers 90% of real-world bundles without
# the heavy Node dependency.
# Targeted: known API/route prefixes (high signal)
_ROUTE_RE = re.compile(
    r"""["'`](/?(?:api|v\d|graphql|webhook|rest|auth|oauth|callback|login|logout|register|user|admin|dashboard)[^"'`\s]*)["'`]""",
    re.IGNORECASE,
)

# Broad: any path-like string inside JS string literals (catches framework routes, SPA paths, etc.)
_GENERIC_PATH_RE = re.compile(
    r"""["'`](/[a-zA-Z][a-zA-Z0-9_\-.~:/?#\[\]@!$&'()*+,;=%]{2,})["'`]""",
)

# False-positive patterns to exclude from generic path extraction
_PATH_BLACKLIST = re.compile(
    r"/(?:https?:/|ftp:/|data:|blob:|//|\.\./|node_modules|vendor|\.min\.|\.map[^.]|\.json[^.]|dist/|build/|\*|\.(?:png|jpg|gif|svg|ico|woff2?|ttf|eot|css|scss|less)$)",
    re.IGNORECASE,
)


def _extract_routes(text: str, routes: list[str]) -> None:
    """Extract route-like paths from JS text using targeted + generic patterns."""
    # High-signal: targeted API/route prefixes
    for m in _ROUTE_RE.finditer(text):
        routes.append(m.group(1))
    # Broad sweep: any path-like string, with blacklist filter
    for m in _GENERIC_PATH_RE.finditer(text):
        path = m.group(1)
        if not _PATH_BLACKLIST.search(path):
            routes.append(path)


async def archivist(
    client: httpx.AsyncClient,
    base_url: str,
    html: str,
    findings: list[Finding],
    leak_detector_fn,
    scope_pattern: Optional[re.Pattern] = None,
) -> list[str]:
    """Parse HTML for <script>/<link> tags, download JS bundles, extract routes.
    Also runs leak-detection on every downloaded JS file and adds findings."""
    soup = BeautifulSoup(html, "html.parser")
    scripts: set[str] = set()

    for tag in soup.find_all("script", src=True):
        src = tag.get("src")
        if src:
            scripts.add(src)

    # Scan ALL inline script blocks for routes (not just import/require)
    routes: list[str] = []
    for tag in soup.find_all("script"):
        if tag.string:
            _extract_routes(tag.string, routes)
    sem = asyncio.Semaphore(10)

    async def _fetch_script(src_raw: str):
        src = urljoin(base_url, src_raw)
        # Only fetch same-domain scripts (compare hostnames to be port-tolerant)
        parsed_src = urlparse(src)
        parsed_base = urlparse(base_url)
        src_host = parsed_src.hostname or ""
        if src_host != parsed_base.hostname:
            return
        # Respect scope, same as Skeleton Key
        if scope_pattern and not scope_pattern.match(src_host):
            return
        async with sem:
            try:
                resp = await client.get(src, timeout=httpx.Timeout(15))
                if resp.status_code == 200:
                    text = _safe_text(resp)
                    _extract_routes(text, routes)
                    # Run leak detection on the JS file itself
                    leaked = leak_detector_fn(text)
                    bh = _structural_hash(text)
                    if leaked:
                        ct = resp.headers.get("Content-Type", "application/javascript")
                        findings.append(Finding(
                            url=str(src),
                            status=200,
                            content_type=ct,
                            found_in="js_bundle",
                            secrets=leaked,
                            body_hash=bh,
                        ))
                        print(f"  {C['G']}[200]{C['W']} {src} {C['Y']}🔑 SECRETS:{len(leaked)}{C['W']}")
                    # Also try to find sourcemap references
                    sm_match = re.search(r"//# sourceMappingURL=(.+)", text)
                    if sm_match:
                        print(f"  {C['B']}[*]{C['W']} Source map found: {sm_match.group(1)}")
            except httpx.RequestError:
                pass

    tasks = [asyncio.create_task(_fetch_script(s)) for s in scripts]
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)

    # Deduplicate
    seen: set[str] = set()
    unique: list[str] = []
    for r in routes:
        r_clean = r.strip("/")
        if r_clean not in seen:
            seen.add(r_clean)
            unique.append(r_clean)
    print(f"  {C['B']}[*]{C['W']} Archivist: {len(unique)} unique routes from {len(scripts)} JS bundles")
    if unique:
        sample = ", ".join(f"/{r}" for r in unique[:8])
        pad = " ..." if len(unique) > 8 else ""
        print(f"       → {sample}{pad}")
    return unique


# ── 3. THE SKELETON KEY (recursive brute-force) ─────────────────────────────

async def _check_path(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    sem: asyncio.Semaphore,
    scope_pattern: Optional[re.Pattern],
    findings: list[Finding],
    leak_detector_fn,
) -> tuple[Optional[Finding], str]:
    """Request a single path; return (Finding_or_None, diagnostic_tag).
    Tags: scope_blocked | error | hit_2xx | hit_3xx | hit_403 | miss"""
    url = urljoin(base_url, "/" + path)
    parsed = urlparse(url)
    host = parsed.hostname or parsed.netloc.split(":")[0]
    if scope_pattern and not scope_pattern.match(host):
        return None, "scope_blocked"
    async with sem:
        try:
            resp = await client.get(url, follow_redirects=False, timeout=httpx.Timeout(10))
        except httpx.RequestError:
            return None, "error"

    status = resp.status_code
    ct = resp.headers.get("Content-Type", "")

    finding = Finding(url=url, status=status, content_type=ct, found_in="wordlist")

    if 200 <= status < 300:
        body = _safe_text(resp)
        finding.body_hash = _structural_hash(body)
        # Run leak detection on text-based responses
        if any(t in ct for t in ("javascript", "json", "xml", "text/html", "text/plain")) or path.endswith((".js", ".json", ".xml", ".bak", ".old", ".map")):
            finding.secrets = leak_detector_fn(body)

        findings.append(finding)
        col = _colour(status)
        extra = f" {C['Y']}🔑 SECRETS:{len(finding.secrets)}{C['W']}" if finding.secrets else ""
        print(f"  {col}[{status}]{C['W']} {url}{extra}")
        return finding, "hit_2xx"

    elif 300 <= status < 400:
        findings.append(finding)
        print(f"  {C['B']}[{status} → {resp.headers.get('Location', '?')}]{C['W']} {url}")
        return finding, "hit_3xx"

    elif status == 403:
        findings.append(finding)
        print(f"  {C['R']}[403]{C['W']} {url}")
        return finding, "hit_403"

    return None, "miss"


async def skeleton_key(
    client: httpx.AsyncClient,
    base_url: str,
    stack: str,
    scope_pattern: Optional[re.Pattern],
    concurrency: int,
    depth: int,
    findings: list[Finding],
    leak_detector_fn,
    archivist_routes: list[str],
) -> None:
    """Tech-stack-adaptive recursive brute-force."""
    # Select wordlist
    wordlist_map = {
        "PHP":        "php.txt",
        "Node/React": "node.txt",
        ".NET":       "dotnet.txt",
        "Java":       "common.txt",
        "Unknown":    "common.txt",
    }
    wl_file = wordlist_map.get(stack, "common.txt")
    base_entries = _load_wordlist("common.txt")
    # Avoid loading common.txt twice for Java/Unknown stacks
    stack_entries = _load_wordlist(wl_file) if wl_file != "common.txt" else []
    all_entries = list(dict.fromkeys(base_entries + stack_entries + archivist_routes))

    print(f"\n  {C['B']}[*]{C['W']} Skeleton Key: {len(all_entries)} paths (common + {wl_file} + JS routes), depth={depth}")

    sem = asyncio.Semaphore(concurrency)

    # Phase 1: initial burst
    hits: list[str] = []
    stats: dict[str, int] = defaultdict(int)
    tasks = [
        asyncio.create_task(
            _check_path(client, base_url, p, sem, scope_pattern, findings, leak_detector_fn)
        )
        for p in all_entries
    ]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for r, path in zip(results, all_entries):
        if isinstance(r, Exception):
            stats["exception"] += 1
            continue
        finding, tag = r  # Unpack (Finding|None, str) tuple
        stats[tag] += 1
        if finding is not None and finding.status in (200, 301, 302):
            # Only recurse into directory-like paths (skip files like .env, .php, etc.)
            if not _FILE_EXT_RE.search(path):
                hits.append(path)

    # Print Phase 1 stats
    scope_n = stats.get("scope_blocked", 0)
    err_n = stats.get("error", 0)
    hit_n = stats.get("hit_2xx", 0) + stats.get("hit_3xx", 0) + stats.get("hit_403", 0)
    miss_n = stats.get("miss", 0)
    print(f"  {C['B']}[*]{C['W']} Phase 1: {hit_n} hits, {miss_n} misses, {scope_n} scope-blocked, {err_n} errors")

    # Phase 2: recursive descent on discovered directories
    if depth < 1 or not hits:
        return

    suffixes = _load_wordlist("dir_suffixes.txt")
    print(f"\n  {C['B']}[*]{C['W']} Recursive descent on {len(hits)} hits, depth={depth}")

    for current_depth in range(2, depth + 1):
        new_hits: list[str] = []
        child_tasks = []
        child_pairs: list[tuple[str, str]] = []

        for parent in hits:
            for suffix in suffixes:
                child_path = f"{parent}/{suffix}"
                child_tasks.append(
                    asyncio.create_task(
                        _check_path(client, base_url, child_path, sem, scope_pattern, findings, leak_detector_fn)
                    )
                )
                child_pairs.append((parent, child_path))

        child_results = await asyncio.gather(*child_tasks, return_exceptions=True)
        for r, (parent, cpath) in zip(child_results, child_pairs):
            if isinstance(r, Exception):
                continue
            finding, tag = r  # Unpack (Finding|None, str) tuple
            if finding is None:
                continue
            if finding.status in (200, 301, 302):
                new_hits.append(cpath)
                # Update found_in from "wordlist" → "recursive"
                for f in findings:
                    if f.url == finding.url:
                        f.found_in = "recursive"
                        break

        print(f"  {C['B']}[*]{C['W']} Depth {current_depth}: {len(new_hits)} new hits")
        hits = new_hits
        if not hits:
            break


# ── 4. THE LEAK DETECTOR ───────────────────────────────────────────────────

# Secret patterns
_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("aws_access_key",     re.compile(r"AKIA[0-9A-Z]{16}")),
    ("aws_secret_key",     re.compile(r"(?i)aws(.{0,20})?(secret|key).{0,10}['\"]([0-9a-zA-Z/+]{40})['\"]")),
    ("bearer_token",       re.compile(r"Bearer\s+[a-zA-Z0-9\-_\.]+\.[a-zA-Z0-9\-_\.]+\.[a-zA-Z0-9\-_]+")),
    ("mongodb_uri",        re.compile(r"mongodb(?:\+srv)?://[^\"'\s]+")),
    ("password_in_js",     re.compile(r"""password\s*[:=]\s*["'][^"']{4,}["']""", re.IGNORECASE)),
    ("jwt_token",          re.compile(r"eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+(?:\.[a-zA-Z0-9\-_]+)?")),
    ("github_token",       re.compile(r"gh[pousr]_[a-zA-Z0-9]{36}")),
    ("google_api_key",     re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("private_key_header", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
    ("slack_webhook",      re.compile(r"https://hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+")),
    ("discord_webhook",    re.compile(r"https://discord(?:app)?\.com/api/webhooks/\d+/[0-9A-Za-z\-_]+")),
    ("stripe_key",         re.compile(r"(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}")),
    ("generic_api_key",    re.compile(r"""api[_-]?key\s*[:=]\s*["'][0-9a-zA-Z\-_]{16,}["']""", re.IGNORECASE)),
]


def leak_detect(content: str) -> list[str]:
    """Scan text content for secrets; return list of matched secret types."""
    found: set[str] = set()
    for name, pattern in _SECRET_PATTERNS:
        if pattern.search(content):
            found.add(name)
    return sorted(found)


# ── 5. THE PATHFINDER (soft-404 clustering) ────────────────────────────────

def _structural_hash(text: str) -> str:
    """Produce a structural fingerprint of an HTML/text response.
    Strips dynamic content (timestamps, tokens, IDs) and hashes the skeleton."""
    # Remove numbers, UUIDs, hex tokens, timestamps
    skeleton = re.sub(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", "UUID", text)
    skeleton = re.sub(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\b", "DATE", skeleton)
    skeleton = re.sub(r"\b\d{10,13}\b", "TS", skeleton)          # Unix timestamps
    skeleton = re.sub(r"\b[0-9a-f]{32,128}\b", "HEX", skeleton)  # Long hex
    skeleton = re.sub(r"\d+", "N", skeleton)                      # All remaining numbers
    return hashlib.sha256(skeleton.encode()).hexdigest()


def pathfinder_cluster(findings: list[Finding], min_cluster_pct: float = 0.30) -> list[Finding]:
    """Cluster findings by structural body-hash similarity. If a cluster of
    404-returning responses exceeds `min_cluster_pct` of all responses, mark
    them as soft-404 templates and exclude from output.

    Returns the filtered list.
    """
    if len(findings) < 5:
        return findings

    # Group by structural body hash (falls back to status:content_type if no hash)
    clusters: dict[str, list[Finding]] = defaultdict(list)
    for f in findings:
        key = f.body_hash if f.body_hash else f"{f.status}:{f.content_type}"
        clusters[key].append(f)

    total = len(findings)
    filtered: list[Finding] = []

    for key, group in clusters.items():
        # If a cluster is >30% and returns 404, it's a soft-404 template
        if len(group) / total > min_cluster_pct and group[0].status == 404:
            print(f"  {C['B']}[*]{C['W']} Pathfinder: filtered {len(group)} soft-404s (cluster size={len(group)}/{total})")
            continue
        filtered.extend(group)

    return filtered


# ── MAIN CLI ───────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="axiom — Context-Aware Reconnaissance & Attack-Surface Discovery Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  axiom https://example.com --scope "*.example.com"
  axiom https://target.io --scope "target.io" --depth 2 --concurrency 20
  axiom https://api.example.com --scope "api.example.com" --output results.jsonl
        """,
    )
    p.add_argument("target", help="Base URL to scan (e.g. https://example.com)")
    p.add_argument("--scope", required=True, help="Domain scope glob (e.g. '*.example.com')")
    p.add_argument("--depth", type=int, default=3, help="Recursive descent depth (default: 3)")
    p.add_argument("--concurrency", type=int, default=30, help="Concurrent request limit (default: 30)")
    p.add_argument("--output", "-o", default="output.jsonl", help="Output JSONL file (default: output.jsonl)")
    p.add_argument("--timeout", type=int, default=10, help="Per-request timeout in seconds (default: 10)")
    p.add_argument("--skip-archivist", action="store_true", help="Skip JS bundle parsing")
    p.add_argument("--skip-recursive", action="store_true", help="Skip recursive descent")
    return p.parse_args()


async def main() -> None:
    args = parse_args()
    target = args.target.rstrip("/")

    # Build scope regex from glob
    # Supported formats:
    #   ".example.com"     → matches example.com + *.example.com  (common bug-bounty format)
    #   "*.example.com"    → matches subdomains + apex
    #   "example.com"      → matches only example.com
    raw_scope = args.scope
    if raw_scope.startswith(".") and not raw_scope.startswith("*."):
        # Leading dot: treat as "apex and all subdomains"
        apex = raw_scope.lstrip(".")
        apex_escaped = apex.replace(".", r"\.")
        subdomain_pattern = apex_escaped.replace("*", r"[^.]+") if "*" in apex_escaped else rf"[^.]+\.{apex_escaped}"
        pattern = f"^(?:{apex_escaped}|{subdomain_pattern})$"
        print(f"  {C['B']}[*]{C['W']} Scope '{raw_scope}' → matches '{apex}' + '*.{apex}'")
    elif raw_scope.startswith("*."):
        bare_domain = raw_scope.replace("*.", "", 1).replace(".", r"\.")
        scope_glob = raw_scope.replace(".", r"\.").replace("*", r"[^.]+")
        pattern = f"^(?:{bare_domain}|{scope_glob})$"
    else:
        scope_glob = raw_scope.replace(".", r"\.").replace("*", r"[^.]+")
        pattern = f"^{scope_glob}$"
    scope_pattern = re.compile(pattern)

    print(f"{C['B']}═══ axiom — Recon Engine ═══{C['W']}")
    print(f"  Target:      {target}")
    print(f"  Scope:       {args.scope}")
    print(f"  Depth:       {args.depth}")
    print(f"  Concurrency: {args.concurrency}")
    print()

    # HTTP client with sensible defaults
    limits = httpx.Limits(max_connections=args.concurrency + 10, max_keepalive_connections=20)
    timeout = httpx.Timeout(args.timeout)
    headers = {
        "User-Agent": "axiom/1.0 (recon engine; bug bounty / authorized pentesting)",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
    }

    async with httpx.AsyncClient(
        headers=headers,
        timeout=timeout,
        limits=limits,
        follow_redirects=False,
    ) as client:

        # ── Step 1: Fingerprint ─────────────────────────────────────────
        t0 = time.monotonic()
        print(f"{C['Y']}[1/5] Fingerprinting target...{C['W']}")
        fp = await fingerprint(client, target)

        # Fetch root page for HTML parsing
        try:
            root_resp = await client.get(target, follow_redirects=True, timeout=httpx.Timeout(15))
            root_html = root_resp.text
        except httpx.RequestError:
            root_html = ""

        # Shared findings accumulator (Archivist + Skeleton Key both write to it)
        findings: list[Finding] = []

        # ── Step 2: Archivist (JS routes) ──────────────────────────────
        print(f"\n{C['Y']}[2/5] Archivist — parsing JS bundles...{C['W']}")
        archivist_routes: list[str] = []
        if not args.skip_archivist and root_html:
            archivist_routes = await archivist(client, target, root_html, findings, leak_detect, scope_pattern)

        # ── Step 3 & 4: Skeleton Key + Leak Detector (interleaved) ────
        print(f"\n{C['Y']}[3/5] Skeleton Key + Leak Detector...{C['W']}")

        await skeleton_key(
            client=client,
            base_url=target,
            stack=fp.stack,
            scope_pattern=scope_pattern,
            concurrency=args.concurrency,
            depth=args.depth if not args.skip_recursive else 1,
            findings=findings,
            leak_detector_fn=leak_detect,
            archivist_routes=archivist_routes,
        )

        # ── Step 5: Pathfinder (soft-404 filtering) ────────────────────
        print(f"\n{C['Y']}[4/5] Pathfinder — soft-404 clustering...{C['W']}")
        filtered = pathfinder_cluster(findings)

        # Deduplicate by URL (keep first occurrence for each unique URL)
        seen_urls: set[str] = set()
        unique_findings: list[Finding] = []
        for f in filtered:
            if f.url not in seen_urls:
                seen_urls.add(f.url)
                unique_findings.append(f)
        filtered = unique_findings

        # ── Output ─────────────────────────────────────────────────────
        print(f"\n{C['Y']}[5/5] Writing output...{C['W']}")

        output_path = Path(args.output)
        # Auto-increment: never overwrite a previous scan
        if output_path.exists():
            stem = output_path.stem
            suffix = output_path.suffix
            parent = output_path.parent
            n = 1
            while (parent / f"{stem}.{n}{suffix}").exists():
                n += 1
            output_path = parent / f"{stem}.{n}{suffix}"
            print(f"  {C['B']}[*]{C['W']} Output file exists → writing to {output_path}")
        written = 0
        try:
            with output_path.open("w") as f:
                for finding in filtered:
                    f.write(finding.to_jsonl() + "\n")
                    written += 1
        except OSError as e:
            print(f"  {C['R']}[!]{C['W']} Cannot write {output_path}: {e} — printing to stdout instead")
            for finding in filtered:
                print(finding.to_jsonl())
                written += 1
            output_path = Path("<stdout>")

        elapsed = time.monotonic() - t0

        # Summary
        status_counts = defaultdict(int)
        secret_hits = 0
        for f in filtered:
            status_counts[f.status] += 1
            if f.secrets:
                secret_hits += 1

        print(f"\n{C['G']}═══ Scan Complete ═══{C['W']}")
        print(f"  Time:       {elapsed:.1f}s")
        print(f"  Findings:   {written} written to {output_path}")
        print(f"  Secrets in: {secret_hits} responses")
        print(f"  Fingerprint: {fp.stack}")
        for s, c in sorted(status_counts.items()):
            col = _colour(s)
            print(f"  {col}[{s}]{C['W']}: {c}")


if __name__ == "__main__":
    asyncio.run(main())
