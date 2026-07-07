# axiom — Context-Aware Reconnaissance & Attack-Surface Discovery Engine

A next-generation recon tool for bug bounty hunters and authorized penetration
testers. Unlike static fuzzers (`gobuster`, `ffuf`, `dirb`), axiom **fingerprints**
the target's technology stack first and adapts its wordlists, recursion strategy,
and detection rules accordingly.

## The Four Pillars

| Module | Role |
| :--- | :--- |
| **The Archivist** | Downloads JS bundles, extracts API routes & GraphQL endpoints, detects source maps, runs secret scanning on JS files |
| **The Skeleton Key** | Tech-stack-adaptive recursive directory brute-force |
| **The Leak Detector** | Regex-based secret scanning (AWS keys, JWTs, MongoDB URIs, tokens, webhooks) |
| **The Pathfinder** | Soft-404 clustering via structural similarity to filter noise |

## Installation

```bash
git clone https://github.com/example/axiom.git
cd axiom

# Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install httpx beautifulsoup4
```

**Requirements:** Python 3.10+

## Quick Start

```bash
# Basic scan with mandatory scope
python axiom.py https://target.com --scope "*.target.com"

# Deeper recursion, higher concurrency
python axiom.py https://api.target.com --scope "api.target.com" --depth 4 --concurrency 50

# Skip JS parsing for pure brute-force mode
python axiom.py https://target.io --scope "*.target.io" --skip-archivist

# Custom output file
python axiom.py https://target.dev --scope "*.target.dev" -o scan_results.jsonl
```

## CLI Reference

```
axiom.py TARGET --scope SCOPE [OPTIONS]

Required:
  TARGET                  Base URL to scan (e.g. https://example.com)
  --scope SCOPE           Domain scope glob (e.g. "*.example.com")

Options:
  --depth N               Recursive descent depth (default: 3)
  --concurrency N         Concurrent request limit (default: 30)
  --output, -o PATH       Output JSONL file (default: output.jsonl)
  --timeout N             Per-request timeout in seconds (default: 10)
  --skip-archivist        Skip JS bundle parsing
  --skip-recursive        Skip recursive descent (depth=1 only)
```

## Output Format

Findings are written as JSON Lines (`.jsonl`):

```json
{"url": "https://target.com/api/v1/users", "status": 200, "content_type": "application/json", "found_in": "wordlist", "secrets": []}
{"url": "https://target.com/.env", "status": 200, "content_type": "text/plain", "found_in": "wordlist", "secrets": ["mongodb_uri", "password_in_js"]}
{"url": "https://target.com/admin/config", "status": 200, "content_type": "text/html", "found_in": "recursive", "secrets": []}
```

Terminal output is color-coded:
- **Green** — 2xx success
- **Blue** — 3xx redirects
- **Red** — 4xx/5xx errors
- **Yellow** — secrets found

## Workflow

1. **Fingerprint** — One request to `/` classifies the target as PHP, Node/React, .NET, Java, or Unknown.
2. **Archivist** — Parses `<script>` tags, downloads JS bundles, extracts `/api/`, `/v1/`, `/graphql/`, and `/webhook/` routes via regex.
3. **Skeleton Key** — Loads the tech-stack wordlist + common base + JS routes, fires concurrent requests, then recursively descends into discovered directories.
4. **Leak Detector** — On every 2xx text-based response AND every Archivist-downloaded JS bundle, scans for 13 secret patterns (AWS keys, Bearer tokens, MongoDB URIs, JWT, GitHub tokens, Slack/Discord webhooks, Stripe keys, private key headers, Google API keys, and more).
5. **Pathfinder** — Clusters responses by structural body-hash similarity (SHA-256 of normalized content); if a 404 cluster exceeds 30% of total, treated as soft-404 and filtered out. Falls back to status/content-type clustering when body is unavailable.
6. **Output** — Filtered findings written to `output.jsonl`.

## Wordlists

axiom ships with curated, tech-stack-specific wordlists under `wordlists/`:

| File | Purpose |
| :--- | :--- |
| `common.txt` | Base-level generic paths (all stacks) |
| `php.txt` | WordPress, Laravel, Symfony, Drupal, PHP configs |
| `node.txt` | Next.js, Express, SPA routes, GraphQL, WebSockets |
| `dotnet.txt` | ASP.NET, IIS, SharePoint, MVC, WCF, Web API |
| `dir_suffixes.txt` | Recursive-descent suffixes (`admin/login`, `admin/config`, etc.) |

Add your own wordlists by placing `.txt` files in `wordlists/` and updating
`axiom.py`'s `wordlist_map` in the `skeleton_key` function.

## Scope Control

The `--scope` flag is **mandatory**. It prevents axiom from following redirects
or making requests to out-of-scope domains. It accepts glob-style patterns:

- `--scope "*.example.com"` — matches `api.example.com`, `admin.example.com`, AND `example.com` itself. Does not match `example.com.attacker.io`.
- `--scope "example.com"` — matches only `example.com`
- `--scope "*.target.io"` — matches any subdomain of `target.io` AND `target.io` itself

## Testing

```bash
# Run the built-in test server and scan it
python tests/test_server.py &
python axiom.py http://127.0.0.1:8080 --scope "127.0.0.1" --depth 2
```

## License

This tool is provided for authorized security testing only. Always obtain
written permission before scanning any target you do not own.
