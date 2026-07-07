# AGENT.md — Axiom Project

## 1. Project Identity

- **Project Name:** `axiom` (codename)
- **Type:** Reconnaissance & Attack-Surface Discovery Engine
- **Primary Use Case:** Bug Bounty / Authorized Penetration Testing
- **Core Philosophy:** Context-aware, tech-stack-adaptive recon. Not a blind brute-forcer. Mimics a tier-1 manual hunter.

## 2. Problem Statement

Existing tools (`gobuster`, `ffuf`, `dirb`) are static battering rams. They waste time fuzzing irrelevant paths and fail to adapt to the target's actual technology stack. `axiom` solves this by:

- **Fingerprinting** the target tech stack (PHP, Node/React, .NET, Java, etc.) *before* brute-forcing.
- **Dynamically swapping** wordlists and recursion strategies based on the fingerprint.
- **Parsing JavaScript** bundles to extract hidden API routes and GraphQL endpoints.
- **Detecting hardcoded secrets** (AWS keys, JWTs, database URIs) in exposed static assets.
- **Recursive directory descent** (when `/admin` is found, it immediately fuzzes `/admin/config`, `/admin/backup`, etc.).

## 3. Core Modules (The "Four Pillars")

The tool must implement these four parallel pipelines:

| Module | Description |
| :--- | :--- |
| **The Archivist** | Downloads JS/CSS bundles, extracts route strings, parses source maps, runs secret scanning on downloaded JS files. Finds unlinked API endpoints and leaked credentials. |
| **The Skeleton Key** | Tech-stack-specific directory brute-force with recursive descent. |
| **The Leak Detector** | Regex-based secret scanning on every discovered `.js`, `.json`, `.xml`, and `.bak` file. |
| **The Pathfinder** | Response-clustering engine to filter soft-404s using Levenshtein distance or structural hashing. |

## 4. Technical Specifications

- **Language:** Python 3.10+ (for rapid prototyping) OR Go (for raw speed). Default to Python unless performance becomes a bottleneck.
- **Key Dependencies (Python):**
  - `httpx` — async HTTP client.
  - `beautifulsoup4` — HTML parsing.
  - `hashlib` (stdlib) — structural body hashing for soft-404 clustering.
- **Route Extraction:** Regex-based pattern matching on JS bundle content (AST walking via `esprima`/`js2py` deferred as future enhancement).
- **Concurrency:** `asyncio.gather` with `return_exceptions=True` for fault tolerance. Explicit exponential backoff on 429 responses is deferred to a future release.
- **Output:** JSON Lines (`.jsonl`) for machine parsing, plus human-readable colorized terminal output (Green=200, Blue=Redirects, Red=Errors, Yellow=Backups/Secrets).
- **Scope Control:** Mandatory `--scope` flag (e.g., `--scope "*.target.com"`) to prevent scanning out-of-scope domains.

## 5. Execution Workflow (The "Attack Flow")

The agent MUST execute the following steps in order:

1. **Fingerprint (Pre-Flight):**
   - Send a single request to the root (`/`).
   - Inspect `Server` header, cookies (`PHPSESSID`, `ASP.NET_SessionId`, `JSESSIONID`), static asset patterns (`?ver=`, `_next/static/`, `chunk-[hash].js`), and `X-Powered-By` headers.
   - Classify the target as: `PHP`, `Node/React`, `.NET`, `Java`, or `Unknown`.

2. **Dynamic Wordlist Selection:**
   - Based on the fingerprint, load a curated wordlist:
     - **PHP:** `wp-admin`, `config.php`, `.php`, `.phtml`
     - **Node/React:** `.json`, `.js.map`, `/api/v1`, `/graphql`, `/static/js/`
     - **.NET:** `.aspx`, `.ashx`, `/web.config`, `/api/`
     - **Unknown:** Fallback to generic `/admin`, `/backup`, `/swagger`, `/v1/`

3. **The Archivist (JS Parsing + Secret Scanning):**
   - Parse all `<script>` and `<link>` tags (including inline scripts).
   - Download JS bundles (same-domain only, scope-respecting).
   - Use regex patterns to extract string literals containing `/api/`, `/v1/`, `/graphql/`, `/webhook/`, etc.
   - Run the Leak Detector on every downloaded JS file; findings are tagged `found_in: "js_bundle"`.
   - Detect and report source map references (`//# sourceMappingURL=`).

4. **The Skeleton Key (Recursive Brute-Force):**
   - Run the initial wordlist burst (common + stack-specific + Archivist routes).
   - On a `200`/`301`/`302` for a directory-like path (file extensions like `.env`, `.php`, `.js` are filtered out), recursively concatenate `dir_suffixes.txt` suffixes.
   - Continue recursion up to `--depth` (default 3).
   - All requests respect the `--scope` pattern; out-of-scope hosts are silently skipped.

5. **The Leak Detector (Secret Scanning):**
   - Runs on every 2xx text-based response (`.js`, `.json`, `.xml`, `.bak`, `.old`, `.map`, `text/html`, `text/plain`) and on all Archivist-downloaded JS bundles.
   - 13 regex patterns covering:
     - AWS Access Keys (`AKIA[0-9A-Z]{16}`)
     - AWS Secret Keys
     - Bearer / JWT Tokens
     - MongoDB URIs (`mongodb://` and `mongodb+srv://`)
     - Hardcoded Passwords (`password = "..."`)
     - GitHub Tokens (`ghp_`, `ghs_`, etc.)
     - Google API Keys
     - Private Key Headers (`-----BEGIN PRIVATE KEY-----`)
     - Slack Webhooks
     - Discord Webhooks
     - Stripe API Keys (`sk_live_`, `pk_test_`, etc.)
     - Generic API Keys (`api_key = "..."`)

6. **The Pathfinder (Soft-404 Filtering):**
   - Compute a structural body hash (SHA-256 of normalized content: UUIDs, dates, timestamps, hex tokens, and all digits replaced with placeholders).
   - Cluster findings by body hash; if a 404-returning cluster exceeds 30% of all findings, treat it as a soft-404 template and exclude from output.
   - Falls back to `status:content_type` clustering when body hashes are unavailable (e.g., for 3xx/4xx responses where the body wasn't cached).

7. **Output Generation:**
   - Write all findings to `output.jsonl` with the following schema:
     ```json
     {
       "url": "https://target.com/api/v1/users",
       "status": 200,
       "content_type": "application/json",
       "found_in": "js_bundle",
       "secrets": ["mongodb_uri", "password_in_js"]
     }
     ```

## 6. Standard Operating Procedure (SOP) — Skills from 9arm-skills

**CRITICAL:** Before writing a single line of code, the agent MUST:

1. **Fetch the 9arm-skills repository:**
   ```bash
   npx skills add thananon/9arm-skills
   ```
   (Or clone it manually if `npx` is unavailable.)

2. **Adapt and adopt the following skills as the project's SOP:**

   - **`debug-mantra`** — Use this four-step discipline for every debugging session:
     1. Reproduce reliably.
     2. Know the fail path.
     3. Falsify the hypothesis.
     4. Every run is a breadcrumb.
     Recite the mantra at the start of any debugging session [1†L3-L6].

   - **`scrutinize`** — Before committing any code, run an outsider-perspective review of the plan or PR. Question intent, trace the actual code path, and verify the change does what it claims [0†L24-L28].

   - **`post-mortem`** — For every fixed bug, write a canonical record: root cause, mechanism, fix, validation, and how it slipped through. Do not draft without a reliable repro, known cause, and validated fix [0†L18-L23].

   - **`delegate`** — Delegate menial, well-scoped coding tasks (bulk renames, formatting, boilerplate, scaffolding) to a cheap subagent via the `agent tool (model_strength: "faster")` command [0†L28-L33].

3. **Embed these skills into the project's workflow:**
   - Create a `.claude/skills/` directory and symlink the skills (or copy them).
   - Reference them in every PR template and commit message.

## 7. Deliverables

By the end of this project, the agent must produce:

- A working `axiom.py` (or `axiom.go`) script.
- A `wordlists/` directory containing:
  - `common.txt`
  - `php.txt`
  - `node.txt`
  - `dotnet.txt`
  - `dir_suffixes.txt`
- A `README.md` with installation, usage examples, and scope control instructions.
- A `tests/` directory with sample targets and expected outputs.
- A `post-mortems/` directory for every bug fixed during development.

## 8. Agent Instructions (The "Master Prompt")

> **You are an elite offensive security engineer building `axiom`, a next-generation recon tool.**
>
> 1. **First**, fetch the 9arm-skills repository and adapt the `debug-mantra`, `scrutinize`, `post-mortem`, and `delegate` skills as your SOP.
> 2. **Second**, read this `AGENT.md` in full. Internalize the four modules and the execution workflow.
> 3. **Third**, begin implementation. Start with the fingerprinting module, then the Archivist, then the Skeleton Key, then the Leak Detector, and finally the Pathfinder.
> 4. **Throughout development**, apply the `debug-mantra` to every bug. Write a `post-mortem` for every fixed issue. Use `scrutinize` before any major PR.
> 5. **Deliver** a working, production-ready tool with clear documentation and tests.

---

**End of AGENT.md**
