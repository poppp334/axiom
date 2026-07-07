---
name: scrutinize
description: Outsider-perspective end-to-end review of axiom code, plans, or PRs. Questions intent, traces actual code paths, verifies claims. Output is concise, actionable, with rationale.
---

# Scrutinize — Axiom Edition

Stand outside the change and ask whether it should exist at all, then verify it actually does what it claims end-to-end.

## Axiom module checklist

When reviewing axiom, trace each of these surfaces:

| Module | File:line range | What to verify |
| :--- | :--- | :--- |
| Fingerprint | `axiom.py:~105-180` | Tech-stack classification, header/cookie parsing |
| Archivist | `axiom.py:~195-300` | JS bundle fetch, route extraction (2 regexes), leak-detect on bundles, scope enforcement |
| Skeleton Key | `axiom.py:~310-465` | Wordlist loading, Phase 1 burst, Phase 2 recursion, `return_exceptions`, file-ext filter, stats |
| Leak Detector | `axiom.py:~465-500` | 13 regex patterns, `\b` boundaries, `password_in_js` ≥8 chars |
| Pathfinder | `axiom.py:~505-535` | Body-hash clustering, >30% filter, fallback to status:content_type |
| CLI / Main | `axiom.py:~540-710` | Scope parsing (`.domain`, `*.domain`, exact), arg parsing, output auto-increment |
| Wordlists | `wordlists/` | No duplicates, no malformed entries, tech-stack coverage |
| Test server | `tests/test_server.py` | Covers all 4 modules, secrets in JS + .env + backup files |

## Known issues found in prior reviews

These are the most common bug classes in axiom — check for them proactively:

1. **`asyncio.gather` without `return_exceptions=True`** — one task crash kills all results
2. **`resp.text` without `_safe_text()`** — crashes on binary/gzip responses
3. **Scope regex doesn't handle leading-dot format** — `.example.com` must match apex + subdomains
4. **Pathfinder dead code** — 404s must be in findings or clustering must use body_hash alone
5. **Regex missing `\b` boundaries** — false positives on substring matches
6. **`--timeout` flag ignored** — hardcoded timeout values in internal functions
7. **Doc-code mismatch** — AGENT.md / README.md claims vs actual implementation

## Workflow

### 1. Intent
State the goal. Is there a simpler way? Could existing code already solve this?

### 2. Trace
Walk the actual code path end-to-end. Include unchanged code on either side. Note surprises.

### 3. Verify
For each claim: does the traced path produce it? What inputs break it? What does it silently change?

### 4. Report
One finding per section, ordered: BLOCKER → MAJOR → NIT.
Each: Finding (one sentence, cite file:line), Why it matters, Evidence, Suggested fix.
Close with one-line verdict: ship / fix-then-ship / rework.

## Project references

- **Repo:** `github.com/poppp334/axiom` (branch: `main`)
- **Test command:** `.venv/bin/python axiom.py http://127.0.0.1:8080 --scope "127.0.0.1" --depth 2`
- **Post-mortems archive:** `post-mortems/` — check if similar bugs were already analyzed
- **SOP chain:** debug-mantra → scrutinize → post-mortem (see companion skills)

## Operating rules

- **No rubber-stamps.** Say what you traced and what you checked.
- **Cite file:line.** Every claim references a specific location in `axiom.py`.
- **Lead with structural issues, defer nits.**
- **One simpler-alternative pass is mandatory.** Even on small changes.
