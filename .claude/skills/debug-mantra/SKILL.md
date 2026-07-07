---
name: debug-mantra
description: Four-mantra debugging discipline for axiom. Recite verbatim at debug start, then apply four steps in order. Use for any bug, crash, stack trace, or investigation in the axiom codebase.
---

# Debug Mantra — Axiom Edition

Four-step discipline for debugging axiom. Recite verbatim, then apply in order.

## Recite this — verbatim

> **Mantra:**
> 1. **First is reproducibility.** Can the issue be reproduced reliably?
> 2. **Know the fail path.** Trace the actual code path; debugger or instrumentation.
> 3. **Question your hypothesis.** What would disprove it?
> 4. **Every run is a breadcrumb.** Cross-reference all of them.

---

## Axiom project context

- **Main code:** `axiom.py` (~710 lines) — async HTTP engine with 4 modules
- **Test server:** `tests/test_server.py` — start with `.venv/bin/python tests/test_server.py`, serves on port 8080
- **Run a scan:** `.venv/bin/python axiom.py http://127.0.0.1:8080 --scope "127.0.0.1" --depth 2`
- **Wordlists:** `wordlists/` — 5 files (common, php, node, dotnet, dir_suffixes)
- **Output:** JSONL at `output.jsonl` (auto-increments: output.1.jsonl…)
- **Git:** `main` branch → `github.com/poppp334/axiom`
- **Deps:** `.venv/` with httpx, beautifulsoup4

### Quick repro for axiom bugs

```bash
# Start test server
.venv/bin/python tests/test_server.py &
# Run scanner
.venv/bin/python axiom.py http://127.0.0.1:8080 --scope "127.0.0.1" --depth 2 -o /tmp/test.jsonl
# Check output
cat /tmp/test.jsonl | python -m json.tool | head -20
```

### Known bug patterns (from prior sessions)

| Pattern | Example | Root cause |
| :--- | :--- | :--- |
| `return` in async generator | `yield` + `return value` in same function | Use `routes.append()` not `yield` |
| `asyncio.gather` cascade failure | One task exception kills all results | Always `return_exceptions=True` |
| `resp.text` on binary body | `UnicodeDecodeError` on gzip/binary 404 | Use `_safe_text(resp)` wrapper |
| Scope regex mismatch | `.kaigo.thai.ac` doesn't match `kaigo.thai.ac` | Leading-dot scope format |
| Pathfinder dead code | 404s never added to findings | Body-hash clustering regardless of status |

---

## 1. Reproduce reliably

- **For axiom:** the test server is your always-available target. Pin the scan flags that trigger the bug.
- **Flaky bug?** Loop the scan: `for i in $(seq 1 20); do .venv/bin/python axiom.py ...; done`
- Target: a 1–5 second deterministic pass/fail signal.

## 2. Know the fail path

Trace the module pipeline in order: Fingerprint → Archivist → Skeleton Key → Leak Detector → Pathfinder.

Key trace points (add `print(f"[DBG-xxx] var={var}")`):
- `_check_path()` — per-request gateway, returns `(Finding|None, tag)`
- `_extract_routes()` — JS route extraction, uses 2 regexes + blacklist
- `leak_detect()` — 13 secret patterns, returns type names
- `pathfinder_cluster()` — body_hash clustering, 30% threshold
- `skeleton_key()` — Phase 1 (wordlist) + Phase 2 (recursive descent)

## 3. Falsify the hypothesis

For axiom bugs, quick disprovers:
- **Scope issue?** Run with `--scope "127.0.0.1"` vs test server — if it works, it's a scope regex bug.
- **HTTP issue?** `curl -s http://127.0.0.1:8080/THE_PATH` to isolate server from scanner.
- **Regex issue?** Test pattern in isolation: `python -c "import re; print(re.findall(r'PATTERN', open('file').read()))"`.
- **Concurrency issue?** Run with `--concurrency 1` to serialize — if bug disappears, it's a race.

## 4. Every run is a breadcrumb

Track in the conversation: what flags you changed, what scan output showed, what was ruled out. The scan output (`Phase 1: N hits, M misses, S scope-blocked, E errors`) is your primary diagnostic — watch how these numbers change.

---

## Operating rules

- Recite the mantra block **once** per debug session.
- Apply the four steps **in order** — don't propose a fix before you have a repro and a traced fail path.
- Use `tests/test_server.py` as your first repro target unless the bug is clearly production-only.
- After fixing, write a post-mortem in `post-mortems/` (see post-mortem skill).
