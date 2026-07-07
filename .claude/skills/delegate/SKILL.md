---
name: delegate
description: Delegate well-scoped, mechanical tasks to a cheaper/faster sub-agent via the agent tool. Use for bulk edits, formatting, boilerplate, search & summarization, scaffolding, running tests and reporting pass/fail. Do NOT use for architecture, design, debugging judgment, or security-sensitive edits.
---

# Delegate — Axiom Edition

Offload **menial, self-contained** tasks to a faster CodeWhale sub-agent so the main session stays focused on design and judgment.

## How to delegate

Use the `agent` tool with `model_strength: "faster"`:

```
agent(
  model_strength: "faster",
  type: "explore" | "implementer" | "verifier",
  prompt: "<self-contained task>"
)
```

- **`type: "explore"`** — read-only lookup, search, summarization, wordlist audit
- **`type: "implementer"`** — write/edit tasks: bulk renames, formatting, boilerplate, scaffolding
- **`type: "verifier"`** — run tests, validate output, check edge cases

## Writing the task prompt

The sub-agent has **zero context** from this conversation. Every prompt must be standalone:

- **Absolute paths** for all files: `/home/python/Documents/axiom/axiom.py`
- **Explicit inputs, outputs, and acceptance criteria**
- **No references** to "the file we discussed" or prior turns

**Bad:** `fix the wordlist duplicates`
**Good:** `In /home/python/Documents/axiom/wordlists/common.txt, find and remove duplicate entries (case-insensitive). Keep the first occurrence of each. Report which entries were removed and the final count.`

## Axiom-appropriate delegation tasks

| Task type | Example | Type |
| :--- | :--- | :--- |
| Wordlist audit | Count entries, find dupes, check for malformed lines | `explore` |
| Code quality scan | Check all regexes compile, all imports used, no bare excepts | `explore` |
| Test runner | Start test server, run axiom, validate JSONL output | `verifier` |
| Bulk wordlist edit | Add 20 new paths to php.txt, dedup after | `implementer` |
| Doc sync check | Compare AGENT.md claims vs axiom.py implementation | `explore` |
| Secret pattern test | Run all 13 regexes against test fixtures, report matches | `verifier` |

## When NOT to delegate

- Architecture decisions, module design
- Debugging that needs reasoning across multiple code paths
- Security-sensitive regex or scope changes
- Anything requiring this conversation's context
- Tasks where a wrong edit is costly to catch

## Parallel delegation

Launch independent tasks in the same turn — the dispatcher runs them concurrently:

```python
agent(type="explore", prompt="Audit wordlists...")
agent(type="verifier", prompt="Run test suite...")
agent(type="implementer", prompt="Add missing paths...")
```

## Verification

**Always verify sub-agent output yourself.** Faster models are cheaper and less reliable. Check the file/result actually meets the acceptance criteria before reporting success. Cross-check one load-bearing finding against a direct `read_file` or `exec_shell`.

## Relationship to SOP chain

- Use `delegate` for menial work discovered during `scrutinize` (e.g., "run the test suite", "audit the wordlists")
- Use `delegate` to verify fixes before writing a `post-mortem`
- The sub-agent runs tests; **you** decide if the test results validate the fix
