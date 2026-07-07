---
name: post-mortem
description: Write the canonical engineering record of a fixed axiom bug. Use after a debug session lands a fix. Output goes to post-mortems/ directory.
---

# Post-mortem — Axiom Edition

The canonical engineering record of a bug fix in axiom. Written **after** debugging lands a real fix, stored in `post-mortems/`.

## Required inputs — refuse without these

- [ ] **Reliable repro exists** (test server invocation or curl command)
- [ ] **Root cause is known** (mechanism identified, not hypothesis)
- [ ] **Fix is identified** (commit SHA on `main`)
- [ ] **Fix is validated** (original repro now passes)

## Structure

### 1. Summary _(mandatory)_
What broke (user-visible). What fixed it. Commit SHA. One paragraph.

### 2. Symptom
Concrete observation: scan output, error message, stack trace, missing finding, wrong secret.

### 3. Root cause _(mandatory)_
The actual bug mechanism. Use code identifiers: function names, `file:line`, regex patterns, variable names. Walk the cause chain end-to-end.

### 4. Why it produced the symptom
Connect root cause → symptom. Often non-obvious (e.g., scope regex mismatch produces 0 findings with no error).

### 5. Fix _(mandatory)_
What changed and why it addresses root cause. Link to commit. If a prior fix attempt papered over the symptom, name it.

### 6. How it was found
Debugging trail: what was tried, what was ruled out, which experiment nailed it.

### 7. Why it slipped through
Test gap, review gap, unexercised code path, missing edge case.

### 8. Validation _(mandatory)_
Evidence the fix works. Include exact commands run and output observed.

### 9. Action items
With owners and tracking (commit SHAs, issue numbers).

## Real axiom example

**Bug:** axiom returns 0 findings on `kaigo.thai.ac` with `--scope ".kaigo.thai.ac"`.

**Root cause.** `axiom.py:528-536`: scope regex builder treated leading-dot scope (`.kaigo.thai.ac`) as an exact-match pattern `^\.kaigo\.thai\.ac$`, which matches the literal string `.kaigo.thai.ac` but NOT the hostname `kaigo.thai.ac`. All 118 requests silently filtered with no diagnostic.

**Fix.** Commit `082151b`: added leading-dot format detection. `.example.com` now generates `^(?:kaigo\.thai\.ac|[^.]+\.kaigo\.thai\.ac)$` matching both apex and all subdomains.

**How it was found.** User reported 0 findings on real target. Traced `_check_path` → found `return None, "scope_blocked"` on scope mismatch. Isolated scope regex builder — confirmed pattern `^\.kaigo\.thai\.ac$` vs hostname `kaigo.thai.ac`.

**Validation.** Unit test: 10/10 scope combinations pass. Integration test: scan against test server with `--scope ".127.0.0.1"` → findings produced (was 0 before fix).

## File naming convention

```
post-mortems/YYYY-MM-DD-short-slug.md
```

Example: `post-mortems/2026-07-07-scope-leading-dot.md`

## Operating rules

- **Refuse to draft without all four required inputs.**
- **Never invent root cause, validation, or action items.** If unknown, ask.
- **Use code identifiers** — this is the engineering record, not a management summary.
- **Blameless.** Describe gaps and bugs, never people.
- **State validation coverage honestly.** If you only tested one config, say so.
- **One iteration is normal, three is a smell.**
