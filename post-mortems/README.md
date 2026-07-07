# Post-Mortems

This directory holds canonical engineering records for every bug fixed during
axiom's development. Each post-mortem follows the SOP established from
`9arm-skills` (see `.claude/skills/post-mortem/SKILL.md`).

## Required inputs before drafting

- [x] Reliable repro exists
- [x] Root cause is known
- [x] Fix is identified (commit / PR)
- [x] Fix is validated

## Structure

Each post-mortem must include:
1. **Summary** — what broke, what fixed it (one paragraph)
2. **Symptom** — what was observed
3. **Root cause** — the actual bug mechanism with code identifiers
4. **Why it produced the symptom** — cause-to-effect chain
5. **Fix** — what changed and why it addresses root cause
6. **How it was found** — debugging trail, disproved hypotheses
7. **Why it slipped through** — test/safety gap
8. **Validation** — evidence the fix works
9. **Action items** — with owners and tracking artifacts

## SOP Skills in Use

| Skill | Location | Purpose |
| :--- | :--- | :--- |
| `debug-mantra` | `.claude/skills/debug-mantra/SKILL.md` | Four-step debugging discipline |
| `scrutinize` | `.claude/skills/scrutinize/SKILL.md` | Pre-commit outsider review |
| `post-mortem` | `.claude/skills/post-mortem/SKILL.md` | Bug fix engineering record |
| `delegate` | `.claude/skills/delegate/SKILL.md` | Delegate menial tasks to faster sub-agent |

These skills were adapted from `thananon/9arm-skills` and customized for the
axiom project and CodeWhale workflow. Every PR template and commit message should reference them.
