# fragments

Knowledge for model checks: the deep audit today, the advisory reviewer on pull requests later. Both read the same files.

## Sources

`registry.json` lists the skills an audit can draw on. A source is either pinned by git commit and fetched (`git`, `commit`), or detected where it is already installed (`skill`). A licensed skill is detected, never copied.

| Source | Role | How it is obtained |
|---|---|---|
| Cloudflare [`security-audit`](https://github.com/cloudflare/security-audit-skill) (MIT) | The audit process. Required | Fetched at the pinned commit into the tool cache |
| jsm `security-audit-for-saas` (proprietary, by subscription) | SaaS and Supabase domain knowledge | Detected in `~/.claude/skills`, `~/.agents/skills` or `~/.codex/skills` |
| OpenAI `security-threat-model`, `security-best-practices` | Threat model and framework checklists | Detected in the same places |

`modes` names the set that resolved: `full` when the jsm skill is installed, `open` otherwise. `node bin/whs.mjs fragments <repo>` shows the mode, each source and what was not available. An audit's run file records the same, so reduced coverage is always stated.

## Fragments

A fragment is a file in the shape Cloudflare's skill calls a companion: `When to use this file`, `Core discipline`, one or more attack-class sections, `Universal moves`, `Validation rules`. The audit quotes those blocks into hunter prompts exactly as it does for its own companions, and its ledger validator accepts block references to files outside its directory.

| Fragment | Applies when the target has |
|---|---|
| `postgres-supabase.md` | SQL migrations or a `supabase/` directory |
| `ci-deploy-credentials.md` | GitHub Actions workflows |
| `agent-configuration.md` | Agent settings, instruction files or skills |

A fragment holds what InStrand has learned that the sources do not say. Write one when an audit confirms a finding that a hunter could have reached sooner with a sentence of guidance. Keep it general: no customer, no incident detail.
