# AGENTS.md: workhorse-security

The durable law of this repository for agents, Claude or Codex, solo or in a swarm. General rules
live in `~/.agents/AGENTS.md`. Re-read this file after context compaction.

---

## RULE 0 - THE FUNDAMENTAL OVERRIDE PREROGATIVE

If I (Ryan) tell you to do something, even if it goes against what follows below, YOU MUST LISTEN TO ME.

## RULE NUMBER 1: NO FILE DELETION

**YOU ARE NEVER ALLOWED TO DELETE A FILE WITHOUT EXPRESS PERMISSION.** Even a new file that you yourself
created. List files or folders you think should go and ask for clear, written permission. Moving, renaming
and restoring files is allowed.

Agent-owned artefacts (scan output, run directories, scratch configs, fixture output, evidence files) may
be replaced or removed by the agent that produced them. Source code, docs, beads and other agents' files
stay under RULE 1.

## Irreversible Git & Filesystem Actions: DO NOT EVER BREAK GLASS

1. **Absolutely forbidden commands:** `git reset --hard`, `git clean -fd`, `rm -rf`, or any command that
   can delete or overwrite code or data, unless Ryan provides the exact command and states in the same
   message that the irreversible consequences are understood and wanted.
2. **No guessing.** If you are unsure what a command might delete or overwrite, stop and ask.
3. **Safer alternatives first.** In the shared tree, `git stash` takes every agent's uncommitted work:
   never run it. Never `git restore` or `git checkout` a file you did not author.
4. **Restate and confirm** any authorised destructive command verbatim, with what it affects, before
   running it, and record the authorising text, the command and the time.

---

## This repository

- workhorse-security is InStrand's security scanning standard and the pack that applies it, owned by
  Ryan Griffin, MIT-licensed. Ryan decided on 11 November 2026 that it is public (decision D9 in the
  standard). Treat every commit, bead and comment as public. Never commit a customer's name, a
  customer's repository or project identifiers, the names of people at a customer, a customer's
  findings or figures, or any customer data. Say "a customer monorepo" or "one real repository". The
  record of a customer's audit lives in that customer's private engagement repository.
- Nothing that comes from a finding enters this repository until the finding is closed: no rule, canary,
  fragment line, bead or commit message. A new rule that appears soon after an audit says what the
  audit found. Until closure the proposal stays on the finding's bead in the private tracker (standard
  9.6). When it moves here it is written in general terms, with nothing that says where it came from.
- The pre-push hook refuses every push until the machine-level file
  `${XDG_CONFIG_HOME:-~/.config}/flywheel-teams/confidential-terms` (`WHS_CONFIDENTIAL_TERMS` overrides
  the path) holds a term or the line `no-terms`, then refuses any push whose commits or ref names
  contain a listed term. The file is shared with flywheel-teams so one list covers both. It then runs
  `test/run.sh` on the pushed commit. `scripts/dev-setup.sh` activates it.
- The jsm skills are proprietary. Read them where they are installed. Never copy their text into this
  repository, a fragment, a canary, a test or a bead.
- The plan of record is `docs/plans/2026-11-11-security-scanning-standard.md`. Work is tracked as `whs-*`
  beads in `.beads/`. Handoff notes live in `docs/handoffs/`.
- This repository runs the normal flywheel on itself: beads prefix `whs`, trunk `main`, Agent Mail with
  this checkout's path under the ntm projects base as the project key (`.ntm/config.toml`).

### The six parts

Everything here is one of six parts, or a combination of them. Before adding code, find the part it
belongs to. If a capability seems to need its own mechanism, the design is wrong or a part is missing;
raise it instead of adding a special case.

| Part | Lives in | Add one by |
|---|---|---|
| Repository config | `security/config.json` in each repository; schema in `lib/config.mjs` | Extending the schema, with a refusal test |
| Surface | `lib/surface.mjs`, `adapters/` | A builder that returns a directory the pack owns, or a selection of commits |
| Check | `checks/registry.json` | A registry entry and canaries. No code |
| Fragment | `fragments/` and `fragments/registry.json` | A file in the companion shape and a registry entry |
| Canary | `canaries/<check>/<case>/expect.json` | A catching case and a quiet case |
| Record | `lib/findings.mjs`, `record/` | Converters into SARIF; everything else reads findings |

### Layout

| Path | Holds |
|---|---|
| `bin/whs.mjs`, `lib/` | The `whs` command: `install`, `canary`, `gate`, `scan`, `fragments`, `audit prepare` |
| `checks/` | `registry.json` (pinned tools and checks), `semgrep/rules/`, `semgrep/requirements.txt`, `gitleaks/` |
| `canaries/` | Known cases, one directory per check |
| `fragments/` | Companion files and `registry.json` (sources, coverage modes, fragments) |
| `skills/workhorse-security-audit/` | The deep audit skill |
| `.github/workflows/` | `security.yml` (the reusable gate) and `test.yml` (this repository's CI) |
| `workflows/` | The caller workflow a repository copies |
| `security/config.json` | This repository's own config |
| `posture/`, `adapters/`, `record/`, `probes/`, `estate/` | Not built. Each README says what goes there and what it wraps |
| `test/` | `run.sh`, `*.test.mjs`, `prepush-gate.test.sh` |
| `docs/` | `plans/`, `handoffs/` |

---

## Project Mission

Written on 11 November 2026 from the standard and accepted the same day under Ryan's delegation ("they
generally sound fine"). Ryan may amend it.

workhorse-security gives InStrand one way of hardening and scanning every repository it works in: its own,
and its customers'. It stays a thin wrapper around tools other people maintain, adds only what those
tools leave open for InStrand's stacks and customers, and improves from its own findings. Agents observe,
investigate and propose. A person approves. The aim for Workhorse-written code is to approach the point
where a defect cannot be written; the aim for customer-written code is a packaged gate, audit and fix
offer that assumes nothing about the customer's machines.

### Milestones

1. Bootstrap (11 November 2026): this repository, the runner, the gate with three checks, the starter
   rules and canaries, the audit skill in its first form. Known when CI is green on both runners.
2. First baseline audit. Known when one audit has run to a validated record on a real repository in a
   stated coverage mode, and its findings are beads.
3. Every change, in every repository: the gate, the advisory reviewer and the deploy wait, adopted by
   `customer-template` and through the overlay. Known when a required `security-gate` check runs on
   pull requests in three repositories.
4. Platform posture: declared baselines, verified weekly. Known when drift from a baseline files a bead.
5. The loop: one record, the importer, closure by re-scan of what is deployed. Known when a security bead
   closes because a later scan no longer reports its fingerprint.
6. Intelligence: advisories matched against what each repository depends on. Known when an advisory
   becomes a bead without a person reading a feed.

### Non-goals

- Writing a scanner, an audit method or a posture tool where a maintained one exists.
- Redesigning the flywheel process (Layer 0). It is referenced.
- Holding any customer's findings, names or data.
- A hosted service. Checks run in the repository's own CI, in operator sessions, or on InStrand's server.

---

## Who decides

Ryan decides: the mission and the standard; visibility, licence and releases; spend, including API keys,
GitHub plan changes and the budget of an audit; exceptions in an InStrand repository's config; anything
sent to a customer; deleting files (RULE 1).

A customer decides everything that changes its repositories, process or spend.

Within a bead, the working agent or the conductor decides implementation details: structure, tests,
fixtures, tool versions, bead mechanics. Record each decision and its reason on the bead and report it as
a decision Ryan may veto.

A question for Ryan is one of his decisions or a fact only he knows. Ask it as one short question in the
reply, record it on the bead, and keep working on everything else.

---

## The shared tree (Agent Flywheel)

- **One working tree, one branch (`main`). NEVER create or use git worktrees.** Agents coordinate by
  reserving files through Agent Mail before they edit.
- **Beads is the tracker** (prefix `whs`, committed in `.beads/`).

The loop, per bead:

1. Pick: `bv --robot-triage` (never bare `bv`; it opens a TUI) or `br ready`. Confirm with
   `br show <id> --json`. Claim with `br update <id> --claim`. Take the highest-priority ready bead.
2. Reserve every file you will edit through Agent Mail, with the bead id in the reason.
3. Implement with tests. Run `test/run.sh` and review your own diff with fresh eyes.
4. Commit and push (rules below), then mail the conductor the bead id, the commit SHA and a short evidence
   line. The conductor closes the bead (Honest credit).

Committing in a tree that other agents are editing at the same moment:

- The index is shared. Never `git add -A` or `git add .`, and never clear or unstage a peer's entries.
- Before you stage, run `git status` and `git diff <file>` on every path, and stage only files you touched
  in this session. Run `git status` again immediately before every commit.
- Commit with explicit paths: `git add -- <new paths> && git commit -m "<scoped message>" -- <paths>`.
  Never bypass a hook. Commit messages cite the bead id.
- Fetch your Agent Mail inbox right before every push and honour any push hold. Push the verified commit
  by SHA: `git push origin <sha>:refs/heads/main`. The pre-push hook runs the tests and the
  confidentiality check; a refusal is a defect in the commit.
- Never revert, restore or overwrite a peer's in-progress work; report a contaminated commit instead.

Tools: `br`, `bv` (robot flags only), `ntm`, Agent Mail, `cass`, `ubs`, `shellcheck`, and `dcg` (it
blocks destructive commands; follow its safer alternative, never work around it). dcg also refuses shell
heredocs that contain regular expressions or redirects to computed paths: write such files with the file
tools.

---

## Honest credit (binding for agents and humans alike)

The purpose of agent work here is working, installable capability. Process serves that outcome and never
becomes the product.

- **Closes come only from the conductor, after independent review.** Never close your own bead or a
  peer's. Never close a red bead: if verification is blocked, leave the bead open and name the blocker.
- **Real code and real tests ship in the same bead.** Forbidden: faked tests, weakened assertions,
  hard-coded success paths, editing the standard instead of implementing it, and narrowing scope while
  claiming full success.
- **Every rule ships with its canaries.** A catching case and a quiet case. Never change a canary's
  expected count to match a rule that got weaker.
- **Every behaviour of the gate carries a planted negative that must fail.** See `test/gate.test.mjs`:
  a change that excuses itself, a change that hides itself, a scanner that errors.
- **Never weaken a gate to get green.** Do not edit a check, an exception, a pin or a tolerance so a
  failing change passes. An exception needs an owner and a reason, and Ryan decides it here.
- **Evidence is what the command examined.** Never silence stderr in a command you cite. A run over zero
  files or zero tests is not a pass. A scanner that did not run is not a clean scan.
- **Security findings** are described by location and impact, never as a working exploit, and never with
  secrets, tokens or personal data in a bead.
- **Solo session, no conductor:** close only after re-running the bead's tests and planted negatives
  against its original acceptance criteria, with a close reason that says "solo: self-verified, not
  independently reviewed".

---

## Code rules

- The `whs` command is Node ESM using the standard library only. No npm dependencies, no build step, no
  `package.json` scripts to run first. It must work on Node 20 and later, on Linux and macOS.
- A scanner is run only through `checks/registry.json`. Its version is exact and its download is checked
  against a SHA-256 (or, for Semgrep, a requirements file with a hash for every package). A version
  change is a registry change with the canaries green. Tools never run from `PATH`.
- A check reads a surface the pack built. A tree-reading check gets no path back to the repository.
- Nothing lets scanned content switch a scanner off. When a tool gains an ignore file or an inline
  ignore comment, add it to that check's `neutralise` entry with a test.
- The gate fails closed: a non-zero exit, a missing report or unreadable SARIF is an error.
- Shell scripts start with `#!/usr/bin/env bash` and `set -euo pipefail`, pass under bash 3.2, and are
  `shellcheck` clean.
- Canary content that must not exist word for word in the repository (a token, an agent hook, text
  addressed to a reviewer) is written at run time from parts in `expect.json`.
- Temporary repositories and scan output for tests live under the system temp directory; tests never
  touch a real repository or the user's home, apart from the tool cache.
- Keep files under about 500 lines. Plain language everywhere, including comments and messages. No em
  dashes. Australian English in docs. Do not call something built, done, secure or synced before it is.

---

## Testing

- `test/run.sh` installs the pinned tools, runs `test/*.test.mjs` with `node --test`, runs `whs canary`,
  runs `test/*.test.sh`, then `shellcheck`. An empty suite fails. The pre-push hook runs it from a
  `git archive` of the pushed commit; green is the bar for every push.
- CI (`.github/workflows/test.yml`) runs the suite on `ubuntu-latest` and `macos-latest`, and runs the
  reusable gate on this repository.
- The audit test fetches Cloudflare's skill at its pinned commit. The gate tests take about a minute
  because they run the real scanners.

---

## Docs

- `README.md` is for users and stays honest about status. The standard is for builders and for Ryan's
  decisions. Each directory's README says what goes there and which existing tool it wraps.
- Writing rules for anything a reader outside this session will see: plain language, no em dashes, no
  invented labels, no figurative phrasing, no deferred naming, and no overclaiming words.

---

## Where to look

| Question | Where |
|---|---|
| What the standard says and why | `docs/plans/2026-11-11-security-scanning-standard.md` |
| What is ready to work on | `br ready --json`, `bv --robot-triage` |
| Which tools and versions run | `checks/registry.json` |
| How to run a deep audit | `skills/workhorse-security-audit/SKILL.md` |
| What the last session left | `docs/handoffs/` |

---

## Beads quick reference

```bash
bv --robot-triage                 # start here: ranked picks, quick wins, blockers, health
bv --robot-next                   # the single top pick and its claim command
br ready --json                   # unblocked work
br show <id> --json               # full bead, with dependencies
br update <id> --claim            # claim
br create --title="..." --type=task --priority=2
br dep add <issue> <depends-on>   # <issue> waits on <depends-on>
br comments add <id> "evidence or decision, with its reason"
br sync --flush-only              # export the DB to .beads/issues.jsonl
```

- Priority is a number: 0 critical, 1 high, 2 medium, 3 low, 4 backlog.
- Swarm workers never run `br close`; see Honest credit.
- Session end: `git status`, stage your own paths, `br sync --flush-only`, commit, fetch your inbox, push
  to `main` by SHA.
