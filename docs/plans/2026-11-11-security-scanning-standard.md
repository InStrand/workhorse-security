# Security scanning standard

- **Date:** 2026-11-11
- **Owner:** Ryan Griffin
- **Status:** draft v5. This is InStrand's standard for scanning and hardening every repository it works in. v4 (9 November 2026) lived in `customer-template`. v5 moves the standard into the standalone pack `workhorse-security`, which also holds the code that carries it out. Changes from v4: the vision (1.1) and the six parts the pack is built from (1.2) are added; coverage modes for the deep audit are added (6.1.1); the data boundary is narrowed to checks that send content to a provider (9.1); distribution (9.5) and rollout (section 12) are rewritten for a standalone pack; decisions D9 to D13 are added (section 13); customer-specific content is removed and kept in InStrand's private engagement records. The two-model review of v2 and the review of that review are kept in InStrand's private records, not in this repository.
- **Scope:** platform posture, the checks on every change, the deep audit, vulnerability intelligence, and the loop that turns what they find into fixed, verified, closed work. The flywheel development process (Layer 0) is referenced, not redesigned.

## 1. What this is

One way of hardening and scanning, set once in the `workhorse-security` pack, consumed by `customer-template` and its clones, installed into repositories we do not own by the overlay tooling `fwt`, operated by agents through the flywheel, tracked in beads, and verified every week. A human decides only what only a human can decide: spend, releases, exceptions, and what a customer's own developers are asked to do.

Two tiers, because the code differs:

- **Workhorse-written code.** The aim is to approach the point where defects do not exist, by making the codebase more rigid over time (Layer 0's enforced rules) and by using better models as they arrive. Every layer applies in full.
- **Customer-written code** (citizen developers, customer engineers, anyone not on the flywheel). A Pareto approach: a packaged bundle that scans automatically on every change, audits on a schedule, and offers fixes as patch files, with nothing assumed about their machines or habits.

The principle behind the tool choices: offload to well-maintained tools and skills, and build only the connective tissue (adapters, an importer, rule files, a wrapper skill). Where this standard names something we write ourselves, section 10 says why nothing existing does the job.

### 1.1 Vision

The standard is a wrapper, kept as thin as it can be, around tooling that other people maintain: the jsm skills, Cloudflare's audit skill, GitHub's native features, the OpenSSF tools, gitleaks, zizmor, Semgrep and Anthropic's review action. It adds only what those tools leave uncovered for our stacks and our customers. It is accretive: every confirmed finding adds a canary and, where a deterministic rule can catch it, a rule, so a machine catches the same defect the next time.

The way of working borrows from Vercel's post on self-driving infrastructure (https://vercel.com/blog/self-driving-infrastructure): people state intent and principles, agents observe, investigate and propose, people approve, and what happens in production informs the code. Applied here: posture is declared; scanners and feeds observe; a triage agent investigates and proposes beads or pull requests; Ryan approves; the loop writes what it learned back into rules, canaries and baselines. Today every recommendation needs a person. More moves to autonomy as the canary measurements (9.2) justify it.

### 1.2 The six parts

The pack is built from six parts, and every capability in this standard is a combination of them. No layer has code of its own.

| Part | What it is | Where it lives |
|---|---|---|
| Repository config | The one file a repository writes about itself: `data_paths` (files that never go to a provider) and `exceptions` (findings a named person accepted: paths, optional checks and rules, a reason, an owner, an optional expiry). Unknown keys are refused, so a typo cannot switch something off | `security/config.json` in the repository, or in the private engagement repository for a repository we do not own. Read by `lib/config.mjs` |
| Surface | What a check reads, built once by the pack. Kinds today: `tree` (one commit's files copied out of git into a directory the pack owns) and `commits` (the commits a selector names: a change's base..head, everything reachable from one commit, or every ref). Further kinds come from adapters: platform settings, deployed state, the dependency inventory, advisory feeds | `lib/surface.mjs`, later `adapters/` |
| Check | A pinned tool invocation that reads one surface and writes SARIF. Declared as data: the tool and its exact version with SHA-256, its class (`deterministic` or `model`), `sends_to` (the providers that receive content; empty when nothing leaves the machine), the argument list per surface, the files it applies to, and which of the scanned repository's own ignore mechanisms are switched off for it. Adding a check is a registry entry plus canaries, with no code | `checks/registry.json`, with the rules we write under `checks/` |
| Fragment | Knowledge for model checks, written in the companion-file shape Cloudflare's audit skill already reads (When to use, Core discipline, attack classes, Universal moves, Validation rules) and selected when the target has matching files. Sources, which are other people's skills, are listed beside the fragments: pinned by git commit and fetched, or detected where they are installed | `fragments/`, `fragments/registry.json` |
| Canary | A known case with the rules that must report it and how many times, or a correct form the check must stay quiet on. It runs through the same code as a real scan | `canaries/<check>/<case>/` |
| Record | Findings in SARIF 2.1.0 with one identity (`partialFingerprints["whs/v1"]`) and one comparison of two sets of findings by that identity | `lib/findings.mjs`, later `record/` |

Seven behaviours follow from what a check or a config declares. None of them is a separate setting.

1. A `deterministic` check can stop a change and a `model` check cannot, because the gate selects checks by class.
2. A check with a non-empty `sends_to` only ever reads a tree with the data paths left out, and never commits. A surface is opened for one reader, and one function of the reader's `sends_to` decides what is left out. The audit's model is a reader of the same kind. No registry check sends content anywhere yet.
3. A check that reads a tree gets no path back to the repository.
4. A rule the pack writes cannot be added without a canary that it catches, because the canary suite fails.
5. A change is judged with the exceptions of its base revision, so it cannot excuse itself.
6. Scanners' own ignore files and inline ignore comments are switched off, or stripped from the copy that scanner reads, and git is read through a directory the pack owns that holds only the repository's objects. The repository config is the only way to accept a finding.
7. A check that errors or writes no SARIF fails the gate.

| Capability | Combination of parts |
|---|---|
| Pull request gate | Deterministic checks over the `commits` of the change (base..head, or everything reachable from the head on a first push), plus tree-reading checks over the head tree compared with the base tree |
| Deploy wait | The same gate on the merged commit |
| Weekly history pass | Commit-reading checks over the `commits` of every ref |
| Platform posture | A declared baseline compared with a platform surface |
| Live-state drift | The tree surface compared with the deployed-state surface |
| Deep audit | Deterministic checks over tree and history as leads, plus fragments, plus a model check that runs Cloudflare's process on a tree surface without the data paths |
| Coverage mode | The name of the set of sources that resolved |
| Intelligence | Advisories compared with the dependency surface |
| Heartbeat | A canary on a schedule: the expected report against the observed one |
| Closure | The last record compared with a new scan of the deployed revision |
| Accretion | A confirmed finding becomes a canary and, where a deterministic rule can catch it, a rule |
| Missing layer | The checks required for the tier compared with the checks that ran |

On 11 November the pull request gate, the history pass, the preparation of the deep audit and the coverage mode exist. The other rows are not built; section 12 gives the order.

## 2. Principles

1. **One tool per job, chosen once.** A repository missing a layer is a finding from the weekly posture check, not a judgement call per project.
2. **Trust follows content, not identity.** An agent-written change was shaped by whatever the agent read. It is untrusted input to every reader, human or model, whichever branch it arrived on.
3. **Deterministic checks gate; models advise.** A model's finding stops something until a named human releases it. A model's silence clears nothing.
4. **Proof, not presence.** A scanner counts only when there is evidence it saw what runs: the route a dependency takes to an advisory database is proven once, deployed state is read rather than inferred from git, and every layer is tested against known defects.
5. **One record, one loop.** Whatever found it, a finding has one identity, one owner, one state, and closes only when a later scan of the deployed revision no longer sees it.
6. **Production credentials are never reachable from a change under review**, from a scheduled audit, or from an agent's session.
7. **Posture is code.** Every platform's security configuration is declared, applied programmatically where the platform allows, and verified weekly. Drift is a finding.

## 3. The layers

Each layer is a named region of surface and trigger. All of them use the same six parts (1.2).

| Layer | Question | Runs | Standard |
|---|---|---|---|
| 0. Minimum standards | Is the code built to standard and verified before it leaves the agent's machine? | Every commit and push, in the flywheel | `coding-standards`, `codebase-design`; `ubs`, typecheck and lint in the pre-commit gate; tests as verification; the pre-push gate; `dcg`. Owned by the flywheel process |
| A. Platform posture | Is every platform the system runs on configured to the baseline the threat model requires? | Applied once, verified weekly | Declared baselines per platform, applied through each platform's API or Terraform, verified by OpenSSF Scorecard and Allstar for GitHub and by small adapters for the rest (section 4) |
| B. Every change | Did this change add a vulnerability, a secret or an unreviewed dependency? | Pull request, push to a trunk, and before a deploy where merging deploys | A deterministic gate (gitleaks, zizmor, Semgrep with our rules, Dependabot) plus an advisory AI reviewer (section 5) |
| C. Deep audit | What is wrong with the whole system as deployed? | Weekly quick, monthly deep for active production, quarterly floor, and on triggers | The `workhorse-security-audit` skill, which lives in the pack: a thin wrapper around the jsm and Cloudflare audit skills with our adapters (section 6) |
| D. Intelligence | Is something we depend on now known to be broken? | Continuous | Dependabot and the GitHub Advisory Database; the Zero Wire feed and vendor advisories read by machine; a triage agent decides action (section 7) |
| The loop | Does every finding reach a fix, a verified close, or a recorded exception? | Always | One record in SARIF, an importer into beads, a triage agent, the flywheel for fixes, closure by re-scan (section 8) |

Layer 0 is the floor. Layers A to D do not trust it: a hook can be skipped, a machine can drift, and a customer's developers are not on the flywheel at all.

## 4. Layer A: platform posture

Earlier drafts limited this layer to GitHub repository settings. That was an omission, not a decision: the plan grew out of "how do we scan code", and configuration of the platforms around the code is a different lane. It is also the cheapest lane, because most of it is a declared baseline applied by API and checked by API, with no model involved.

The baseline per platform is derived from the threat model for that stack (`security-threat-model`, once per system, refreshed when a boundary changes). The outcome is one file per platform in the pack (`posture/<platform>.yaml`) stating the required settings, one apply step, and one weekly check that reads the platform and files a bead per difference. A repository's overrides live in its repository config; no override key exists yet, because no posture file exists yet. The first control is production credentials held only in a branch-restricted `production` environment. It is proven with a sentinel: a pull request that edits a workflow to read a production secret must fail to read it.

| Platform | Baseline (examples, derived from the threat model) | Apply and verify with | Existing tool that already does it |
|---|---|---|---|
| GitHub (code) | Dependabot alerts and security updates on; production credentials only in a branch-restricted `production` environment, none at repository or organisation level; `GITHUB_TOKEN` read-only by default; Actions may not approve pull requests; allowed-actions policy; rulesets on `main` and trunks (pull request required, always-run required checks, no admin bypass, up-to-date branches, checks bound to the Actions app); two-factor enforcement; Actions pinned by SHA; Secret Protection where the plan allows | `gh api` or the Terraform GitHub provider; organisation security configurations where available | **OpenSSF Scorecard** (per-repository score on branch protection, pinned dependencies, token permissions, dangerous workflows, vulnerabilities, maintained, and more; Action and CLI; SARIF output) and **OpenSSF Allstar** (GitHub App that enforces organisation-wide policies continuously and files issues or fixes). These replace a hand-written GitHub posture check |
| Edge and DNS (Cloudflare) | Records proxied, not exposed origins; WAF managed rulesets; bot fight mode; rate limiting on authentication and public endpoints; Access in front of admin and internal surfaces; TLS settings | Cloudflare API or Terraform (`cf-terraforming` to import what exists) | Cloudflare's own WAF, Access and Security Center. We declare the baseline; Cloudflare enforces it |
| Database (Supabase) | Network restrictions on direct database access; SSL enforcement; point-in-time recovery; auth settings (MFA where the product needs it, email OTP settings); RLS on every public table; no `SECURITY DEFINER` without `search_path`; no table grants to anonymous roles; a read-only role for audits | Supabase Management API and SQL | Supabase's Security Advisor (the open-source `splinter` lints) is the check; our adapter runs the same lints by SQL and reads the project settings by API |
| Backend (Convex) | Deployment environment separation; deploy keys scoped per environment; public function surface known and reviewed | Convex dashboard API and `npx convex function-spec --prod` | Convex's own deployment controls; our adapter diffs the public function surface |
| Hosting (Vercel, Netlify) | Firewall rules and attack challenge mode; deployment protection on previews; environment variables scoped per environment; security headers; no production credential in a preview environment | Vercel API (firewall, deployment protection); Netlify API | Vercel Firewall and Security dashboard; Netlify equivalents. The trial of Vercel Security Review (D5) sits in Layer B, not here |
| VPS | Firewall, SSH keys only, unattended security upgrades, TLS termination, private network (Tailscale), no production credential on disk outside the secret store, deploy user with least privilege | Ansible or cloud-init from the template | The template's deploy-user installer already verifies the pinned Bun release and never runs as root; the baseline generalises that |
| Identity (Entra, Supabase Auth, Better Auth) | MFA; conditional access where the customer runs Entra; session lifetimes; no shared accounts | Customer's identity platform; our settings in code | The identity platform's own controls. For a customer this is their decision and often their tenancy |
| Secrets | One store per platform (GitHub environments, Supabase Vault, the hosting platform's environment variables); rotation runbook per secret type; no secret in a repository, a log or a bead | Platform APIs; gitleaks in Layer B | GitHub Secret Protection where bought; gitleaks and the rotation runbook otherwise |
| Infrastructure as code and containers | Terraform, Dockerfiles and workflow files scanned for misconfiguration | Trivy or Checkov in CI | Both are well maintained; pick one in wave 1 |

Why not only GitHub: many serious defects sit in deployed state and platform configuration (function bodies, grants, dashboard settings, credentials that automation can reach), where no diff shows them. Posture prevents those. Scanning finds the rest.

## 5. Layer B: every change

Two forms. **B1** for customer-written code: nothing is assumed about the developer's machine, so the checks live on GitHub and the ruleset makes them required. For a customer with citizen developers this is the gate between "try it" and "release it". **B2** for Workhorse code: Layer 0 has already run the static checks locally; B2 re-runs them in CI because CI does not trust the machine, and adds the AI reviewer as an independent second reader. Where agents push to a trunk without a pull request, B2 runs on push to the trunk and again on the pull request from the trunk into `main`.

### 5.1 What the tools are

| Tool | What it is | Who maintains it | Role here |
|---|---|---|---|
| Dependabot (alerts, security updates), secret scanning and push protection, CodeQL, rulesets | GitHub's own features | GitHub | Alerts and rulesets are the backbone (Layer A). Secret Protection where the plan allows. CodeQL not by default |
| gitleaks | Open-source secret scanner (Go) | gitleaks project | The pack pins 8.30.1 by SHA-256 for four platforms and runs it. The template's own `test.yml` step (the same version, scanning `base..HEAD` on every pull request) stays until the template adopts the pack's workflow. The pack runs the binary because `gitleaks/gitleaks-action` needs an organisation licence key. A weekly full-history pass is still to be scheduled |
| zizmor | Open-source static analyser for GitHub Actions workflows (pinning, permissions, `pull_request_target`, template injection) | zizmor project | New. The pack pins 1.32.0 by SHA-256 and runs it in the gate on every change. The weekly run is not scheduled yet |
| Semgrep CE | Open-source pattern engine; rules are YAML files we write | Semgrep | New. The pack pins 1.185.0 with a hash-locked requirements file (75 packages). The one engine for our own rules: stack policy checks (for example `security definer` without `search_path`, grants to anonymous roles, a public route with no classified guard, a Convex public mutation with no identity check) and the agent-configuration check (a hook command, MCP server command or permission allow entry added to `.claude/**`, `.mcp.json`, `.cursor/**`). We write rules, not a scanner |
| OSV-Scanner | Google's open-source dependency scanner against OSV.dev | Google | Not on pull requests: Dependabot alerts already cover lockfiles within hours. Used in Layer C for SBOM output and to prove advisory routes |
| `anthropics/claude-code-security-review` | Anthropic's GitHub Action: Claude reads the diff with context, filters low-value classes, comments on lines | Anthropic | The advisory AI reviewer (5.3) |
| OpenSSF Scorecard | Open-source repository posture scorer | OpenSSF | Layer A, weekly; its SARIF feeds the record |
| Vercel Security Review | Vercel's hosted review on push, Pro and Enterprise | Vercel | Trial beside the standard where a project deploys on Vercel (D5) |

Earlier drafts also named Trufflehog, a dependency-review step, path-filtered checks and hand-written grep scripts. Dropped: Trufflehog duplicates gitleaks; dependency review needs Code Security on private repositories and duplicates Dependabot; path-filtered required checks never report and block the merge; grep scripts are what Semgrep rules are for.

### 5.2 The deterministic gate

One reusable workflow, `.github/workflows/security.yml` (`workflow_call`), with one always-run job, `security-gate`, that runs `whs gate`. The job decides inside which checks apply: a check with no matching files reports `not_applicable`. That is how the rule about always-run required check names holds. `permissions: contents: read`, `persist-credentials: false`, no secrets, no `pull_request_target`. This job is the required check.

The gate stops only what the change adds. Checks that read commits (gitleaks) read the commits of the change. Checks that read a tree (zizmor, Semgrep) run on the head tree and on the base tree, and the two sets of findings are compared by fingerprint (section 8). A finding that was already there is reported as unchanged. It goes to the record and does not stop the author. Exceptions come from the repository config of the base revision. A scanner that errors or writes no SARIF fails the gate.

Starter rules in Semgrep: a `SECURITY DEFINER` function or procedure without `set search_path`; a privilege granted to the anonymous role; a command, server or permission allow entry in agent configuration files. The dependency surface check (6.3) and the team's own tests are not in the gate yet.

### 5.3 The AI reviewer

`anthropics/claude-code-security-review` in its own job with one secret, a spend-limited API key (D3). It is not a required check. It posts a status with three values: reviewed with findings, reviewed clean, not reviewed (timeout, budget, error, size). High and critical findings enter the record (section 8) and, where merging deploys, stop the deploy until a named human releases it. A clean or not-reviewed result decides nothing. Its instructions file is composed from stack fragments and loaded from the base revision, not from the pull request's checkout. `run-every-commit: true`, because the action otherwise caches per pull request. Its timeout defaults to 20 minutes. The action is not hardened against prompt injection, which is one reason it decides nothing alone. It is measured against the canary corpus (9.2) before it is believed.

### 5.4 Human review where it counts

CODEOWNERS on guard files, workflows, agent configuration, the repository config (it holds the exceptions), the reviewer's instructions file, and on migrations or changes that grant, define `SECURITY DEFINER` or alter authentication. Everything else keeps the team's pace. In a customer's repository this changes their process and is their decision.

### 5.5 Where merging deploys

The deploy workflow gains a first job that runs the deterministic gate on the exact merged commit and a preflight that reads GitHub's check conclusions for that SHA before the `production` environment is granted. Deterministic failure stops the deploy; an AI high or critical finding stops it until a named human re-runs with a recorded reason; a not-reviewed result does not stop it. The same job is the wait condition for Vercel deployment checks.

## 6. Layer C: the deep audit

### 6.1 One skill, two brains, one run

`workhorse-security-audit` is a wrapper. On 11 November it lives in the pack as `skills/workhorse-security-audit/`, because its value is the code it calls and the two must version together. D14 keeps that property and changes the place: the skill that people install is a short trigger published in InStrand's skills repository, and the steps of a run stay in the pack, which writes them into each run directory. It uses two existing skills and runs them as one audit:

- **jsm `security-audit-for-saas`** is the domain brain: fifteen domains, the security kernel's axioms and operators, the dispatched subagents (RLS auditor, red-team agent, recovery-path walker, admin-escalation mapper, webhook divergence detective), and the scripts (`rls-coverage.sql`, `find-fail-open.sh`, `api-auth-mapper.sh`, `leak-scan.sh`, the webhook signature test). This is the most robust security skill available to us and the one with the deepest knowledge of our stacks.
- **Cloudflare `security-audit-skill`** is the process shell: reconnaissance into a coverage ledger, coverage-led hunting with critics, a fresh verifier that tries to disprove every candidate, a strict findings schema with validators, and additive runs that re-verify prior findings against current source.

The design is to run the Cloudflare workflow once, with the jsm domain references supplied to its hunters and the jsm scripts that only search source run in preflight as deterministic inputs, so that the hunters carry jsm's knowledge and the output carries Cloudflare's verification and record. Read from Cloudflare's source on 11 November: its coverage ledger validator accepts any block reference string in `selected_companion_blocks` (it checks only that the list holds strings and that a block is not both selected and excluded), so companion files outside the skill directory are accepted without changing the skill. Its hunter prompt contract requires each selected companion's Core discipline, the chosen class, its Universal moves and its Validation rules, copied verbatim, so the pack's fragments are written in that shape. The jsm references are not in that shape. In `full` mode they are read where they are installed, as reference sections for a ledger unit, and Cloudflare's own core method and validation rules apply to what the hunter finds. Not verified: a complete run with jsm references on a real target. The first baseline audit is that test. The alternative, if the Cloudflare skill does not take the references cleanly, is to run jsm's own end-to-end workflow and write its findings into the record through the importer, keeping Cloudflare's verifier step. Either way: one run, one record, no second full pass.

What we add, and why nothing existing does it:

- **The audit preparation** (`whs audit prepare`): the copy of one commit without the data paths (6.6), the deterministic checks' findings as leads, and the run file that states the coverage mode (6.1.1). Neither skill builds its own input or records which knowledge it had.
- **Preflight adapters:** the estate inventory (every repository, site, published skill and hand-deployed service a customer has, with a tier), the dependency surface inventory (6.3), and the live-state adapters (6.4). Neither skill reads deployed state or declares dependencies outside manifests.
- **The importer** into the record and beads (section 8). Neither skill tracks findings across runs into a work tracker.
- **The instructions fragments** per stack, shared with Layer B.
- **The canary corpus** (9.2).

`claude-security` (Anthropic's plugin) is the optional third tool, used for its "suggest patches" job: findings turned into patch files, each checked by a panel, for the customer tier where no agent will fix the code through the flywheel.

#### 6.1.1 Coverage modes

jsm skills are a paid subscription under a proprietary licence. They cannot be copied into this repository, and a customer or a later operator may not have them. The audit therefore runs with the sources that are present and states which they were. The mode is not a switch: `whs` resolves the sources listed in `fragments/registry.json` and names the result.

| Mode | When | What the audit has |
|---|---|---|
| `full` | `security-audit-for-saas` is installed | jsm and Cloudflare, plus the pack's fragments and deterministic checks |
| `open` | Otherwise | Cloudflare, plus the OpenAI `security-threat-model` and `security-best-practices` skills where they are installed, plus the pack's fragments and deterministic checks |

Cloudflare's skill is required in both modes. It is pinned by commit in the registry and fetched. The run file (`whs-run.json`) states the mode, every source with its version, and every source that was not available with what it provides.

| What `open` loses | What partly substitutes |
|---|---|
| The fifteen-domain sweep | Cloudflare's attack classes and companion files for the general classes; the OpenAI skills' threat model and framework checklists where installed |
| The axioms and operators | Nothing in the pack |
| The RLS auditor | The `postgres-supabase` fragment; the Semgrep rules for definers and anonymous grants; when built, the live-state adapters for grants, RLS flags and anonymous-executable definers |
| The fail-open probe | Nothing in the pack |
| The API auth mapper | Cloudflare's access control class |
| The recovery-path walker | Nothing in the pack |
| The admin-escalation mapper | Cloudflare's access control class |
| The billing checks | Nothing in the pack |

Reduced coverage is accepted and recorded, never hidden.

### 6.2 Profiles, cadence and triggers

| When | Profile | Who |
|---|---|---|
| Baseline, once per repository | `deep` | First audit bead in the first wave |
| Weekly | `quick`; skipped when nothing changed and the live-state and advisory monitors are healthy | Scheduled run, read-only, results to the inbox |
| Monthly | `deep` for active production systems; quarterly floor for quiet repositories | Audit bead in an operator session |
| New attack-surface entry from the live-state diff; new authentication, tenancy, payment, integration or LLM surface | `scoped` | The wave that builds it |
| Before a release gate | `scoped` to the diff since the last gate, in the repository that ships the release | Operator session |
| A Layer D item the triage agent marks actionable | The item's own check, then `scoped` if it applies | Same day |

Figures are proposals for D8.

### 6.3 Dependency surface inventory

Scanners read manifests and lockfiles and nothing else. A generator in the pack lists every dependency declared anywhere else (inline registry or URL imports, CDN script tags, `curl | sh`, vendored files, container bases, downloaded tools), resolves each to an exact version, and records the route by which a scanner sees it: native lockfile, native manifest, submitted graph, SBOM, or none. Each route is proven once in a private probe repository holding a dependency with a known advisory; a route that stops alerting downgrades every dependency on it to uncovered. A dependency with route `none` and no dated exception fails the pull request gate. GitHub's Advisory Database covers rubygems, npm, pip, maven, nuget, composer, go, rust, erlang, actions, pub, swift and "other"; it has no JSR or Deno ecosystem, so such specifiers alert only through a proven mapped route. Dependabot reads Deno dependencies from `deno.json` and `deno.jsonc` only, and OSV-Scanner has no Deno support. An `integrity` attribute cannot go on an ES module import; an import map can carry integrity in current Chromium.

### 6.4 Live-state adapters

Git is not always what runs. Per backend, a read-only adapter emits the same surface schema: Supabase (nightly catalogue snapshot through a catalogue-only role: lints, anonymous-executable definers, grants, RLS, body hashes, diffed; weekly deployed-function listing and source comparison from an operator session), Convex (`function-spec --prod` diffed for new public functions), Vercel or VPS (public routes, environment separation, deploy identity). Adapter credentials are their own, least-privilege, never the deploy token, never an account-wide token in an unattended job. Supabase's function download leaves out import maps and `deno.json`, so the comparison is of sources only.

### 6.5 After the audit: what happens to a finding

This is the loop, and it is the same for Layer B and Layer D (sections 7 and 8).

1. **Record.** The audit writes `findings.json` (Cloudflare schema) and the importer converts it to SARIF, the one format every tool here speaks, with a stable fingerprint per finding.
2. **Triage.** A triage agent (an ntm pane, or the conductor) reads the new and changed results: deduplicates against the record, confirms reachability and severity, and marks each one `fix`, `accept` (with reason and expiry) or `validate` (reproduce in a sandbox or the development environment). Nothing in `needs_validation` becomes a confirmed fix item without that step.
3. **Beads.** One bead per `fix` item, severity mapped to priority, labelled `security`, with the fingerprint in the description; one bead per `validate` item. Unattended runs never commit: they write to Agent Mail or an inbox and the conductor imports.
4. **Fix.** The bead runs through the flywheel like any other: an agent writes the fix and a test, adds the reproduction to the canary corpus (9.2), and the pull request passes Layer B. For the customer tier, the fix is offered as a patch file from `claude-security`, or as a bead in their tracker, and their process applies.
5. **Verify and close.** The bead closes when a later scan of the deployed revision no longer reports the fingerprint (SARIF `baselineState: absent`) and the fixing commit is deployed. Nobody closes a security bead by hand.
6. **Report.** `REPORT.md` to `docs/reviews/<date>-security-audit.md`. A daily list of overdue items by severity, and a monthly summary: found, fixed, accepted, overdue, per repository.

Each bead says who must act, so that the fix can start: an agent through a pull request, the repository's owner through a platform setting, or a decision by the owner first. On 11 November the pack finds and recommends. Fixing runs through the flywheel as ordinary beads, and nothing in the pack automates it yet.

Two more steps apply to every confirmed finding. A variant hunt searches the estate for the same root cause, and what it finds joins the same bead. For a confirmed critical or high finding, a second bead asks whether it was used: which logs would show it and how long they are kept. Sign-in and session tables should carry the IP address and user agent so that the question can be answered.

Open critical and high detail stays in InStrand's engagement record until fixed, with only the fingerprint in the target repository. Cloudflare's findings schema refuses extra fields on every finding, so the note of which jsm reference led to a finding goes inside `evidence`.

On 11 November the importer and the SARIF conversion of `findings.json` are not built. The first audits keep `findings.json` and the coverage ledger as the record, and beads are created from them in the operator session.

### 6.6 Where it runs

Operator runs in an ntm pane under the conductor, on Ryan's machine or the InStrand server, with a read-only fine-grained GitHub token, no production credential, inside the sandbox, because the code it reads is partly agent-written and can carry text addressed to it. The weekly `quick` run is scheduled on the InStrand server (a cron'd `claude -p`, or a Claude cloud routine where the customer's data rules allow), bounded and read-only. None of this depends on the hosting platform.

The audit reads a copy of one commit with the data paths left out, in a run directory outside every repository. The directory is Cloudflare's default, `~/security-audit-skill/<repo>/run-<N>`, so its prior-run logic works unchanged. Reading a copy also keeps the target's own agent instruction files from loading as instructions.

## 7. Layer D: intelligence, and its loop

Sources, all read by machine:

- **Dependabot alerts** on every repository (the Advisory Database carries GHSA records with or without a CVE), with Dependabot or Renovate opening the update pull request.
- **OSV** against the SBOM from 6.3, for routes GitHub does not cover.
- **The Zero Wire RSS feed** (`https://radar.cloudflare.com/security/zero-wire/rss`), polled daily and parsed deterministically; items carry status, CVE ids and technology tags as categories. The feed holds recent items only, so every poll is stored. The briefing's own AI prompt is never executed.
- **Vendor advisories** for the stacks we run (Supabase, Deno, Vercel, Netlify, Convex, Better Auth, Hono, TanStack, the MCP SDK, the Actions we use) and CISA's Known Exploited Vulnerabilities list for priority.

The loop: every item is matched against the dependency surface inventory of every repository. A match goes to the triage agent (6.5 step 2), which decides whether it is actionable: is the affected version actually deployed, is the vulnerable path reachable, is there a fixed version. Actionable items become beads; where Dependabot or Renovate has already opened the pull request, the bead is to review and merge it through Layer B. Non-actionable matches are logged with the reason. Humans see the actionable list, in the engagement's weekly check-in. The October 2026 security update in `customer-template` is the precedent: advisories to pinned upgrades, with the research and test result of each recorded.

## 8. The record and the lifecycle

**Format.** SARIF 2.1.0 is the record. Every deterministic tool here emits it (gitleaks, zizmor, Semgrep, Scorecard, Trivy, OSV-Scanner), GitHub's code scanning ingests it where Code Security is bought, and it was designed for the lifecycle: `partialFingerprints` for identity across runs and `baselineState` (`new`, `unchanged`, `updated`, `absent`) for closure. The deep audit's `findings.json` stays as its native evidence and is converted by the importer. Formats compared for D4: SARIF, the Cloudflare schema, the OSV schema (advisories, not findings), CycloneDX and SPDX (bills of materials, not findings), the jsm finding template and `claude-security`'s report (Markdown, no identity or state). Only SARIF is tool-neutral with identity and state built in. Exceptions appear in the record as SARIF `suppressions` with the reason and the owner. Microsoft's `sarif-multitool` (`match-results-forward`) is to be evaluated in wave 3 before any more record code is written.

**Identity.** Read from the tools' output on 11 November: Semgrep CE's SARIF carries `matchBasedId/v1: "requires login"`, zizmor's carries no fingerprint, and gitleaks' carries the commit. So the pack computes its own, `partialFingerprints["whs/v1"]`. For a tree it is the hash of check, rule, path and the flagged lines with whitespace normalised. The line number is left out, so an unrelated edit above a finding does not change its identity. For commits it is the hash of check, rule, path, commit and line. For the deep audit's findings: class, symbol or route, and boundary. For dependencies: GHSA or CVE.

**States.** `new`, `triaged` (fix, accept or validate), `in_progress`, `verified_closed`, `accepted_risk` (owner, reason, expiry). Closure only by re-scan of the deployed revision.

**Fix-time targets** (proposals for D8): critical 48 hours, high 7 days, medium 30 days, low by the next quarterly audit. Overdue items are listed daily.

**Where the record lives.** For repositories we own, under `security/record/` in the repository as committed SARIF with exploit detail redacted; for a customer's repository, in the private engagement repository, with fingerprints only in the customer's tracker.

## 9. Cross-cutting

### 9.1 Data boundary

Customers accept InStrand's terms, which cover the use of AI on their code, and a customer running their own skills has already made that choice. What remains is narrower and is configuration.

`data_paths` in the repository config lists the files that never go to a provider: seed and baseline SQL, fixtures shaped like real records, exported documents. They are removed from the surface of any check that sends content to a provider. Deterministic checks run locally or in the repository's own CI and send nothing, so they scan everything, including seed files: a secret or a grant in a data file is still a finding. A finding under a data path reaches a model with its rule, path and line only; the quoted text is removed. The list of providers is the `sends_to` field of each check.

This narrows v4, in which scanners skipped the data paths too.

One marker check is to stop a run and ask a human when a repository carries material the organisation's rules flag as sensitive (classified, defence or security-related client material). The marker check is not built.

### 9.2 Acceptance canaries

A canary is a directory `canaries/<check>/<case>/` with an `expect.json` that names the rules that must report the case and how many times. A case that expects nothing holds the correct form, and the check must stay quiet on it. The suite fails when a check has no catching case or no quiet case and, for a check whose rules the pack writes, when any loaded rule has no case that it catches. Fixtures that must not exist verbatim in the repository (a token, an agent hook, text addressed to a reviewer) are written at run time from parts held in `expect.json`. On 11 November there are ten cases across three checks.

The corpus to build: known-bad changes, one per canary with the detector expected to catch it: an authentication function with a NULL hole, a read-shaped path that writes, a scheduled function with no guard, a new anonymous-executable definer, an unpinned CDN import, a provider-format token, a `pull_request_target` checkout, a paired injection canary (a real defect plus text addressed to the reviewer), a public mutation with no identity check, a server function trusting a client-supplied user id. Deterministic detectors must catch all of theirs. The AI reviewer is measured statistically with a recorded detection rate and noise budget. Run on every scanner, rule or model change, and monthly. Every confirmed finding adds a canary and, where a deterministic rule can catch it, a Semgrep rule, so the standard learns from real findings as well as from general lists. The addition enters this repository in general terms and only after the finding is closed (9.6).

### 9.3 Posture check and heartbeat

Weekly: Scorecard and Allstar for GitHub; the posture adapters for the other platforms; a bead per drift from the declared baseline. A heartbeat per scheduled job, so silent failure of the automation is itself a finding.

### 9.4 Cost

Measured in wave 1, not estimated: AI reviewer tokens over two weeks of real pull requests; deep-audit sessions per month by repository tier; runner minutes; GitHub seats and Secret Protection committers per organisation from current billing. Purchases on a customer's organisation are the customer's decision, put to them with the figures.

The deterministic checks need no budget: they run in seconds. A deep audit does, because it asks one question per entry surface, boundary and attack class, and each question is one agent run. The rule (D17): reconnaissance is a small fixed cost and writes the coverage ledger; full coverage then costs the number of units, plus one critic per wave and a final one, plus one or two verifiers per candidate; a ceiling per run decides how much of that this run does, and the rest is recorded as deferred and starts the next run. The operator names the model before the run. Each run records the agent runs it used, so the next estimate rests on measured figures. In the first seven quick-profile runs, 93 of 134 budgeted agent runs were used.

### 9.5 Distribution

The standard has three kinds of content, with different owners.

- Per-repository consumption: a caller workflow, the repository config, posture overrides, the SARIF record and beads. It lives in each repository, or in the private engagement repository for a customer's repository we do not own.
- The pack, `workhorse-security`: generic, versioned and consumed by every repository. It holds the reusable workflows, the runner, the check registry and rules, the fragments, the posture baselines, the adapters, the canaries and the audit skill.
- Estate operations: the weekly posture check across all organisations, the intelligence reader and triage, the heartbeat and version drift. These are scheduled jobs that read every organisation with an estate-read token. They run from the pack repository's own Actions or the InStrand server, never from a customer's repository.

Private reusable workflows cannot be called across GitHub organisations, and a consumer's CI cannot check out a private pack without a credential, so the pack is either public or vendored into each consumer at a pinned hash (D9). Both statements come from the planning of 10 November and were not re-checked on 11 November (section 14). GitHub gives a called workflow no documented way to learn its own commit, so a caller passes the pack commit it pins as an input, and the gate refuses to run from another repository without it.

`customer-template` carries a caller workflow and a repository config. `init-customer` copies them into a new clone. `fwt` installs the same into a repository we do not own, with the config kept in the engagement repository. The `flywheel-core` add-on registry checks every repository and reports drift. Later, pack versions are promoted in rings (template, one InStrand production repository, one customer pilot, the rest) with a pinned previous version for rollback.

### 9.6 What is public and what is private

The pack is public (D9). Its strength does not depend on secrecy. The runner, the registry, the general rules, the fragments and the deterministic canaries can be read by anyone, and a consumer's CI must be able to fetch them. A person who can push to a repository can already read the workflow that scans it.

These stay private:

- The record of any repository: findings, exceptions and triage decisions. It lives in the repository itself or, for a customer, in the private engagement repository.
- A customer's repository config.
- The estate inventory, and the credentials of the estate jobs.
- A rule, canary or fragment line that comes from a finding, until the finding is closed. A new rule that appears in a public repository soon after an audit says what the audit found. Until closure the proposal stays on the finding's bead in the private tracker, and the rule can run from a private overlay (a second pack root with the same layout, not built). After closure it moves here in general terms.
- A held-out set of canaries for model checks. Public canaries can reach training data, and a detection rate measured on them would be too high.

Candidates for a hosted back end later, not now: the record and the loop across customers (importer, triage, closure, fix-time reporting), and the estate operations. The pack would stay the open client that runs in each repository.

## 10. Tools and skills: the catalogue and the overlap

Everything earlier drafts named, what each uniquely adds, and the decision. "Unique" means no other item in the kept set does it.

| Item | Layer | Maintained by | Unique contribution | Decision |
|---|---|---|---|---|
| jsm `security-audit-for-saas` | C | Jeffrey (jsm) | Domain knowledge for SaaS and Supabase stacks: domains, axioms, subagents, scripts | **Keep, the domain brain**; read where installed, never copied (6.1.1) |
| Cloudflare `security-audit-skill` | C | Cloudflare | Verification process, strict record, coverage ledger, additive runs | **Keep, the process shell**; pinned by commit in `fragments/registry.json` |
| `claude-security` plugin | C, customer tier | Anthropic | Verified patch files | **Keep, optional**, for the customer tier |
| `security-threat-model` (OpenAI) | A, preflight | OpenAI | A design-level threat model before code exists | **Keep**, once per system; Cloudflare's reconnaissance covers the rest |
| `security-best-practices` (OpenAI) | B fragments | OpenAI | Framework checklists for Next, React, Express, Django, FastAPI, Go | **Keep as source material** for the instructions fragments; not run as a skill |
| `codebase-audit` (jsm) | C | Jeffrey | None beyond the two audit skills | **Retire** for security |
| `codebase-benchmark` | Scorecard | InStrand | A trend over time | **Keep**; it reads the record, it does not re-audit |
| `multi-pass-bug-hunting`, `ubs`, `dcg`, `slb` | 0 | Jeffrey | The flywheel's own gates and fix loop | **Layer 0**, unchanged |
| `testing-fuzzing` (jsm) | C follow-up | Jeffrey | Fuzz harnesses for parsers and protocol handlers | **Keep**, on what the baseline audit names |
| `audit-website` (squirrelscan) | External check | squirrelscan | Black-box checks of live URLs | **Keep**, monthly against the estate inventory |
| `anthropics/claude-code-security-review` | B | Anthropic | Diff-time AI review in CI | **Keep, advisory** |
| `security-guidance` plugin, `/security-review` | 0, ad hoc | Anthropic | Local guardrail; one-off branch check | **Not part of the standard** |
| `auto-codex-review.yml` | B2 | InStrand | General code review by Codex | **Keep**; not security-specific |
| gitleaks | B | gitleaks | Secret detection | **Keep**; pinned and run by the pack (8.30.1) |
| zizmor | B | zizmor | Actions workflow analysis | **Adopt**; pinned and run by the pack (1.32.0) |
| Semgrep CE | B | Semgrep | Engine for our own rules | **Adopt**; pinned and run by the pack (1.185.0); replaces grep scripts |
| OSV-Scanner | C | Google | SBOM and route proof | **Keep in C only** |
| Trufflehog | B | Truffle Security | Verified-secret mode | **Drop**; duplicates gitleaks |
| OpenSSF Scorecard, Allstar | A | OpenSSF | GitHub posture scoring and org-wide enforcement | **Adopt**; replaces a hand-written posture check |
| Trivy or Checkov | A | Aqua, Prisma | IaC and container misconfiguration | **Adopt one** in wave 1 |
| Dependabot, Renovate | A, D | GitHub, Mend | Alerts; version updates | **Keep both**: Dependabot for alerts, Renovate for versions (D2) |
| GitHub Secret Protection, Code Security | A | GitHub | Push protection; CodeQL | Secret Protection where the plan allows; Code Security not by default |
| Vercel Security Review | B | Vercel | Hosted review with finding tracking | **Trial** where a project is on Vercel (D5) |
| Zero Wire, Advisory Database, CISA KEV, vendor feeds | D | Cloudflare, GitHub, CISA, vendors | Briefings; exposure; priority | **Adopt**, read by machine |
| `dueling-idea-wizards`, `brennerbot-with-ntm` | Method | Jeffrey | Reviewing this standard | Not scanners. Run at frontier models and high effort, with claim verification as a phase |

Considered, not used:

- reviewdog. It filters findings to the lines a change touched, which misses a finding that a change causes elsewhere in the file. The pack compares the base tree with the head tree instead.
- Microsoft's `sarif-multitool`. Not used yet; it is to be evaluated in wave 3 (section 8).

**What we write ourselves,** and why: the runner (`whs`, about 1,300 lines of dependency-free Node: the same checks must run in the gate, the deploy wait, the schedule, the audit preflight and against canaries, and no existing tool gates on new findings across all three scanners with exceptions read from the base revision), the wrapper skill, kept in the pack (nobody runs two audit skills as one with our adapters), the dependency surface generator (no scanner declares dependencies outside manifests), the live-state adapters (no tool reads deployed Supabase or Convex state into an audit), the importer (no tool turns SARIF into beads), Semgrep rules (our stacks' guard patterns), the posture files and non-GitHub posture adapters (no cross-platform posture tool covers Supabase and Convex), the instructions fragments, and the canary corpus. Each is small. Nothing else is built where something maintained exists.

## 11. First application: the first customer

The standard lands at the first customer through the overlay, and arrives in that customer's new monorepo with `customer-template` when that is created. Everything that changes the customer's repositories, process or spend is the customer's decision and goes to them with the evidence. Order: Layer A for GitHub and the database, then the repository config, then `security.yml` with the customer's fragments and the deploy wait where merging deploys, then the baseline deep audit through the overlay with findings as beads in the engagement tracker, then the scheduled runs and release-gate audits in the repository that ships each release, then the hosted review trial when a project deploys on that host. Customer-specific findings, including items the baseline audit will pick up, stay in the private engagement repository.

## 12. Rollout

| Wave | Content | Where | State on 11 Nov |
|---|---|---|---|
| 0, bootstrap (11 Nov) | The repository; `whs` (install, canary, gate, scan, fragments, audit prepare); three checks pinned; three starter rules; ten canaries; three fragments; the audit skill in its first form; the reusable `security.yml` | `workhorse-security` | Written. CI green on `ubuntu-latest` and `macos-latest`, and the reusable gate green on the pack itself (`docs/handoffs/2026-11-11.md`). `whs audit prepare` has run on one real target; the audit itself has not |
| 1 | The first baseline deep audit, which is the design validation of 6.1; Layer A posture files and GitHub posture through Scorecard and Allstar; the advisory reviewer with its three-state status; the deploy wait; adoption in `customer-template` and through the overlay; cost measurement starts; D9 decided and the cross-repository call proven in a probe repository | The pack; `customer-template`; the first customer through the overlay | Not started. The advisory reviewer, the posture files and the deploy wait are not built |
| 2 | Adapters (dependency surface, Supabase catalogue, Convex function spec, Vercel and VPS); `findings.json` to SARIF; more fragments and rules from the baseline audits | The pack; `workhorse-platform`; the first customer | Not started |
| 3 | The record and the importer into beads; triage agent; heartbeat; probe repositories; closure by re-scan | All | Not started |
| 4 | Backfill across InStrand's repositories; registry drift checks | `workhorse-platform` and the customer repositories InStrand owns | Not started |
| 5 | Advisory reader with triage; scheduled weekly quick audit; hosted review trial; ringed rollout | All | Not started |

## 13. Decisions for Ryan

| # | Decision | Status |
|---|---|---|
| D1 | Upgrade `InStrand` and one customer organisation on the Free plan to GitHub Team (branch-restricted environments and Secret Protection need it) | Decided 9 Nov: upgrade, later. Until then those organisations cannot fence production credentials in environments |
| D2 | Renovate for versions, Dependabot for alerts | Open |
| D3 | The CI-run AI reviewer needs an Anthropic API key as a repository secret, because it runs in GitHub Actions and calls the API; operator and pane runs use the Claude subscriptions instead. The decision is whose key: one per customer organisation (cost lands with the engagement, revocation scope is one customer) or one InStrand key | Recommend one per customer organisation, spend-limited |
| D4 | SARIF as the record, with the Cloudflare schema as the deep audit's native evidence | Recommended, after comparing SARIF, the Cloudflare schema, OSV, CycloneDX, SPDX and the two Markdown templates (section 8) |
| D5 | Trial Vercel Security Review where a project deploys on Vercel; if the standard matches it, run our own. Layers C and D never depend on Vercel: C runs in operator sessions and on the InStrand server, D in GitHub Actions on a schedule | Decided 9 Nov: trial |
| D6 | Zero Wire and all Layer D sources read by machine; a triage agent decides what is actionable; humans see the actionable list | Decided 9 Nov, with the triage agent |
| D7 | Earlier drafts proposed a consent step per customer. Replaced by configuration: the data paths and the provider list in 9.1. No decision needed | Closed |
| D8 | Cadence (weekly quick, monthly deep for active production, quarterly floor) and fix-time targets (48 hours, 7 days, 30 days, next quarter), set once the wave 1 cost figures are in | Proposals in 6.2 and section 8; decide after wave 1 |
| D9 | `workhorse-security` public or private | Decided by Ryan, 11 Nov: public. A consumer's CI can then check the pack out with no credential and the gate can be called from a customer organisation. Public from its first published commit on 12 Nov. What stays private is in 9.6 |
| D10 | The pack's own code is dependency-free Node (ESM), not bash plus jq. The findings comparison and SARIF handling need real data structures, Node is already required by Cloudflare's validators, and nothing is installed | Made 11 Nov by the building agent. Confirmed the same day under Ryan's delegation |
| D11 | The gate stops only what a change adds, reads exceptions from the base revision, and switches off scanners' own ignore mechanisms (5.2) | Made 11 Nov by the building agent. Confirmed the same day under Ryan's delegation |
| D12 | Data paths apply only to checks that send content to a provider (9.1) | Made 11 Nov by the building agent. Confirmed the same day under Ryan's delegation |
| D13 | Directory names: `checks/` instead of `rules/semgrep/`, `record/` instead of `importer/`, reusable workflows in `.github/workflows/` with caller templates in `workflows/` | Made 11 Nov by the building agent. Confirmed the same day under Ryan's delegation |
| D14 | Where the audit skill lives. The skill that people install is a short trigger in InStrand's skills repository. The steps of a run stay in the pack, and `whs audit prepare` writes them into the run directory, so the skill and the code cannot differ in version | Direction from Ryan, 11 Nov. The split is the building agent's proposal. Not built |
| D15 | Nothing that comes from a finding enters the public pack until the finding is closed; a private overlay carries it until then (9.6) | Proposed 11 Nov as a consequence of D9. The rule is in force for agents now; the overlay is not built |
| D16 | The GitHub organisation is renamed `workhorse-tech`; the skills repository becomes `workhorse-tech/skills` | Decided by Ryan, 11 Nov. Not done: only an organisation owner can rename it. Until then this repository's address is `InStrand/workhorse-security`, and the caller workflow names that address |
| D17 | A deep audit runs under a ceiling of agent runs and on a model the operator names before it starts. Reconnaissance comes first; the ledger then gives the number of units; what the ceiling leaves out is deferred to the next run (9.4) | Made 11 Nov by the building agent after the owner asked for a mechanical rule and a cheaper model. Applied by hand in the first audits; not built into `whs` |

## 14. Verification record

- Repository and organisation settings, and the Advisory Database ecosystem list, read from the GitHub API on 9 November 2026. The template's `test.yml` gitleaks step read from source.
- Tool facts from vendor pages and source on 9 November 2026: the Cloudflare skill's `SKILL.md` and `report-schema.json`; the Anthropic action's `action.yml`; GitHub's environments, supported-ecosystems and Advanced Security pages; OSV-Scanner's supported lockfiles; Supabase's backup and restore guide; the Zero Wire RSS feed.

Verified on 11 November 2026:

- gitleaks 8.30.1 release checksums read from the release's checksum file; the linux x64 value equals the one pinned in `customer-template`.
- zizmor 1.32.0 (released 2 November 2026): release archives hashed after download; `gh attestation verify` against `zizmorcore/zizmor` exited 0 for the two archives checked.
- Semgrep 1.185.0 from PyPI (needs Python 3.10 or later), hash-locked with `uv pip compile --generate-hashes --universal`: 75 packages.
- Semgrep CE's SARIF fingerprint is "requires login"; zizmor's SARIF has no fingerprints.
- With no `.semgrepignore`, Semgrep skipped `tests/` and `node_modules/`; a `.semgrepignore` in the scanned directory hid the paths it named. The pack replaces every `.semgrepignore` in its copy and passes `--disable-nosem`.
- A `# zizmor: ignore[rule]` comment removed the finding from zizmor 1.32.0's output, and no flag was found to disable it; the pack strips the comment from its copy. `--no-config` and `--offline` exist.
- gitleaks has `--ignore-gitleaks-allow` and `--gitleaks-ignore-path`.
- Cloudflare `security-audit-skill` at commit `c1c8a8c` (14 September 2026, MIT): the ledger validator's treatment of companion blocks, the hunter prompt contract, the default output directory, the three run profiles and the budget as a maximum number of agent invocations, read from source.
- jsm 0.3.47 lists `security-audit-for-saas` as installed on the operator machine. Its scripts are static searches over source except `webhook-signature-test.sh` (sends requests to a running server) and `rls-coverage.sql` (needs a database connection), so neither of those two runs in an audit's preflight.
- `git archive` with exclude pathspecs works on git 2.55.
- The gate's behaviour is tested by `test/gate.test.mjs` (ten cases, including a change that tries to excuse itself and one that tries to hide itself). Those two cases failed on first run and found a real defect: the gate fell back to the head revision's exceptions when the base had none.
- GitHub's "Reuse workflows" page, read on 11 November: reusable workflows are located in `.github/workflows`, and "Subdirectories of the `workflows` directory are not supported."
- GitHub's contexts reference, read on 11 November: the `github` context has no `job_workflow_sha` property. `github.workflow_sha` is the commit of the calling workflow file. The gate therefore takes the pack commit as an input.
- The pack's gate stopped the pack's own first commit: zizmor's `self-repository` audit (added in 1.30.0) reported `uses: ./.github/workflows/security.yml`. GitHub's changelog of 30 July 2026 says a `uses:` value that starts with `$/` "resolves to your workflow's own repository at the exact commit that is running", including for reusable workflow calls, on runner 2.336.0 or newer. The pack's CI now uses `$/`.

- Both SQL rules also report commented-out SQL and a comment string that holds the same words (tested 11 November). Neither knows that a later migration replaced a definition. They give leads. The accurate form is a check of the catalogue after the migrations are applied to a throwaway database.
- Several jsm tool repositories carry their own skill at the root (`SKILL.md` in ntm, destructive_command_guard, coding_agent_session_search and ultimate_bug_scanner; `skills/` in beads_rust), read from GitHub on 11 November.

Verified on 12 November 2026, each with a test that fails without the fix (bead `whs-m6y.3.17`):

- gitleaks 8.30.1, zizmor 1.32.0 and Semgrep 1.185.0 write plain paths in SARIF and percent-encode nothing (tested with a space, a `%` and a non-ASCII letter in file names). The pack decoded them, so a file named `fixtures%2Fx.sql` was covered by an exception for `fixtures/`.
- gitleaks reads `.gitleaksignore` from the directory it scans, whatever `--gitleaks-ignore-path` says, in `dir` and in `git` mode. A fingerprint line hid a finding. A line that is not a fingerprint, such as `*`, hides nothing, so a test that plants one proves nothing.
- `git archive` leaves out a file that the commit's own `.gitattributes` marks `export-ignore`, and `git log -p` leaves out the text of a file marked `-diff`. Both hid a change from the gate. An `info/attributes` file in a git directory outranks `.gitattributes` in a commit.
- `git archive` refuses a tree that holds a `.git` entry.
- zizmor 1.32.0 lists `ZIZMOR_CONFIG`, `ZIZMOR_OFFLINE`, `ZIZMOR_NO_ONLINE_AUDITS` and `GH_HOST` as environment variables it reads (`zizmor --help`). With `GIT_DIR` set in the caller's environment, the pack's git commands read the repository it names.

Known gaps in the code on 11 November, and their state on 12 November. The six are closed in the code and tested on macOS; none of the commits has run in CI on Linux yet.

- Closed: the data boundary is derived when a surface is opened for a reader (`hiddenFrom` in `lib/surface.mjs`), for every check and for the audit's model.
- Closed: text under a data path is left out when the report is built, before anything is written.
- Closed: rule ids are put in the pack's naming where a tool's output is read, so `scan.sarif` holds no local path. What each tool wrote is no longer kept beside it.
- Closed: every process the pack starts gets an allowlisted environment.
- Closed: `whs gate --config <file>`. The reusable workflow has no input for it yet.
- Closed: `whs install` installs every pin, the audit process included, and nothing else fetches.

Known gaps in the code on 12 November:

- The allowlisted environment and the pack-owned git directory are tested on macOS only. On Linux, a runner that grants git's `safe.directory` through `GIT_CONFIG_*` variables, or a Python that needs a variable outside the list, would fail the gate closed.
- Each tree-reading check gets its own copy of a commit. The cost on a large repository is not timed.
- A finding under a data path keeps the tool's message. The pack's rules have fixed messages; a rule whose message quotes what it matched would carry that text to the model.
- An error that is not a usage error ends the command with exit code 1, which the exit codes define as findings. It should be 2.
- `fragments/registry.json`: the validator says "the last mode must need nothing" and checks that some mode needs nothing.
- The gate job in CI now fetches the audit process, which it does not use, because one command installs every pin.

Not yet verified:

- The current OpenSSF Scorecard check list and Allstar policy set.
- GitHub organisation security configurations on Free plans.
- Supabase Management API endpoint names for network restrictions and SSL enforcement.
- Whether Dependabot alerts fire for dependencies submitted through the dependency submission API, and whether Dependabot security updates are free on all plans.
- GitHub Secret Protection and Code Security prices.
- Claude Code's exact workspace-trust behaviour for project hooks.
- That a private reusable workflow cannot be called from another organisation, and that a consumer's CI cannot check out a private pack without a credential (from the planning of 10 November; the page read on 11 November does not state the access rules).
- A call of the reusable workflow from another repository, in the same organisation or another, and that the pack commit a caller passes equals the commit of the workflow it calls.
- What `$/` resolves to inside a workflow that another repository called. If it is the called repository at the called commit, the gate can load the pack through a `$/` action and the pack commit input goes away.
- The lockfile flags of `deno check` on the Deno version a target uses.
- How Semgrep derives the path prefix on rule ids (the pack strips everything up to the last dot).
- Whether GitHub push protection would react to canary fixtures if the repository becomes public.
- `sarif-multitool`'s matching.
- A complete audit run in each coverage mode.
