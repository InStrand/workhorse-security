# CI and Deploy Credential Hunting

#### When to use this file

Reach for this file when the target has GitHub Actions workflows that deploy, load data, publish packages or skills, or otherwise hold a credential for a production system, and above all when merging to the default branch deploys. It covers who can reach a production credential and what runs with it. Use `SUPPLY-CHAIN-AND-RELEASE.md` for dependency and release integrity and `CLOUD-AND-DEPLOYMENT.md` for the platform the deploy lands on.

Split large targets by workflow trigger: pull request, push to the default branch, schedule, manual dispatch, and workflows started by other workflows.

## Core discipline (include in every agent prompt for this domain)

```
- For a pull request from a branch in the same repository, the workflow file that runs is the one on that branch, and it can read every repository-level and organisation-level secret. Anyone who can push a branch can therefore read those secrets by editing a workflow. Only secrets held in an environment with branch restrictions are out of reach.
- Where merging deploys, a control counts only if it is evaluated on the merged commit before the deploy starts. A review comment that arrives after the merge arrives after the deploy.
- Repository settings are not in the repository: branch protection, rulesets, environments, secret scopes, who is an administrator. Do not assume them. Use needs_validation and give the exact read-only API call the owner can run.
- A required check that is filtered by path never reports on other changes. Treat it as absent for those changes.
- An account-wide token is every project that account can reach. Ask what the job needs and compare.
```

## Credential reach attack classes (subagent_type: `general`)

**Production credential readable from a change under review**
A workflow that runs on `pull_request` (or on both a schedule and pull requests) and references a production secret, or a repository-level production secret in a repository where any workflow runs for pull requests. State which secret, which trigger, and who can push a branch.

**Privileged trigger with untrusted code**
`pull_request_target` or `workflow_run` that checks out, builds, installs or executes code from the pull request, or passes its title, body, branch name or files into a shell step.

**Expression expanded into a shell command**
`${{ ... }}` holding event data (titles, branch names, comment bodies, file names, inputs) inside `run:` or an action input that is evaluated as code.

**Token with more rights than the job needs**
No `permissions:` block, write permissions at workflow level, `persist-credentials` left on in a job that runs other code, or a personal or account-wide token where a scoped one exists.

## Deploy integrity attack classes (subagent_type: `general`)

**Unpinned code in a job that holds a credential**
Actions referenced by tag or branch, tools installed at `latest`, scripts fetched and piped to a shell, or container images by mutable tag, inside a deploy, loader or publish job.

**Deploy that does not wait for its checks**
A deploy job that starts on push to the default branch with no job that re-runs the checks on that commit and no dependence on their result.

**Service that is deployed outside the workflow**
A skip list, a hand-deployed function or site, or a publish step done from a browser. The repository is not the record for that service. Name it, and what the workflow would overwrite or never update.

**Automatic merge as the control point**
A workflow that merges or approves pull requests after checks. Find what a person decided, and whether that decision came before the action it was meant to control.

## Universal moves (apply across the above)

- Build one table: workflow, triggers, secrets referenced, environment (if any), permissions, and whether the job runs code from the change. Every row with a production secret and a pull request trigger is a lead.
- Follow one production credential from where it is stored to every step that can read it, including steps in reusable workflows and composite actions.
- Read the deploy workflow as the merged commit sees it. List what must be true before the first step that changes production, and where each of those is enforced.

## Validation rules (apply before reporting ANY finding here)

1. Name the actor (anyone with push access, a fork contributor, a compromised action), the credential or deploy step reached, and the workflow line that gives the reach.
2. Do not run workflows, call the GitHub API with a write scope, or use any credential. Source evidence only.
3. When the finding depends on a setting outside the repository (environment protection, secret scope, branch rules), return `needs_validation` with the read-only API call that settles it, for example `gh api repos/OWNER/REPO/environments`.
4. Return `confirmed` when the workflow files alone show the reach, for example a pull request trigger and a `secrets.` reference in the same job with no environment.
5. Describe impact by what the credential can do. Do not print, guess or test secret values.
