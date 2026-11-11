# probes

Not built. A probe is a private repository that holds one known case and proves, from outside, that something we rely on still works. It is a canary for a service rather than for a scanner.

| Probe | Proves |
|---|---|
| Advisory routes | That a dependency with a known advisory, declared by each route (lockfile, manifest, submitted graph, SBOM), raises an alert. A route that stops alerting marks every dependency on it as uncovered (standard 6.3) |
| Cross-repository call | That a repository in another organisation can call the reusable gate at a pinned commit, and which commit the gate then runs |
| Production credential fence | That a pull request which edits a workflow to read a production secret cannot read it |

Known limits to prove against: GitHub's Advisory Database has no JSR or Deno ecosystem; Dependabot reads Deno dependencies from `deno.json` and `deno.jsonc` only; OSV-Scanner has no Deno support.
