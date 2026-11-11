# adapters

Not built. An adapter builds a surface from something that is not a git commit, so that checks can read it and two surfaces can be compared. Each adapter is read-only, uses its own least-privilege credential, and never the deploy token.

| Adapter | Surface | Wraps |
|---|---|---|
| `dep-surface` | Every dependency a repository declares anywhere, with the route by which a scanner sees it: lockfile, manifest, submitted graph, SBOM, or none (standard 6.3) | Dependabot, [OSV-Scanner](https://github.com/google/osv-scanner) for SBOM output |
| `supabase` | The deployed catalogue through a catalogue-only role: lints, definers the anonymous role can execute, grants, RLS flags, function body hashes; and deployed Edge Function sources | Supabase's Security Advisor lints, the Management API |
| `convex` | The public function surface of the production deployment | `npx convex function-spec --prod` |
| `vercel`, `vps` | Public routes, environment separation, deploy identity | Platform APIs |

Comparisons these make possible: the tree against deployed state (what runs that no file shows), a declared baseline against platform settings (`posture/`), advisories against dependencies (`estate/`).

Git is not always what runs. A migration can rewrite a deployed function's body from the database itself, and a setting can be changed in a dashboard, so the Semgrep rules in `checks/` are a tripwire and the catalogue is the authority.
