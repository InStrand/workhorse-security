# posture

Not built. Layer A of the standard (section 4).

One declared baseline per platform, the settings the threat model for that stack requires, plus an apply step and a verify step. Verifying is a check like any other: it compares the baseline with a platform surface from `adapters/` and reports each difference as a finding. Applying is the fix for such a finding, and a person approves it.

| Platform | File | Verified with |
|---|---|---|
| GitHub | `github.yaml` | [OpenSSF Scorecard](https://github.com/ossf/scorecard) and [Allstar](https://github.com/ossf/allstar), not a check of our own |
| Cloudflare | `cloudflare.yaml` | Cloudflare API or Terraform |
| Supabase | `supabase.yaml` | Management API, and the Security Advisor lints run by SQL |
| Convex | `convex.yaml` | `npx convex function-spec --prod` |
| Vercel, Netlify | `vercel.yaml`, `netlify.yaml` | Platform APIs |
| VPS | `vps.yaml` | Ansible or cloud-init |

The first control is the one with the most reach: production credentials only in a branch-restricted `production` environment, proven by a pull request that changes a workflow to read one and fails.
