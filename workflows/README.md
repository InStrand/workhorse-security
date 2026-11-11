# workflows

Caller workflows for a repository to copy. The reusable workflows themselves sit in `.github/workflows/` of this repository, because GitHub loads a reusable workflow only from that directory and does not support subdirectories.

| File | Copy to | Calls |
|---|---|---|
| `security.yml` | `.github/workflows/security.yml` | `.github/workflows/security.yml` in this repository: the gate (`whs gate`) |

Then add `security/config.json` to the repository and make `security / security-gate` a required check.

Not built: `deploy-wait.yml`, which runs the gate on the merged commit and reads GitHub's check conclusions for that commit before the `production` environment is granted (standard 5.5), and the advisory AI reviewer job (standard 5.3).

Calling the gate from another organisation needs this repository to be public, or the pack vendored at a pinned hash (decision D9).
