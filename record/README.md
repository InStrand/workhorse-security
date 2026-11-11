# record

Mostly not built. The record is every finding from every check, in SARIF 2.1.0, with one identity and one state. What exists today is in `lib/findings.mjs`: the fingerprint (`partialFingerprints["whs/v1"]`), the comparison of two sets of findings, and exceptions written as SARIF `suppressions`.

What goes here:

| Piece | Does | Wraps |
|---|---|---|
| Converters | Turn output that is not SARIF into SARIF: the audit's `findings.json`, posture differences, advisory matches | Cloudflare's `report-schema.json` as the audit's native evidence |
| The record | Merge a scan into the stored record and set `baselineState`: `new`, `unchanged`, `updated`, `absent` | SARIF 2.1.0. Evaluate Microsoft's `sarif-multitool` before writing more |
| The importer | One bead per finding to fix or validate, keyed by fingerprint; a security bead closes only when a later scan of the deployed revision no longer reports it | [beads_rust](https://github.com/Dicklesworthstone/beads_rust) |

States: `new`, `triaged` (fix, accept or validate), `in_progress`, `verified_closed`, `accepted_risk` (owner, reason, expiry). Nobody closes a security bead by hand.

Until this exists, an audit's record is its `findings.json` and coverage ledger, and beads are created from them in the operator session (see the audit skill, steps 5 and 6).
