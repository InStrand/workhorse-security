# estate

Not built. Scheduled jobs that read every organisation InStrand works in, with a read-only token. They run from this repository's Actions or InStrand's server, never from a customer's repository.

| Job | Does | Wraps |
|---|---|---|
| Weekly posture check | Compares each platform with its baseline in `posture/` and files a bead per difference | OpenSSF Scorecard and Allstar for GitHub |
| Advisory reader | Polls the feeds daily, matches each item against every repository's dependency surface, and hands matches to a triage agent | Dependabot and the GitHub Advisory Database, OSV, the [Zero Wire](https://radar.cloudflare.com/security/zero-wire/rss) feed (parsed as data; its own AI prompt is never run), vendor advisories, CISA KEV |
| Heartbeat | Reports when a scheduled job has not reported, so that silence is a finding | |
| Version drift | Reports which repositories run an older pack | The `flywheel-core` add-on registry |

An estate inventory per customer comes first: every repository, site, published skill and hand-deployed service, each with a tier and the checks that tier requires.
