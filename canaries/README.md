# canaries

A canary is a small known case that proves a check sees what it is there to see. One directory per check, one directory per case:

```
canaries/<check>/<case>/expect.json
canaries/<check>/<case>/<fixture files>
```

`expect.json`:

| Field | Meaning |
|---|---|
| `about` | One sentence: what the case is |
| `expect` | Rule id to the exact number of findings. `{}` means the check must stay quiet |
| `allow_other_rules` | True when the tool may report other rules on the same fixture |
| `files` | Path to a list of strings, joined and written at run time. For content that must not exist word for word in this repository: a token, an agent hook, text addressed to a reviewer |

`node bin/whs.mjs canary` runs every case through the same code as a real scan. It fails when a check has no catching case or no quiet case, when a rule the pack writes has no catching case, and when any count differs.

Every confirmed finding adds a canary, written in general terms, and a rule where a pattern can catch it. It is added here only after the finding is closed, because a new canary that appears soon after an audit says what the audit found (standard 9.6). Until then it lives in a private overlay beside the record.

Not built: canaries for model checks (measured as a detection rate, not pass or fail), and the paired injection canary.
