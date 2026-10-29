---
topic: security-policy
status: verified
last-updated: 2026-10-29
---

# Security policy
Report vulnerabilities privately through GitHub: open the repository's Security tab and choose "Report a vulnerability". Do not open a public issue, pull request or discussion for a vulnerability. Never include real secrets, credentials or personal data in a report; use synthetic values.

SiftFetch is an early release maintained by one person. Reports are acknowledged on a best-effort basis, with a target of seven days. Fixes ship in a new release; the advisory is published after the fix.

## Supported versions
| Version | Supported |
|---|---|
| Latest 0.x release | Yes |
| Older releases | No; upgrade first |

## Report privately
These break a stated guarantee in the [threat model](docs/threat-model.md):

| Area | Example |
|---|---|
| Envelope | Fetched content that closes, forges or escapes the untrusted-content envelope |
| Hidden text | Text invisible to a human reader that survives cleaning without a span or label |
| Grading | A body returned with no risk grade or label at all |
| Outbound values | A protected value that leaves through a fetch, search, redirect or download |
| Hook | A tool call that the documented coverage says is denied or rerouted but runs |
| Setup tool | install, adopt or uninstall writing outside its ownership manifest, or loosening an existing guard |
| Files | Downloads or saves that escape the staging or quarantine folder |
| Policy folder | Any tool path that reveals policy contents to an agent |

## Report publicly
These are known limits, not vulnerabilities. Open a normal issue, and add the sample as a test fixture if you can:

| Area | Why |
|---|---|
| Missed injection | Pattern scanning cannot catch every phrasing; labels reduce risk but cannot prevent every injection |
| False positive | Benign text graded too high |
| Unsupported file type | Content shown as a binary notice instead of text |
| Uncovered tool | A client tool the [hook](docs/hook.md) does not claim to cover; static hooks are not a sandbox |

## Testing rules
Test only against your own machine and synthetic policies. Do not target sites, services or people you do not control. The offline suite never contacts the network beyond loopback test servers; keep proofs of concept the same way.
