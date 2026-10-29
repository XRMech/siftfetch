---
topic: environment
status: verified
last-updated: 2026-10-27
---

# Environment
Set environment before starting the host process. Never put protected values in aliases. Owners control these settings.

| Variable | Default | Effect |
|---|---|---|
| SIFTFETCH_ENABLED | unset | Exactly 0 disables; cannot override config false to true |
| SIFTFETCH_HOME | ~/.siftfetch | Policy folder; update client deny rules if moved |
| SIFTFETCH_DATA | platform data folder | Artifact/ledger/sightings root |
| SIFTFETCH_DOWNLOAD_DIR | config download_dir, then data folder | Override downloads only |
| SIFTFETCH_CONTACT_ALIAS | config contact_alias/substitute.email | Nonempty environment alias wins; sanity checks still apply |
| SIFTFETCH_ATTENDED | unset | Exactly 1 opts MCP into attended behavior |
| AGENT_HEADLESS | unset | Exactly 1 forces unattended, overriding attended opt-in |
| LOCALAPPDATA | OS supplied | Windows data root: LOCALAPPDATA/siftfetch |
| XDG_DATA_HOME | ~/.local/share | Other platforms: XDG_DATA_HOME/siftfetch |

## Runtime inputs
Do not mutate process environment concurrently with library calls. Hook payload agent_id, Codex turn_id and --deny also force unattended decisions. Hook path expansion recognizes HOME, USERPROFILE and other environment references; these are path inputs, not additional SiftFetch config keys.
