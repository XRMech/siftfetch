---
topic: install
status: verified
last-updated: 2026-10-28
---

# Install
Use Python 3.11+. This repository is standalone; no other host infrastructure is needed. Never enter personal data through an agent.

For stable hook interpreter paths, prefer `pipx install C:/path/to/siftfetch` or `uv tool install C:/path/to/siftfetch`. Publication is owner-run; these examples install a local checkout. Run `siftfetch setup` for the five-prompt wizard, or the installed Python's `-m siftfetch setup`. Setup refuses temporary interpreters; avoid ephemeral uvx/cache environments.

```powershell
siftfetch setup --preset standard --client claude --client codex --scope user
siftfetch setup --preset standard --client claude --client codex --scope user --apply
```

Review the plan before applying. Restart clients, re-trust the hook in Codex `/hooks`, then run `siftfetch doctor`. Registration remains configured; verification pending. Developer checkout workflow:

```powershell
python -m venv .venv
.venv/Scripts/python.exe -m pip install -e ".[test]"
.venv/Scripts/python.exe -m pytest -q
.venv/Scripts/python.exe -m siftfetch init
```

POSIX uses .venv/bin/python. Installation requires package access; tests do not. Python tomllib handles TOML without added dependencies. Detector patterns, PSL and init templates are packaged. Windows is verified; other platforms require verification.

| Extra | Purpose |
|---|---|
| test | pytest |
| browser | Playwright real-browser reads |
| logins | browser-cookie3 login extraction |

Owner configures [policy files](policy-files.md), reviews install dry run, then applies. Init's empty identifiers cannot protect values not listed. Optional browser installation is owner-run; browser reads default off.
