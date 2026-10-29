---
topic: RELEASING
status: verified
last-updated: 2026-10-27
---

# Release plan
Publication is an owner action, not part of implementation. Source installation is supported; no PyPI publication is claimed.

## Release prerequisites
Verify an isolated wheel install includes detector patterns, the public suffix list and init templates. Run the offline suite on each advertised platform. Run doctor with a temporary synthetic policy and client configuration. Owner-run live hook trust/execution checks remain separate from automated tests.

Init, doctor, install and TOML support are implemented. Existing JSON policies and public library signatures remain supported. A future unified console command may supplement the supported `python -m siftfetch` setup interface and existing `siftfetch-hook` / `siftfetch-server` entry points.

## Clean-room check
Run `python tools/cleanroom.py` before release. The stdlib harness copies tracked and nonignored source into temporary storage, builds a wheel and sdist, rebuilds the sdist, and installs noneditable wheels in fresh PDF/test and test-only environments. CI runs both on Python 3.12 across Windows, Linux and macOS; the existing editable test matrix remains.

Use `--offline --find-links /path/to/wheels` with a complete local wheelhouse (including setuptools, wheel, optional build and both extras' dependencies). Repeat --find-links for additional directories. No inherited pip configuration or user tool PATH is used. `--variant pdf/no-pdf` selects one variant; `--temp-parent DIR` selects scratch storage. Artifacts are retained for inspection.

Each numbered step prints PASS/FAIL and a reason; any failure gives a nonzero exit. Child environments have temporary home, application-data, XDG and Codex directories. A child reports home/policy/data paths before writes; any escape aborts. Installed tests disable pytest's source pythonpath and check imported package locations. Package resources, setup round trips, unrelated client content, legacy adoption, backups, hook stdin, stdio MCP, loopback HTML/PDF fetching and the packaged benchmark are checked. No clients or models are launched. Owner strings are scanned in every sdist file and in tracked files by the offline suite; public author metadata is explicitly allowlisted.

## Publication workflow
The owner selects a version, records changes, builds distributions, validates metadata, and publishes through an approved release workflow. TestPyPI and PyPI configuration, tags, pushes and publishing require owner authorization. No publishing credentials belong in this repository.

Before 1.0, document compatibility changes explicitly. Security fixes need release notes and appropriate advisories. See [testing](docs/testing.md) and [setup](SETUP.md).
