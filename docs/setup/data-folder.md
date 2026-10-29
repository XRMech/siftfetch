---
topic: data-folder
status: verified
last-updated: 2026-10-27
---

# Data folder
Artifacts remain untrusted. Keep readable data separate from owner-only policy. Never execute downloads automatically.

| Location | Contents |
|---|---|
| saved/ | Enveloped accepted Markdown |
| quarantine/ | High-risk/incomplete text for owner review |
| downloads/ | Unchanged download bytes |
| *.siftfetch.json | Hash/type/grade/completeness sidecar |
| saved-ledger.jsonl | Save provenance and grade |
| sightings.jsonl, sightings.1.jsonl | Current/rotated detections |

SIFTFETCH_DATA overrides platform defaults: LOCALAPPDATA/siftfetch on Windows, XDG_DATA_HOME/siftfetch or ~/.local/share/siftfetch elsewhere. Download root precedence: explicit library staging_dir, SIFTFETCH_DOWNLOAD_DIR, config download_dir, data folder. Download quarantine uses its download root; other records stay in data. Download links/junctions are refused.

Text scanning is bounded to 2 MB; longer text is held. Binary files are "not scanned". Decision logs live in policy, with labels/reasons and no values. Potentially sensitive hosts are hashed; disabled URL decisions conservatively hash hosts.
