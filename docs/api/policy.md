---
topic: policy
status: verified
last-updated: 2026-10-27
---

# Matching and scan API
Never accept complete=false as clean. Local policy checks log labels/reasons without values.

| API | Contract |
|---|---|
| egress_policy.API_VERSION | 1 |
| identifier_pattern(kind, value, match="auto") | Compiled pattern; email/phone/text; auto/word/substring |
| decoded_views(text, budget=None) | DecodeResult views and complete; default 4 MB, three levels |
| check_url(url, *, op="fetch", tool="siftfetch", session_kind="unattended", chrome=False, extra=None, resolve_host=False) | Decision for URL plus location/value header/body pairs |
| check_search(query, *, tool="siftfetch", session_kind="unattended") | Search Decision |
| check_text(text, *, op="api", tool, session_kind, chrome=False, log=True, exact_only=False, interactive_ask=False) | Free-text Decision; shell-prefix grants for shell only |
| check_mcp(payload, *, tool, session_kind) | String leaves/URLs under shared budget |
| enabled() | Effective switch; malformed config never disables |
| get_substitute(kind=None) | Validated approved fields |
| policy_dir(), policy_fingerprint() | Path; digest of six files excluding log |
| contact_alias() | Safe contact email or None; reserved domains excluded |
| injection_scan.scan_text(text, hidden=(), *, spotlight="off") | LabeledText, Scan tuple |
| injection_scan.hidden_texts(raw_html) | Bounded hidden-region list with completeness |
| injection_scan.envelope(content, source, scan) | Model-facing envelope |

## Decisions and matching
Decision fields: action (allow/deny/ask), reason_code, label, sensitive_host. next_step and message() provide guidance. Transport denial raises EgressDenied with .decision. See [reason codes](../hook.md).

Decoding handles URL/HTML escapes, Unicode normalization, base64/base32/hex. Exact text of eight or more alphanumeric characters matches inside padding; short/soft text uses boundaries. Email recognizes plus tags and Gmail dot variants. Phones use ten digits, dropping a leading US 1, with bounded separators. Reversal, ROT13 and paraphrase are outside coverage. Cache tracks file location, nanosecond mtime/size and alias environment; access is locked.
