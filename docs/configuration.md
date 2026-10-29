---
topic: configuration
status: verified
last-updated: 2026-10-29
---

# Configuration
Only the owner loosens policy or enters identities. The CLI/library can apply validated tightening changes. Malformed JSON/TOML, unknown security keys, conflicting security declarations or unsafe substitutes fail closed with policy_unavailable, even when enabled=false. Identifiers remain required.

## Config keys
Use config.json or config.toml. TOML wins for non-security settings after both files parse/validate. Differing security declarations are rejected conservatively, even if one seems stricter. Prefer one format; doctor warns about shadowed JSON.

| Key | Default | Meaning |
|---|---|---|
| enabled | true | Egress value checks; environment can disable |
| blocked_domains | [] | Hosts or leading *. patterns; PSL-aware suffix match; public-suffix-only patterns refused |
| contact_alias | unset | Compatibility alias for substitute.email |
| substitute | {} | Approved identity fields, never protected values |
| substitute.name | unset | Approved name |
| substitute.email | unset | Contact email; must agree with contact_alias if both set |
| substitute.phone | unset | Approved phone |
| substitute.postal_address | unset | Approved postal address |
| substitute.organization | unset | Approved organization |
| secret_file_mode | strict | strict/standard/off shell dotenv protection |
| shell_fetch | reroute | reroute/deny/off; recognized public shell fetches rewrite, deny, or retain old checks; independent of enabled; shown by policy_status/doctor |
| cookie_origins | [] | Exact origins allowed owner logins |
| cookies_attended_only | true | Require attended login use |
| local_endpoints | [] | Explicit local origins |
| local_endpoints.scheme | required | http/https |
| local_endpoints.host | required | Nonempty host |
| local_endpoints.port | required | Integer 1-65535 |
| local_endpoints.service, local_endpoints.allowed_ops | absent | Legacy metadata, not additional enforcement |
| mcp_local_tools | [] | Owner-trusted local MCP names/server wildcards |
| guard_lock | false | Boolean or table |
| guard_lock.enabled | true in table | Lock guard settings |
| guard_lock.paths | [] | Additional locked paths |
| browser_fetch | {} | Optional real-browser settings |
| browser_fetch.mode | off | off/on-wall/always-for-listed |
| browser_fetch.window | offscreen | offscreen/minimized/visible |
| browser_fetch.browser | msedge | msedge/chrome |
| browser_fetch.max_per_minute | 6 | Integer 1-60 |
| browser_fetch.sites | [] | Hosts for always-for-listed |
| download_dir | data folder | Download root; environment overrides |
| sightings | on | Independent on/off recording switch |
| sightings_max_bytes | 20971520 | Positive rotation threshold |
| spotlight | paragraph | paragraph/words/off |

Invalid browser option values use conservative defaults. An unknown key in any policy file fails closed, and the error and doctor name it. Keys starting with `_` or `$` (comments, `$schema`) and `version` are ignored. Other malformed security fields reject policy. Domains normalize case, IDN/punycode and IP literals. A host covers its subdomains, including with *. prefix. Domain blocks remain active when value checks are disabled.

## JSON and TOML examples
Only synthetic identities appear here. Missing substitute fields are omitted by get_substitute. No real alias ships. Load-time matching rejects protected values and recognized credentials in any substitute, including environment aliases. Doctor prints sanity/counts without values.

```json
{"enabled": true, "blocked_domains": ["blocked.example"],
 "substitute": {"name": "Alex Example", "email": "alias@example.invalid"}}
```

```toml
enabled = true
blocked_domains = ["blocked.example"]
[substitute]
name = "Alex Example"
email = "alias@example.invalid"
```

Reserved email domains are excluded from automatic contact headers. See [environment](environment.md) for precedence and [policy files](setup/policy-files.md) for identifier/grant schemas. Invalid recognized grants are ignored with a count warning; unknown grant keys fail closed.

## Managed tightening
See [CLI presets](cli.md). `tighten` compares validated effective state, including both formats and environment switches. It refuses mixed or unknown transitions. Atomic config replacements retain other keys, format and TOML comments, with backups; unsupported TOML forms require an editor. Matching JSON/TOML files are updated together; a partial I/O failure can require owner repair. Identifiers/exceptions are create-only through init and otherwise editor-only.

`install-manifest.json` is a separately validated versioned receipt in the policy folder. It stores client edit hashes, prior managed scalars, ownership and pending/completed intent, never policy values or whole client documents. Policy loaders and policy_fingerprint ignore it. Interrupted intent is reported, never replayed. Backups may contain client tokens.
