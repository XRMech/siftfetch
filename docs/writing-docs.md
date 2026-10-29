---
topic: writing-docs
status: verified
last-updated: 2026-10-27
---

# Writing documentation
Document verified code, not intentions. Never include personal data or real aliases. Use repository placeholders; keep SiftFetch generic and standalone.

## Structure rules
README.md and docs/index.md are routers under approximately 400 tokens. Use a table with one row per directly routed doc and one-line "read when". Topic files target 1500 tokens; split larger topics into a subfolder with its own index.md. Lint estimates tokens as characters divided by four, allowing 10% tolerance: 440 router / 1650 topic tokens. This is a documented estimate, not a model tokenizer.

Every document has frontmatter: topic, status, last-updated. Last-updated is an absolute ISO date verified against code, such as 2026-10-27. Relative update claims are prohibited. CLI duration filters are not update dates.

## Writing rules
Critical rules come first. Each second-level section must stand alone; do not refer backward instead of restating a relevant constraint. Use tables for functions, tools, parameters, config keys, environment variables and reason codes. Tag every code fence with its language. Use resolving relative repository links. Use one term per concept from the [vocabulary](index.md).

State precise defaults, behavior, results, errors and limits. Labels do not prevent all injection, and static hooks are not a sandbox. Explain opt-ins and owner-only steps. Preserve public signatures and JSON compatibility in code and docs.

## Validation
Run the offline suite after changes. Add coverage entries for new public functions/tools/keys/variables/codes. Review critical-rule ordering, section independence and router wording manually; lint cannot judge meaning. Executable network/model examples never belong in automated tests.
