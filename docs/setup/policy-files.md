---
topic: policy-files
status: verified
last-updated: 2026-10-27
---

# Policy files
Owner-only: enter protected values in your own editor. Agents must never read/list/search/edit the real policy folder, dotenv files or secret folders. Doctor reports only status/counts. Keep policy outside repositories.

Init creates absent JSON examples with empty identifiers. It skips a stem when either format exists and never overwrites/reads existing values. Owner chooses permissions; init does not change ACLs.

| File | Required | Schema |
|---|---|---|
| identifiers.json / identifiers.toml | yes | values array; optional version |
| exceptions.json / exceptions.toml | no | exceptions array; optional version |
| config.json / config.toml | no | [Config keys](../configuration.md) |

TOML wins after both formats validate and security declarations agree. Conflicts fail closed. Doctor warns about shadowed JSON; prefer one format.

## Identifiers
Empty values is valid but protects no personal identifiers. Examples are synthetic.

| Field | Meaning |
|---|---|
| label | Non-sensitive diagnostic label |
| kind | email/phone/text |
| value | Protected literal; owner-entered only |
| class | exact/soft |
| public_search | false; true only for soft identifiers |
| match | Optional word/substring; otherwise automatic |

```json
{"values":[{"label":"personal_email","kind":"email","value":"jane.doe@mail.example","class":"exact"}]}
```

```toml
[[values]]
label = "personal_email"
kind = "email"
value = "jane.doe@mail.example"
class = "exact"
```

## Disclosure grants
Grants permit one label at a destination/location until an offset-bearing RFC3339 expiry. Invalid recognized grants are ignored and counted; unknown keys fail closed. Credentials cannot be granted. Shell grants cannot include chains/pipes/redirection/substitution.

| Field | Meaning |
|---|---|
| label | Identifier label |
| op | Operation such as fetch/search/shell |
| origin | Exact HTTP(S) origin for URL grants |
| location | host/path/query/param:name |
| path_prefix | Default /; plain bounded path |
| expires | Required RFC3339 with timezone |
| command_prefix | Shell grants use this instead of origin/location |

```json
{"exceptions":[{"label":"work_email","origin":"https://work.example","op":"fetch","location":"param:email","path_prefix":"/profile","expires":"2027-01-31T00:00:00Z"}]}
```

```toml
[[exceptions]]
label = "work_email"
origin = "https://work.example"
op = "fetch"
location = "param:email"
path_prefix = "/profile"
expires = "2027-01-31T00:00:00Z"
```

Quote TOML expires to match the string schema. Configure substitutes separately from protected values. Automatic contact email excludes reserved domains; no real alias ships.
