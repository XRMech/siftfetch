"""Outbound privacy policy shared by the SiftFetch transport and agent hooks.

Decides whether an outbound request may carry what it carries. Owner
identifiers and credentials are matched in every structural location of the
request (host, path, each query parameter, headers, body); each occurrence is
decided on its own and any deny wins. A disclosure grant can allow one exact
occurrence at one exact origin; nothing else relaxes a protected value.

Stdlib only: agent hooks import this file with whatever Python runs the hook.

Policy files live in ``SIFTFETCH_HOME`` (default ``~/.siftfetch``):

- ``identifiers.json`` -- protected values. Required: if it is missing or
  unreadable every check denies (fail closed).
- ``exceptions.json`` -- disclosure grants. Optional.
- ``config.json`` -- ``local_endpoints``, ``cookie_origins``,
  ``cookies_attended_only`` (default true), ``secret_file_mode`` (``strict`` | ``standard`` | ``off``; default
  ``strict``), ``contact_alias``, ``browser_fetch`` and ``guard_lock``
  (default off). Optional.

Decisions are appended to ``egress-decisions.jsonl`` in the same directory.
Records hold labels, hosts and reason codes only -- never values, full URLs,
queries or cookies. When a protected value matched, the host is hashed.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import html
import ipaddress
import json
import os
import re
import socket
import threading
import time
import unicodedata
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

POLICY_VERSION = "egress-1"

# A request larger than this is not scanned; it is denied. Real search queries
# and URLs are far smaller, and an unbounded input would make the decoder an
# easy way to stall the transport.
MAX_INPUT_BYTES = 1_000_000

# Runs this long are plausible base64 payloads; shorter ones are mostly words
# and identifiers that decode to noise.
_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]{16,4096}={0,2}")

_CREDENTIAL_PATTERNS = [
    re.compile(p)
    for p in (
        r"sk-ant-[A-Za-z0-9_-]{10,}",
        r"\bsk-[A-Za-z0-9_-]{20,}",
        r"\bgh[pousr]_[A-Za-z0-9]{30,}",
        r"\bgithub_pat_[A-Za-z0-9_]{20,}",
        r"\bAKIA[0-9A-Z]{16}\b",
        r"\bxox[baprs]-[A-Za-z0-9-]{10,}",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
        r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{20,}",
    )
]

_NEXT_STEP = {
    "protected_value": (
        "Remove the value; if an API needs a contact email use {alias}; "
        "otherwise omit the field."
    ),
    "protected_value_no_alias": (
        "Remove the value and omit the field. No contact alias is set; the "
        "owner can set contact_alias in the SiftFetch config."
    ),
    "soft_identifier": (
        "This identifier is protected for this operation. Remove it, or ask "
        "the owner directly."
    ),
    "credential": "Credentials never go into requests; ask the owner.",
    "policy_unavailable": (
        "The privacy policy could not load; tell the owner. Web requests will "
        "fail until it is fixed; work that needs no web access can continue."
    ),
    "ambiguous_request": (
        "The request has userinfo or cannot be parsed, or it repeats a query "
        "parameter or has a bare flag and also holds a protected value; send "
        "a plain canonical URL without the protected value."
    ),
    "oversized_input": "The request is too large to check; send a smaller request.",
    "private_destination": (
        "Private, loopback and link-local destinations are not reachable "
        "through this route."
    ),
}


class EgressDenied(Exception):
    """Raised by the transport when the policy denies a request."""

    def __init__(self, decision: "Decision") -> None:
        super().__init__(decision.message())
        self.decision = decision


@dataclass(frozen=True)
class Decision:
    action: str  # "allow" | "deny" | "ask"
    reason_code: str = "ok"
    label: str | None = None

    @property
    def next_step(self) -> str:
        # The literal alias, not a variable name: headless sessions deny shell
        # commands that expand variables, so a name leaves a well-behaved
        # agent with no usable contact. No alias ships; without one, the hint
        # says to omit the field.
        alias = contact_alias()
        if self.reason_code == "protected_value" and alias is None:
            return _NEXT_STEP["protected_value_no_alias"]
        return _NEXT_STEP.get(self.reason_code, "").replace("{alias}", alias or "")

    def message(self) -> str:
        if self.action == "allow":
            return ""
        label = f", {self.label}" if self.label else ""
        return (
            f"Blocked by privacy policy ({self.reason_code}{label}). {self.next_step}\n"
            "Don't send this value another way (another tool, encoding or route). "
            "Retrying without it, or carrying on with the rest of the task, is fine."
        )


ALLOW = Decision("allow")


@dataclass(frozen=True)
class _Identifier:
    label: str
    cls: str  # "exact" | "soft"
    pattern: re.Pattern
    public_search: bool = False


@dataclass(frozen=True)
class _Grant:
    label: str
    origin: str
    op: str
    location: str
    path_prefix: str
    expires: datetime


@dataclass
class _Policy:
    identifiers: list[_Identifier]
    grants: list[_Grant]
    local_endpoints: set[str]
    cookie_origins: set[str]
    mtimes: tuple = field(default_factory=tuple)
    cookies_attended_only: bool = True


def policy_dir() -> Path:
    return Path(os.environ.get("SIFTFETCH_HOME") or Path.home() / ".siftfetch")


def policy_fingerprint() -> str:
    """One hash over the policy files (identifiers, grants, config), not the log.

    Lets a test harness confirm the owner's policy was not changed during a
    run without reading or printing any value itself. Missing files count as
    absent, so creating one changes the fingerprint too.
    """
    digest = hashlib.sha256()
    for name in ("identifiers.json", "exceptions.json", "config.json"):
        path = policy_dir() / name
        digest.update(name.encode())
        try:
            digest.update(hashlib.sha256(path.read_bytes()).digest())
        except OSError:
            digest.update(b"absent")
    return digest.hexdigest()


SECRET_FILE_MODES = ("strict", "standard", "off")


def _config() -> dict:
    """The optional ``config.json``; empty when missing or unreadable."""
    try:
        config = json.loads((policy_dir() / "config.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    return config if isinstance(config, dict) else {}


def secret_file_mode() -> str:
    """How many shell routes to a dotenv file's contents are blocked.

    ``strict`` (the default) blocks printing, redirects, loading and copying;
    ``standard`` blocks printing and redirects; ``off`` blocks nothing.
    Anything missing or invalid means ``strict``: the owner loosens the mode
    on purpose, never by accident.
    """
    mode = _config().get("secret_file_mode", "strict")
    return mode if mode in SECRET_FILE_MODES else "strict"


# The guard's own settings: hook registration and deny rules, the hook
# scripts, and Codex config. Matched anywhere in a path, so every project's
# .claude/settings.json is covered too.
GUARD_LOCK_PATHS = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".claude/hooks/",
    ".codex/config.toml",
)


def normalize_path_text(text: str) -> str:
    """Lowercase with forward slashes, for matching paths inside commands."""
    return re.sub(r"/{2,}", "/", text.replace("\\", "/")).lower()


def guard_lock_paths() -> list[str]:
    """Paths agents may not change while the owner's ``guard_lock`` is on.

    Off (empty) unless the owner sets ``guard_lock`` to ``true``, or to
    ``{"enabled": true, "paths": [...]}`` to lock extra paths, such as the
    folder the engine is installed in. It is the owner's choice: with the
    lock off, agents configure settings as usual.
    """
    return guard_lock_state()[0]


def guard_lock_state() -> tuple[list[str], str | None]:
    """The locked paths, and why the lock setting couldn't be read, if it couldn't.

    A missing config means the lock is off. A config that exists but can't
    be read, or a ``guard_lock`` value that is neither off nor a valid
    lock, fails closed: the built-in paths stay locked and the second item
    names the cause, so the owner can fix it.
    """
    path = policy_dir() / "config.json"
    if not path.exists():
        return [], None
    builtin = list(GUARD_LOCK_PATHS)
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return builtin, "config.json could not be read"
    if not isinstance(config, dict):
        return builtin, "config.json is not a JSON object"
    lock = config.get("guard_lock", False)
    if lock is False or lock is None:
        return [], None
    if lock is True:
        lock = {}
    if not isinstance(lock, dict):
        return builtin, "guard_lock is not true, false or an object"
    enabled = lock.get("enabled", True)
    if enabled is False:
        return [], None
    if enabled is not True:
        return builtin, "guard_lock.enabled is not true or false"
    paths = lock.get("paths", [])
    if not isinstance(paths, list):
        return builtin, "guard_lock.paths is not a list"
    extra = [normalize_path_text(os.path.expandvars(os.path.expanduser(p.strip())))
             for p in paths if isinstance(p, str) and p.strip()]
    return builtin + extra, None


def contact_alias() -> str | None:
    """The owner's contact alias: ``SIFTFETCH_CONTACT_ALIAS``, else
    ``contact_alias`` in the config. None when unset or a placeholder.

    The config value matters for long-lived servers started by a client whose
    environment lacks the variable.
    """
    alias = os.environ.get("SIFTFETCH_CONTACT_ALIAS") or _config().get("contact_alias")
    if not isinstance(alias, str) or alias.count("@") != 1:
        return None
    # A placeholder domain reads as a bot hiding its identity: Unpaywall rejects
    # it and polite-pool APIs deprioritize it. Sending no contact is better.
    domain = alias.rsplit("@", 1)[1].strip().lower().rstrip(".")
    if domain in _RESERVED_DOMAINS or domain.endswith(_RESERVED_SUFFIXES):
        return None
    return alias.strip()


BROWSER_FETCH_MODES = ("off", "on-wall", "always-for-listed")
BROWSER_WINDOWS = ("offscreen", "minimized", "visible")


def browser_fetch_settings() -> dict:
    """Owner settings for real-browser page reads (``browser_fetch`` in the config).

    Off unless the owner turns it on. Invalid values fall back to the
    conservative choice: mode ``off``, window ``offscreen``, 6 pages a minute.
    """
    raw = _config().get("browser_fetch")
    raw = raw if isinstance(raw, dict) else {}
    mode = raw.get("mode", "off")
    window = raw.get("window", "offscreen")
    browser = raw.get("browser", "msedge")
    rate = raw.get("max_per_minute", 6)
    sites = raw.get("sites", [])
    return {
        "mode": mode if mode in BROWSER_FETCH_MODES else "off",
        "window": window if window in BROWSER_WINDOWS else "offscreen",
        "browser": browser if browser in ("msedge", "chrome") else "msedge",
        "max_per_minute": rate if isinstance(rate, int) and 0 < rate <= 60 else 6,
        "sites": [s.lower().strip() for s in sites if isinstance(s, str) and s.strip()],
    }


_RESERVED_DOMAINS = frozenset({"example.com", "example.net", "example.org"})
_RESERVED_SUFFIXES = (".example", ".test", ".invalid", ".localhost", ".local")


# --- identifier patterns ----------------------------------------------------

_SEP = r"[\s+_.\-]*"


def _email_pattern(value: str) -> re.Pattern:
    local, _, domain = value.strip().partition("@")
    if not local or not domain:
        raise ValueError("email identifier needs local@domain")
    # The @ can be spelled out or swapped for a separator, as in a DNS name
    # (pat.example.mailhost.test); the domain's dots can be spelled out too.
    # Possessive (*+): whitespace is never given back, so a long run of
    # spaces after the local part can't make the search quadratic.
    at = r"\s*+(?:@|\(at\)|\[at\]|\{at\}|(?<=\s)at(?=\s)|[._-])\s*+"
    dot = r"\s*+(?:\.|\(dot\)|\[dot\]|(?<=\s)dot(?=\s))\s*+"
    domain_pattern = dot.join(re.escape(part) for part in domain.split("."))
    return re.compile(re.escape(local) + at + domain_pattern, re.IGNORECASE)


def _phone_pattern(value: str) -> re.Pattern:
    digits = re.sub(r"\D", "", value)
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) != 10:
        raise ValueError("phone identifier needs 10 digits")
    body = r"[\s.\-()]*+".join(digits)
    return re.compile(r"(?<!\d)(?:\+?1[\s.\-]*)?\(?" + body + r"(?!\d)")


def _text_pattern(value: str) -> re.Pattern:
    tokens = value.split()
    if not tokens:
        raise ValueError("text identifier is empty")
    body = _SEP.join(re.escape(t) for t in tokens)
    return re.compile(r"(?<![A-Za-z0-9])" + body + r"(?![A-Za-z0-9])", re.IGNORECASE)


_KIND_PATTERNS = {"email": _email_pattern, "phone": _phone_pattern, "text": _text_pattern}


# --- policy loading ---------------------------------------------------------

_lock = threading.Lock()
_cached: _Policy | None = None


def _mtime(path: Path) -> float | None:
    try:
        return path.stat().st_mtime
    except FileNotFoundError:
        return None


def _parse_expiry(value: str) -> datetime:
    # RFC 3339 only: a timestamp without an explicit offset is rejected, so a
    # grant can never silently expire in an unexpected timezone.
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(\.\d+)?[+-]\d{2}:\d{2}", text):
        raise ValueError("expires must be RFC 3339")
    return datetime.fromisoformat(text)


def _canonical_origin(scheme: str, host: str, port: int | None) -> str:
    scheme = scheme.lower()
    default = {"http": 80, "https": 443}.get(scheme)
    effective = port or default
    return f"{scheme}://{host.lower().rstrip('.')}:{effective}"


def _origin_of(url: str) -> str:
    parts = urlsplit(url)
    return _canonical_origin(parts.scheme, parts.hostname or "", parts.port)


def _load_policy() -> _Policy:
    global _cached
    base = policy_dir()
    files = [base / "identifiers.json", base / "exceptions.json", base / "config.json"]
    mtimes = tuple(_mtime(f) for f in files)
    with _lock:
        if _cached is not None and _cached.mtimes == mtimes:
            return _cached

        raw_ids = json.loads(files[0].read_text(encoding="utf-8"))
        identifiers = []
        for entry in raw_ids["values"]:
            cls = entry["class"]
            if cls not in ("exact", "soft"):
                raise ValueError(f"unknown identifier class {cls!r}")
            public = bool(entry.get("public_search", False))
            if public and cls != "soft":
                raise ValueError("public_search is only allowed on soft identifiers")
            pattern = _KIND_PATTERNS[entry["kind"]](entry["value"])
            identifiers.append(_Identifier(entry["label"], cls, pattern, public))

        grants: list[_Grant] = []
        if mtimes[1] is not None:
            for entry in json.loads(files[1].read_text(encoding="utf-8")).get("exceptions", []):
                try:
                    expires = _parse_expiry(entry["expires"])
                except (KeyError, ValueError):
                    continue  # an invalid grant is ignored, never widened
                grants.append(_Grant(
                    label=entry["label"],
                    origin=_origin_of(entry["origin"]),
                    op=entry["op"],
                    location=entry["location"],
                    path_prefix=entry.get("path_prefix", "/"),
                    expires=expires,
                ))

        local_endpoints: set[str] = set()
        cookie_origins: set[str] = set()
        attended_only = True
        if mtimes[2] is not None:
            config = json.loads(files[2].read_text(encoding="utf-8"))
            for ep in config.get("local_endpoints", []):
                local_endpoints.add(_canonical_origin(ep["scheme"], ep["host"], int(ep["port"])))
            cookie_origins = {_origin_of(o) for o in config.get("cookie_origins", [])}
            attended_only = config.get("cookies_attended_only", True) is not False

        _cached = _Policy(identifiers, grants, local_endpoints, cookie_origins, mtimes,
                          cookies_attended_only=attended_only)
        return _cached


def cookie_origin_allowed(url: str) -> bool:
    """True when browser cookies may be attached to requests for this URL's origin."""
    try:
        return _origin_of(url) in _load_policy().cookie_origins
    except Exception:
        return False


def login_cookies_allowed(session_kind: str) -> bool:
    """False when logins are limited to attended sessions and this caller isn't one.

    ``cookies_attended_only`` defaults on; an unknown caller counts as
    unattended.
    """
    try:
        return session_kind == "attended" or not _load_policy().cookies_attended_only
    except Exception:
        return False


# --- decoding and matching --------------------------------------------------

def _views(text: str) -> list[str]:
    """Normalized forms of one location's text that matching runs over."""
    views = []
    current = unicodedata.normalize("NFKC", text)
    views.append(current)
    for _ in range(2):
        decoded = unquote(current.replace("+", " "))
        if decoded == current:
            break
        views.append(decoded)
        current = decoded
    unescaped = html.unescape(current)
    if unescaped != current:
        views.append(unescaped)
    for run in _B64_RUN.findall(current):
        padded = run + "=" * (-len(run) % 4)
        for decoder in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                out = decoder(padded).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if out.isprintable():
                views.append(out)
            break
    return views


def _credential_in(text: str) -> bool:
    return any(p.search(v) for v in _views(text) for p in _CREDENTIAL_PATTERNS)


def _identifiers_in(text: str, policy: _Policy) -> list[_Identifier]:
    found = []
    views = _views(text)
    for ident in policy.identifiers:
        if any(ident.pattern.search(v) for v in views):
            found.append(ident)
    return found


def _path_matches(prefix: str, path: str) -> bool:
    prefix = prefix.rstrip("/") or "/"
    if prefix == "/":
        return True
    return path == prefix or path.startswith(prefix + "/")


def _granted(policy: _Policy, ident: _Identifier, location: str, origin: str,
             op: str, path: str) -> bool:
    now = datetime.now(timezone.utc)
    return any(
        g.label == ident.label and g.location == location and g.origin == origin
        and g.op == op and _path_matches(g.path_prefix, path) and g.expires > now
        for g in policy.grants
    )


# --- decisions --------------------------------------------------------------

def _decide(locations: list[tuple[str, str]], *, policy: _Policy, op: str,
            origin: str | None, path: str, session_kind: str, chrome: bool) -> Decision:
    """Decide every occurrence; the first deny wins, then any ask."""
    asks: list[Decision] = []
    for location, text in locations:
        if not text:
            continue
        if _credential_in(text):
            return Decision("deny", "credential")
        for ident in _identifiers_in(text, policy):
            if ident.cls == "exact":
                if origin is not None and _granted(policy, ident, location, origin, op, path):
                    continue
                if chrome and session_kind == "attended":
                    asks.append(Decision("ask", "protected_value", ident.label))
                    continue
                return Decision("deny", "protected_value", ident.label)
            if ident.public_search and op == "search":
                continue
            if session_kind == "attended":
                asks.append(Decision("ask", "soft_identifier", ident.label))
                continue
            return Decision("deny", "soft_identifier", ident.label)
    return asks[0] if asks else ALLOW


def _url_locations(url: str) -> tuple[list[tuple[str, str]], str, str, bool] | Decision:
    """Locations to scan, origin, path, and whether the query is ambiguous.

    A query with a repeated name or a field that isn't name=value (a bare
    flag like ``?download``) is ambiguous: servers may read it differently
    than we split it. It is still scanned, with the raw query added as one
    more location, and ``check_url`` refuses it if anything matches.
    """
    try:
        parts = urlsplit(url)
        _ = parts.port  # raises on a malformed port
    except ValueError:
        return Decision("deny", "ambiguous_request")
    if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
        return Decision("deny", "ambiguous_request")
    if "@" in parts.netloc:
        return Decision("deny", "ambiguous_request")
    ambiguous = False
    try:
        params = parse_qsl(parts.query, keep_blank_values=True, strict_parsing=bool(parts.query))
    except ValueError:
        ambiguous = True
        try:
            params = parse_qsl(parts.query, keep_blank_values=True)
        except ValueError:
            return Decision("deny", "ambiguous_request")
    names = [name for name, _ in params]
    if len(names) != len(set(names)):
        ambiguous = True
    locations = [("host", parts.hostname), ("path", unquote(parts.path))]
    locations += [(f"param:{name}", f"{name}={value}") for name, value in params]
    if ambiguous:
        locations.append(("query", parts.query))
    locations.append(("fragment", parts.fragment))
    origin = _canonical_origin(parts.scheme, parts.hostname, parts.port)
    return locations, origin, parts.path or "/", ambiguous


def _is_private(address: str) -> bool:
    ip = ipaddress.ip_address(address.split("%", 1)[0])
    return not ip.is_global


def resolve_public(host: str, port: int) -> list[str] | Decision:
    """Resolve once and require every address to be public.

    The transport connects to the returned address, so a second lookup cannot
    swap in a private one (DNS rebinding).
    """
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return []
    addresses = [info[4][0] for info in infos]
    if any(_is_private(a) for a in addresses):
        return Decision("deny", "private_destination")
    return addresses


def _host_for_log(host: str | None, decision: Decision) -> str | None:
    """The host, or its hash when it may hold a protected value.

    The host is scanned on its own, because some decisions (an ambiguous
    request, an oversized one) are made before any value matching. If the
    scan can't run, the host is hashed.
    """
    if not host:
        return host
    try:
        hidden = bool(decision.label) or _credential_in(host) or bool(
            _identifiers_in(host, _load_policy()))
    except Exception:
        hidden = True
    if hidden:
        return "sha256:" + hashlib.sha256(host.encode("utf-8")).hexdigest()[:16]
    return host


def _logged(decision: Decision, *, tool: str, op: str, host: str | None) -> Decision:
    host = _host_for_log(host, decision)
    record = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "policy_version": POLICY_VERSION,
        "tool": tool,
        "op": op,
        "origin_host": host,
        "reason_code": decision.reason_code,
        "label": decision.label,
        "action": decision.action,
    }
    try:
        base = policy_dir()
        base.mkdir(parents=True, exist_ok=True)
        with (base / "egress-decisions.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass  # logging must never turn a decision into a crash
    return decision


def _guarded(fn, *, tool: str, op: str, host: str | None, size: int) -> Decision:
    if size > MAX_INPUT_BYTES:
        return _logged(Decision("deny", "oversized_input"), tool=tool, op=op, host=host)
    try:
        decision = fn(_load_policy())
    except Exception:
        decision = Decision("deny", "policy_unavailable")
    return _logged(decision, tool=tool, op=op, host=host)


def check_url(url: str, *, op: str = "fetch", tool: str = "siftfetch",
              session_kind: str = "unattended", chrome: bool = False,
              extra: list[tuple[str, str]] | None = None) -> Decision:
    """Check one outbound URL, plus optional header/body locations."""
    try:
        host = urlsplit(url).hostname
    except ValueError:
        host = None

    def run(policy: _Policy) -> Decision:
        parsed = _url_locations(url)
        if isinstance(parsed, Decision):
            return parsed
        locations, origin, path, ambiguous = parsed
        # A listed local endpoint exempts only the destination; its request
        # content is still scanned like any other.
        if origin not in policy.local_endpoints and _literal_private(host):
            return Decision("deny", "private_destination")
        if ambiguous:
            # No grant applies (it names one field, and a repeated field is
            # read either way), and any match is refused rather than asked.
            decision = _decide(locations + (extra or []), policy=policy, op=op, origin=None,
                               path=path, session_kind=session_kind, chrome=False)
            if decision.reason_code == "credential":
                return decision
            if decision.action != "allow":
                return Decision("deny", "ambiguous_request", decision.label)
            return decision
        return _decide(locations + (extra or []), policy=policy, op=op, origin=origin,
                       path=path, session_kind=session_kind, chrome=chrome)

    return _guarded(run, tool=tool, op=op, host=host, size=len(url) + _size(extra))


def destination_allowed(url: str) -> bool:
    """True when the URL's origin is an owner-listed local endpoint."""
    try:
        return _origin_of(url) in _load_policy().local_endpoints
    except Exception:
        return False


def check_search(query: str, *, tool: str = "siftfetch",
                 session_kind: str = "unattended") -> Decision:
    def run(policy: _Policy) -> Decision:
        return _decide([("query", query)], policy=policy, op="search", origin=None,
                       path="/", session_kind=session_kind, chrome=False)

    return _guarded(run, tool=tool, op="search", host=None, size=len(query))


def check_text(text: str, *, op: str = "api", tool: str, session_kind: str,
               chrome: bool = False) -> Decision:
    """Check free text (a shell command, a browser action) as one location.

    Grants never apply: free text cannot be parsed reliably enough to bind a
    grant to one field at one origin.
    """
    def run(policy: _Policy) -> Decision:
        return _decide([("text", text)], policy=policy, op=op, origin=None, path="/",
                       session_kind=session_kind, chrome=chrome)

    return _guarded(run, tool=tool, op=op, host=None, size=len(text))


def _literal_private(host: str | None) -> bool:
    if not host:
        return False
    try:
        return _is_private(host)
    except ValueError:
        return host.lower().rstrip(".") in ("localhost",) or host.lower().endswith(".localhost")


def _size(extra: list[tuple[str, str]] | None) -> int:
    return sum(len(v) for _, v in extra or [])
