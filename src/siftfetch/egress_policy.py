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
import warnings
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, unquote, urlsplit

POLICY_VERSION = "egress-1"
API_VERSION = 1

# A request larger than this is not scanned; it is denied. Real search queries
# and URLs are far smaller, and an unbounded input would make the decoder an
# easy way to stall the transport.
MAX_INPUT_BYTES = 1_000_000

# Runs this long are plausible base64 payloads; shorter ones are mostly words
# and identifiers that decode to noise.
_B64_RUN = re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}")

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
    "could_not_check": "Could not check all encoded content; send less at once.",
    "oversized_input": "The request is too large to check; send a smaller request.",
    "private_destination": (
        "Private, loopback and link-local destinations are not reachable "
        "through this route."
    ),
    "destination_unconfirmed": "Couldn't confirm the address is public; retry the request.",
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
    sensitive_host: bool = field(default=False, compare=False, repr=False)

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
    command_prefix: str = ""


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


class PolicyError(ValueError):
    """A policy file or field is invalid; never includes its value."""


def validate_policy(name: str, data: object) -> dict:
    def require(ok, field):
        if not ok:
            raise PolicyError(f"{name}: {field} is invalid")

    require(isinstance(data, dict), "root")
    if name == "identifiers.json":
        require(isinstance(data.get("values"), list), "values")
        for i, entry in enumerate(data["values"]):
            field = f"values[{i}]"
            require(isinstance(entry, dict), field)
            for key in ("label", "value"):
                require(isinstance(entry.get(key), str), field + "." + key)
            require(isinstance(entry.get("kind"), str) and entry["kind"] in _KIND_PATTERNS, field + ".kind")
            require(entry.get("class") in ("exact", "soft"), field + ".class")
            if "public_search" in entry:
                require(type(entry["public_search"]) is bool, field + ".public_search")
                require(not entry["public_search"] or entry["class"] == "soft", field + ".public_search")
            if "match" in entry:
                require(entry["match"] in ("word", "substring"), field + ".match")
            try:
                identifier_pattern(entry["kind"], entry["value"])
            except (ValueError, KeyError):
                require(False, field + ".value")
    elif name == "exceptions.json":
        require(isinstance(data.get("exceptions"), list), "exceptions")
        valid = []
        for entry in data["exceptions"]:
            try:
                if not isinstance(entry, dict):
                    raise ValueError
                keys = ("label", "op", "command_prefix", "expires") if entry.get("op") == "shell" else (
                    "label", "origin", "op", "location", "expires")
                if not all(isinstance(entry.get(k), str) for k in keys):
                    raise ValueError
                if entry.get("op") == "shell":
                    if not entry["command_prefix"].strip() or not _single_command(entry["command_prefix"]):
                        raise ValueError
                    _parse_expiry(entry["expires"])
                    valid.append(entry)
                    continue
                if not isinstance(entry.get("path_prefix", "/"), str):
                    raise ValueError
                _parse_expiry(entry["expires"])
                parts = urlsplit(entry["origin"])
                if parts.scheme not in ("http", "https") or not parts.hostname or parts.username:
                    raise ValueError
                _ = parts.port
            except (ValueError, TypeError):
                continue
            valid.append(entry)
        count = len(data["exceptions"]) - len(valid)
        if count:
            warnings.warn(f"exceptions.json: ignored {count} invalid grants", stacklevel=2)
        data = dict(data, exceptions=valid)
    elif name == "config.json":
        if "guard_lock" in data:
            lock = data["guard_lock"]
            require(type(lock) is bool or isinstance(lock, dict), "guard_lock")
            if isinstance(lock, dict):
                require(type(lock.get("enabled", True)) is bool, "guard_lock.enabled")
                paths = lock.get("paths", [])
                require(isinstance(paths, list) and all(isinstance(p, str) for p in paths), "guard_lock.paths")
        if "secret_file_mode" in data:
            require(data["secret_file_mode"] in SECRET_FILE_MODES, "secret_file_mode")
        if "cookies_attended_only" in data:
            require(type(data["cookies_attended_only"]) is bool, "cookies_attended_only")
        for key in ("cookie_origins", "mcp_local_tools"):
            if key in data:
                require(isinstance(data[key], list) and all(isinstance(v, str) for v in data[key]), key)
        for i, origin in enumerate(data.get("cookie_origins", [])):
            try:
                parts = urlsplit(origin)
                require(parts.scheme in ("http", "https") and bool(parts.hostname)
                        and not parts.username, f"cookie_origins[{i}]")
                _ = parts.port
            except ValueError:
                require(False, f"cookie_origins[{i}]")
        if "local_endpoints" in data:
            require(isinstance(data["local_endpoints"], list), "local_endpoints")
            for i, ep in enumerate(data["local_endpoints"]):
                field = f"local_endpoints[{i}]"
                require(isinstance(ep, dict), field)
                require(ep.get("scheme") in ("http", "https"), field + ".scheme")
                require(isinstance(ep.get("host"), str) and bool(ep["host"]), field + ".host")
                require(type(ep.get("port")) is int and 0 < ep["port"] <= 65535, field + ".port")
    return data


def _read_policy(name: str, optional: bool = False) -> dict:
    try:
        data = json.loads((policy_dir() / name).read_text(encoding="utf-8"))
    except FileNotFoundError:
        if optional:
            return {"exceptions": []} if name == "exceptions.json" else {}
        raise PolicyError(f"{name}: file is missing") from None
    except (OSError, ValueError):
        raise PolicyError(f"{name}: file could not be read") from None
    return validate_policy(name, data)


def _config() -> dict:
    return _read_policy("config.json", optional=True)


def secret_file_mode() -> str:
    """How many shell routes to a dotenv file's contents are blocked.

    ``strict`` (the default) blocks printing, redirects, loading and copying;
    ``standard`` blocks printing and redirects; ``off`` blocks nothing.
    Anything missing or invalid means ``strict``: the owner loosens the mode
    on purpose, never by accident.
    """
    try:
        mode = _config().get("secret_file_mode", "strict")
    except PolicyError:
        return "strict"
    return mode if mode in SECRET_FILE_MODES else "strict"


# The guard's own settings: hook registration and deny rules, the hook
# scripts, and Codex config. Matched anywhere in a path, so every project's
# .claude/settings.json is covered too.
GUARD_LOCK_PATHS = (
    ".mcp.json",
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

    With valid identifiers, a missing optional config means the lock is off.
    A config that exists but can't
    be read, or a ``guard_lock`` value that is neither off nor a valid
    lock, fails closed: the built-in paths stay locked and the second item
    names the cause, so the owner can fix it.
    """
    path = policy_dir() / "config.json"
    try:
        _read_policy("identifiers.json")
    except PolicyError as exc:
        return list(GUARD_LOCK_PATHS), f"{exc} in {policy_dir()}"
    if not path.exists():
        return [], None
    builtin = list(GUARD_LOCK_PATHS)
    try:
        config = _config()
    except PolicyError as exc:
        return builtin, str(exc)
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
    try:
        alias = os.environ.get("SIFTFETCH_CONTACT_ALIAS") or _config().get("contact_alias")
    except PolicyError:
        return None
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
    local_pattern = re.escape(local)
    if domain.lower() in ("gmail.com", "googlemail.com"):
        local_pattern = r"\.?".join(re.escape(c) for c in local.replace(".", ""))
        domain_pattern = r"(?:gmail|googlemail)" + dot + "com"
    tag = r"(?:\+[^\s@]{1,128})?"
    return re.compile(local_pattern + tag + at + domain_pattern, re.IGNORECASE)


def _phone_pattern(value: str) -> re.Pattern:
    digits = re.sub(r"\D", "", value)
    if len(digits) == 11 and digits.startswith("1"):
        digits = digits[1:]
    if len(digits) != 10:
        raise ValueError("phone identifier needs 10 digits")
    body = r"[\s.\-()/_,]{0,3}".join(digits)
    return re.compile(body)


def _text_pattern(value: str) -> re.Pattern:
    tokens = value.split()
    if not tokens:
        raise ValueError("text identifier is empty")
    body = _SEP.join(re.escape(t) for t in tokens)
    return re.compile(r"(?<![A-Za-z0-9])" + body + r"(?![A-Za-z0-9])", re.IGNORECASE)


_KIND_PATTERNS = {"email": _email_pattern, "phone": _phone_pattern, "text": _text_pattern}


def identifier_pattern(kind: str, value: str, match: str = "auto") -> re.Pattern:
    """Compile an identifier using the versioned matching API."""
    if match not in ("auto", "word", "substring"):
        raise ValueError("unknown match mode")
    pattern = _KIND_PATTERNS[kind](value)
    if kind == "text" and (match == "substring" or
                           match == "auto" and sum(c.isalnum() for c in value) >= 8):
        return re.compile(_SEP.join(re.escape(t) for t in value.split()), re.IGNORECASE)
    if match == "word" and kind != "text":
        return re.compile(r"(?<![A-Za-z0-9])(?:" + pattern.pattern + r")(?![A-Za-z0-9])",
                          pattern.flags)
    return pattern


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

        raw_ids = _read_policy("identifiers.json")
        identifiers = []
        for entry in raw_ids["values"]:
            cls = entry["class"]
            if cls not in ("exact", "soft"):
                raise ValueError(f"unknown identifier class {cls!r}")
            public = bool(entry.get("public_search", False))
            if public and cls != "soft":
                raise ValueError("public_search is only allowed on soft identifiers")
            pattern = identifier_pattern(entry["kind"], entry["value"],
                                         "word" if cls == "soft" else entry.get("match", "auto"))
            identifiers.append(_Identifier(entry["label"], cls, pattern, public))

        grants: list[_Grant] = []
        if mtimes[1] is not None:
            for entry in _read_policy("exceptions.json")["exceptions"]:
                try:
                    expires = _parse_expiry(entry["expires"])
                except (KeyError, ValueError):
                    continue  # an invalid grant is ignored, never widened
                grants.append(_Grant(
                    label=entry["label"],
                    origin="" if entry["op"] == "shell" else _origin_of(entry["origin"]),
                    op=entry["op"],
                    location=entry.get("location", ""),
                    path_prefix=entry.get("path_prefix", "/"),
                    expires=expires,
                    command_prefix=entry.get("command_prefix", ""),
                ))

        local_endpoints: set[str] = set()
        cookie_origins: set[str] = set()
        attended_only = True
        if mtimes[2] is not None:
            config = _config()
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

MAX_DECODE_BYTES = 4 * 1024 * 1024


@dataclass
class DecodeResult:
    views: list[str]
    complete: bool
    _used: int = field(default=0, repr=False)


def _normalized(text: str) -> str:
    text = unicodedata.normalize("NFKC", html.unescape(unquote(text)))
    return "".join(c for c in text if unicodedata.category(c) != "Cf")


def decoded_views(text: str, budget: int | None = None) -> DecodeResult:
    """Raw and recursively decoded views, bounded to three decoding levels.

    The budget counts decoded candidate bytes, including non-text candidates.
    Callers must refuse an incomplete result rather than treating it as clean.
    """
    limit = MAX_DECODE_BYTES if budget is None else max(0, budget)
    result = DecodeResult([text], True)
    seen = {text}
    pending = [(text, 0)]
    tried = set()

    def add(value, depth):
        if value not in seen:
            seen.add(value)
            result.views.append(value)
            pending.append((value, depth))

    for current, depth in pending:
        if depth >= 3:
            continue
        normal = _normalized(current)
        if normal != current:
            cost = len(normal.encode("utf-8"))
            if result._used + cost > limit:
                result.complete = False
                return result
            result._used += cost
            add(normal, depth + 1)
        for source in dict.fromkeys((current, normal)):
            for pattern, encoding in ((_B64_RUN, "base64"),
                                      (re.compile(r"[0-9a-fA-F]{24,}"), "hex"),
                                      (re.compile(r"[A-Z2-7]{16,}={0,6}", re.I), "base32")):
                for match in pattern.finditer(source):
                    run = match.group()
                    pieces = [run]
                    if encoding == "base64":
                        pieces += [p for p in run.split("/") if len(p) >= 12]
                    for piece in pieces:
                        for start in range(0, len(piece), 3072):
                            candidate = piece[start:start + 4096]
                            key = (encoding, candidate)
                            if key in tried:
                                continue
                            tried.add(key)
                            try:
                                if encoding == "hex":
                                    if len(candidate) % 2:
                                        continue
                                    raw = bytes.fromhex(candidate)
                                elif encoding == "base32":
                                    candidate = candidate.rstrip("=")
                                    raw = base64.b32decode(candidate + "=" * (-len(candidate) % 8), casefold=True)
                                else:
                                    candidate = candidate.rstrip("=")
                                    raw = base64.b64decode(candidate + "=" * (-len(candidate) % 4), altchars=b"-_")
                            except (ValueError, binascii.Error):
                                continue
                            result._used += len(raw)
                            if result._used > limit:
                                result.complete = False
                                return result
                            try:
                                decoded = raw.decode("utf-8")
                            except UnicodeDecodeError:
                                continue
                            clean = "".join(c for c in decoded if ord(c) >= 32 and
                                            unicodedata.category(c) != "Cf")
                            if clean and sum(c.isprintable() for c in clean) / len(clean) >= .85:
                                add(decoded, depth + 1)
                                add(clean, depth + 1)
    return result


def _location_texts(location: str, text: str):
    yield text
    leaves = []
    if location == "body":
        try:
            def walk(value):
                if isinstance(value, str):
                    leaves.append(value)
                elif isinstance(value, dict):
                    for item in value.values():
                        walk(item)
                elif isinstance(value, list):
                    for item in value:
                        walk(item)
            walk(json.loads(text))
        except (ValueError, RecursionError):
            pass
    elif location.startswith(("header:", "param:")):
        leaves.append(text)
    for leaf in leaves:
        yield leaf
        if len(leaf) < 64 * 1024:
            normal = _normalized(leaf)
            yield re.sub(r"[^A-Za-z0-9+/_=-]", "", normal)


def _credential_in(text: str) -> bool:
    return any(p.search(v) for v in decoded_views(text).views for p in _CREDENTIAL_PATTERNS)


def _identifiers_in(text: str, policy: _Policy) -> list[_Identifier]:
    found = []
    views = decoded_views(text).views
    for ident in policy.identifiers:
        if any(ident.pattern.search(v) for v in views):
            found.append(ident)
    return found


def _plain_path(path: str) -> bool:
    """False when the path the server acts on may differ from this text.

    Clients and servers resolve ``.`` and ``..`` segments (also when
    percent-encoded) and some decode ``%2f`` or treat ``\\`` as a slash, so
    a grant's path prefix is only compared against a path with none of them.
    """
    decoded = unquote(path)
    if "\\" in decoded or decoded.count("/") != path.count("/"):
        return False
    return not any(seg in (".", "..") for seg in decoded.split("/"))


def _path_matches(prefix: str, path: str) -> bool:
    if not _plain_path(path):
        return False
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


def _single_command(command: str) -> bool:
    return not re.search(r"[;|<>&`\r\n]|\$\(", command)


def _shell_granted(policy: _Policy, ident: _Identifier, command: str) -> bool:
    if not _single_command(command):
        return False
    command = command.strip()
    return any(g.op == "shell" and g.label == ident.label and g.command_prefix
               and command.startswith(g.command_prefix)
               and (len(command) == len(g.command_prefix) or command[len(g.command_prefix)].isspace())
               and g.expires > datetime.now(timezone.utc) for g in policy.grants)


# --- decisions --------------------------------------------------------------

def _decide(locations: list[tuple[str, str]], *, policy: _Policy, op: str,
            origin: str | None, path: str, session_kind: str, interactive_ask: bool,
            exact_only: bool = False, command: str | None = None) -> Decision:
    """Decide every occurrence; the first deny wins, then any ask."""
    asks: list[Decision] = []
    sensitive_host = False
    remaining = MAX_DECODE_BYTES
    cache = {}
    for location, text in locations:
        if not text:
            continue
        views = []
        for candidate in _location_texts(location, text):
            if candidate not in cache:
                decoded = decoded_views(candidate, remaining)
                if not decoded.complete:
                    return Decision("deny", "could_not_check")
                remaining -= decoded._used
                cache[candidate] = decoded.views
            views.extend(cache[candidate])
        if any(p.search(v) for v in views for p in _CREDENTIAL_PATTERNS):
            return Decision("deny", "credential")
        for ident in policy.identifiers:
            if exact_only and ident.cls == "soft":
                continue
            if not any(ident.pattern.search(v) for v in views):
                continue
            sensitive_host |= location == "host"
            if op == "shell" and command is not None and _shell_granted(policy, ident, command) and all(
                    other.label == ident.label or not any(other.pattern.search(v) for v in views)
                    for other in policy.identifiers):
                continue
            if ident.cls == "exact":
                if origin is not None and _granted(policy, ident, location, origin, op, path):
                    continue
                if interactive_ask and session_kind == "attended":
                    asks.append(Decision("ask", "protected_value", ident.label))
                    continue
                return Decision("deny", "protected_value", ident.label)
            if ident.public_search and op == "search":
                continue
            if session_kind == "attended":
                asks.append(Decision("ask", "soft_identifier", ident.label))
                continue
            return Decision("deny", "soft_identifier", ident.label)
    return asks[0] if asks else Decision("allow", sensitive_host=sensitive_host)


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
    locations += [(f"param:{name}", value) for name, value in params]
    locations += [("param-name", name) for name, _ in params]
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

    Reuse the host sensitivity retained by matching. Rejections made before
    matching also hash the host, without running a second decode pass.
    """
    if not host:
        return host
    hidden = decision.sensitive_host or bool(decision.label) or decision.action != "allow"
    if hidden:
        return "sha256:" + hashlib.sha256(host.encode("utf-8")).hexdigest()[:16]
    return host


def _logged(decision: Decision, *, tool: str, op: str, host: str | None) -> Decision:
    if decision.action == "allow" and (op == "shell" or tool.startswith("mcp__")):
        return decision
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
        if not base.is_dir():
            return decision
        with (base / "egress-decisions.jsonl").open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass  # logging must never turn a decision into a crash
    return decision


def _guarded(fn, *, tool: str, op: str, host: str | None, size: int,
             log: bool = True) -> Decision:
    if size > MAX_INPUT_BYTES:
        decision = Decision("deny", "oversized_input")
    else:
        try:
            decision = fn(_load_policy())
        except PolicyError as exc:
            decision = Decision("deny", "policy_unavailable", str(exc))
        except Exception:
            decision = Decision("deny", "policy_unavailable")
    return _logged(decision, tool=tool, op=op, host=host) if log else decision


def check_url(url: str, *, op: str = "fetch", tool: str = "siftfetch",
              session_kind: str = "unattended", chrome: bool = False,
              extra: list[tuple[str, str]] | None = None,
              resolve_host: bool = False) -> Decision:
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
                               path=path, session_kind=session_kind, interactive_ask=False)
            if decision.reason_code in ("credential", "could_not_check"):
                return decision
            if decision.action != "allow":
                return Decision("deny", "ambiguous_request", decision.label)
            if resolve_host and origin not in policy.local_endpoints:
                parts = urlsplit(url)
                destination = _hook_destination(host, parts.port or (443 if parts.scheme == "https" else 80))
                return decision if destination.action == "allow" else destination
            return decision
        decision = _decide(locations + (extra or []), policy=policy, op=op, origin=origin,
                           path=path, session_kind=session_kind, interactive_ask=chrome)
        if decision.action != "allow":
            return decision
        if resolve_host and origin not in policy.local_endpoints:
            destination = _hook_destination(host, urlsplit(url).port or (443 if url.startswith("https:") else 80))
            return decision if destination.action == "allow" else destination
        return decision

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
                       path="/", session_kind=session_kind, interactive_ask=False)

    return _guarded(run, tool=tool, op="search", host=None, size=len(query))


def check_text(text: str, *, op: str = "api", tool: str, session_kind: str,
               chrome: bool = False, log: bool = True, exact_only: bool = False,
               interactive_ask: bool = False) -> Decision:
    """Check free text (a shell command, a browser action) as one location.

    Only restricted shell-prefix grants apply to shell operations; origin
    grants cannot be bound to free text. ``log=False`` skips the decision log,
    for checks of local files that are not outbound requests.
    """
    def run(policy: _Policy) -> Decision:
        return _decide([("text", text)], policy=policy, op=op, origin=None, path="/",
                       session_kind=session_kind, interactive_ask=chrome or interactive_ask, exact_only=exact_only,
                       command=text if op == "shell" else None)

    return _guarded(run, tool=tool, op=op, host=None, size=len(text), log=log)



def check_mcp(payload: dict, *, tool: str, session_kind: str) -> Decision:
    """Check string leaves under one shared budget, including URL locations."""
    browser_driver = tool.startswith(("mcp__claude-in-chrome__", "mcp__Claude_Browser__"))
    locations = []
    urls = []
    soft = False

    def walk(value):
        nonlocal soft
        if isinstance(value, str):
            locations.append(("header:mcp-leaf", value))
            if value.startswith(("http://", "https://")):
                urls.append(value)
        elif isinstance(value, dict):
            soft |= any(str(k).lower().endswith(("url", "recipient", "email", "body")) for k in value)
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)
    walk(payload)

    def run(policy):
        for url in urls:
            parsed = _url_locations(url)
            if isinstance(parsed, Decision):
                return parsed
            parts, origin, _, _ = parsed
            locations.extend(parts)
            if not browser_driver and origin not in policy.local_endpoints and _literal_private(urlsplit(url).hostname):
                return Decision("deny", "private_destination")
        return _decide(locations, policy=policy, op="mcp", origin=None, path="/",
                       session_kind=session_kind, interactive_ask=True, exact_only=not soft)

    return _guarded(run, tool=tool, op="mcp", host=None, size=_size(locations))

def _literal_private(host: str | None) -> bool:
    if not host:
        return False
    try:
        host = socket.inet_ntoa(socket.inet_aton(host))
    except OSError:
        pass
    try:
        return _is_private(host)
    except ValueError:
        return host.lower().rstrip(".") in ("localhost",) or host.lower().endswith(".localhost")


_HOOK_DNS_TIMEOUT = 1.0


def _hook_destination(host: str, port: int) -> Decision:
    result = []
    done = threading.Event()

    def resolve():
        try:
            result.append(resolve_public(host, port))
        except Exception:
            pass
        finally:
            done.set()

    threading.Thread(target=resolve, daemon=True).start()
    if not done.wait(_HOOK_DNS_TIMEOUT) or not result or not result[0]:
        return Decision("deny", "destination_unconfirmed")
    return result[0] if isinstance(result[0], Decision) else ALLOW


def _size(extra: list[tuple[str, str]] | None) -> int:
    return sum(len(v) for _, v in extra or [])
