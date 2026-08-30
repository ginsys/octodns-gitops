"""Parse the opt-in `forward_email:` block and the per-domain desired-state files.

Three layers, most general first:

1. Package defaults (`DEFAULT_SETTINGS`, `DEFAULT_EXPECT`, `DEFAULT_ALIAS`) — the only
   layer shared across repos, since each dns-zones repo (and its CI) can only see itself.
2. The `forward_email:` block in the repo's octoDNS `config.yaml` (octoDNS ignores it,
   exactly like `delegation:`): API token env ref, the desired-state directory, repo-level
   default overrides, and the opt-in domain list. **The domain list is the ownership
   boundary** — the reconciler never touches a domain that is not listed.
3. One YAML file per claimed domain under the directory: `settings:` (API-writable domain
   fields only), `expect:` (read-only fields we want drift-checked), `aliases:`.

Field sets below come from Forward Email's server code (`update-domain.js` controller,
`domains.js` / `aliases.js` models), not from its API docs, which omit several.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

# Domain fields the update controller actually reads — the only ones git can enforce.
SETTINGS_FIELDS: frozenset[str] = frozenset(
    {
        "smtp_port",
        "retention_days",
        "bounce_webhook",
        "max_quota_per_alias",
        "alias_default_smtp_limit",
        "has_adult_content_protection",
        "has_phishing_protection",
        "has_executable_protection",
        "has_virus_protection",
        "has_recipient_verification",
        "ignore_mx_check",
        "allow_subdomain_forwarding",
        "has_delivery_logs",
        "require_tls_inbound",
    }
)

# Accepted by PUT but absent from GET: can be sent, never verified.
WRITE_ONLY_SETTINGS: frozenset[str] = frozenset({"bounce_webhook", "max_quota_per_alias"})

# Read-only domain fields worth declaring so drift can be reported. `has_strict_dmarc`
# is deliberately absent: it is derived from DNS and tracked against the zone file.
EXPECT_FIELDS: frozenset[str] = frozenset(
    {"has_smtp", "has_newsletter", "max_recipients_per_alias", "plan"}
)

# Alias fields the alias create/update endpoints accept. `labels` is deliberately absent: the
# server applies it (`catch-all`), so declaring it would plan as clean and do nothing.
SERVER_MANAGED_ALIAS_FIELDS: frozenset[str] = frozenset({"labels"})
ALIAS_FIELDS: frozenset[str] = frozenset(
    {
        "name",
        "recipients",
        "description",
        "is_enabled",
        "error_code_if_disabled",
        "has_imap",
        "has_pgp",
        "public_key",
        "has_recipient_verification",
        "max_quota",
        "vacation_responder",
    }
)

# Scalar types per field. `bool` is checked strictly (it is an `int` subclass in Python), and a
# string where a bool/int belongs is rejected: `"false"` would reach the API verbatim.
_BOOL_SETTINGS = {
    "has_adult_content_protection",
    "has_phishing_protection",
    "has_executable_protection",
    "has_virus_protection",
    "has_recipient_verification",
    "ignore_mx_check",
    "allow_subdomain_forwarding",
    "has_delivery_logs",
    "require_tls_inbound",
}
SETTINGS_TYPES: dict[str, type] = {
    "smtp_port": str,
    "retention_days": int,
    "bounce_webhook": str,
    "max_quota_per_alias": str,
    "alias_default_smtp_limit": int,
    **dict.fromkeys(_BOOL_SETTINGS, bool),
}
EXPECT_TYPES: dict[str, type] = {
    "has_smtp": bool,
    "has_newsletter": bool,
    "max_recipients_per_alias": int,
    "plan": str,
}
ALIAS_TYPES: dict[str, type] = {
    "name": str,
    "recipients": (str, list),
    "description": str,
    "is_enabled": bool,
    "error_code_if_disabled": int,
    "has_imap": bool,
    "has_pgp": bool,
    "public_key": str,
    "has_recipient_verification": bool,
    "max_quota": str,
    "vacation_responder": dict,
}
# Alias fields a repo may default. Per-alias-only fields (quota, key, responder) are excluded:
# a default there would silently be ignored by the reconciler.
ALIAS_DEFAULTABLE: frozenset[str] = frozenset(
    {
        "is_enabled",
        "error_code_if_disabled",
        "has_imap",
        "has_pgp",
        "has_recipient_verification",
        "description",
    }
)

# Decided 2026-08-30 (see the audit plan). `smtp_port` is a *string* on the API.
DEFAULT_SETTINGS: dict = {
    "smtp_port": "25",
    "retention_days": 30,
    "max_quota_per_alias": "1 GB",
    "alias_default_smtp_limit": 0,
    "has_adult_content_protection": True,
    "has_phishing_protection": True,
    "has_executable_protection": True,
    "has_virus_protection": True,
    "has_recipient_verification": False,
    "ignore_mx_check": False,
    "allow_subdomain_forwarding": False,
    "has_delivery_logs": True,
    "require_tls_inbound": True,
}

DEFAULT_EXPECT: dict = {
    "has_smtp": True,
    "has_newsletter": False,
    "max_recipients_per_alias": 10,
    "plan": "team",
}

DEFAULT_ALIAS: dict = {
    "is_enabled": True,
    "error_code_if_disabled": 250,
    "has_imap": False,
    "has_pgp": False,
    "has_recipient_verification": False,
    "description": None,
}

DEFAULT_DIRECTORY = "mail/forward-email"
DEFAULT_TOKEN_ENV = "FORWARD_EMAIL_API_TOKEN"

# Keys of the `forward_email:` block and of its `defaults:` sub-block. Checked like every other
# mapping here: an unknown key is an error, never something silently ignored.
BLOCK_FIELDS: frozenset[str] = frozenset({"token", "directory", "domains", "defaults"})
DEFAULTS_FIELDS: frozenset[str] = frozenset({"settings", "expect", "alias"})


class ForwardEmailConfigError(ValueError):
    """Raised when the block or a domain file is invalid."""


@dataclass(frozen=True)
class ForwardEmailConfig:
    """Resolved repo-level configuration (package defaults merged with repo overrides)."""

    token_env: str
    directory: Path
    domains: list[str]
    settings: dict
    expect: dict
    alias: dict


@dataclass(frozen=True)
class DesiredAlias:
    name: str
    recipients: list[str]
    description: str | None = None
    is_enabled: bool | None = None
    error_code_if_disabled: int | None = None
    has_imap: bool | None = None
    has_pgp: bool | None = None
    public_key: str | None = None
    has_recipient_verification: bool | None = None
    max_quota: str | None = None
    vacation_responder: dict | None = None


@dataclass(frozen=True)
class DesiredDomain:
    domain: str
    settings: dict
    expect: dict
    aliases: list[DesiredAlias]


def _load_yaml(path: Path) -> dict:
    if not path.exists():
        raise ForwardEmailConfigError(f"file not found: {path}")
    try:
        with open(path) as f:
            data = yaml.safe_load(f) or {}
    except (OSError, yaml.YAMLError) as e:
        raise ForwardEmailConfigError(f"{path}: {type(e).__name__}: {e}") from e
    if not isinstance(data, dict):
        raise ForwardEmailConfigError(f"{path}: expected a mapping at top level")
    return data


def _section(where: str, container: dict, key: str) -> dict:
    """An optional mapping-valued key. Absent or `null` is an empty mapping; anything else that is
    not a mapping (`[]`, `false`, a scalar) is an error — never silently "nothing declared", since
    the package defaults would then be enforced from a file the author got wrong."""
    value = container.get(key)
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ForwardEmailConfigError(f"{where}: expected a mapping, got {type(value).__name__} ({value!r})")
    return value


def _check_keys(where: str, given: dict, allowed: frozenset[str]) -> None:
    unknown = sorted(set(given) - allowed)
    if unknown:
        raise ForwardEmailConfigError(f"{where}: unknown or read-only field(s): {', '.join(unknown)}")


def _check_alias_keys(where: str, given: dict, allowed: frozenset[str]) -> None:
    """Like `_check_keys`, but a server-managed field gets its own message: accepting it would
    plan as clean while doing nothing, and "unknown" would send the reader looking for a typo."""
    managed = sorted(set(given) & SERVER_MANAGED_ALIAS_FIELDS)
    if managed:
        raise ForwardEmailConfigError(
            f"{where}: {', '.join(managed)} is server-managed by Forward Email and cannot be declared"
        )
    _check_keys(where, given, allowed)


def _check_types(where: str, given: dict, types: dict) -> None:
    for k, v in given.items():
        want = types.get(k)
        if want is None:
            continue
        if want is bool:
            ok = isinstance(v, bool)
        else:
            ok = isinstance(v, want) and not isinstance(v, bool)
        if not ok:
            names = "/".join(t.__name__ for t in (want if isinstance(want, tuple) else (want,)))
            raise ForwardEmailConfigError(f"{where}: {k} must be {names}, got {type(v).__name__} ({v!r})")


def _normalize_domain(name) -> str:
    if not isinstance(name, str) or not name.strip():
        raise ForwardEmailConfigError(f"forward_email.domains: entries must be non-empty strings, got {name!r}")
    return name.strip().rstrip(".").lower()


def load_forward_email(config_path: str) -> ForwardEmailConfig | None:
    """Parse the `forward_email:` block. Returns None when the repo has not opted in."""
    cfg_file = Path(config_path)
    cfg = _load_yaml(cfg_file)
    if "forward_email" not in cfg:
        return None
    # The key itself is the opt-in: a present-but-empty block is a broken config, never an opt-out.
    block = cfg["forward_email"]
    if not isinstance(block, dict) or not block:
        raise ForwardEmailConfigError(
            "forward_email: expected a non-empty mapping (remove the key entirely to opt out)"
        )
    # A misspelled key (`defualts:`) must not silently fall back to the package defaults.
    _check_keys("forward_email", block, BLOCK_FIELDS)

    token = block.get("token", f"env/{DEFAULT_TOKEN_ENV}")
    if not isinstance(token, str) or not token.startswith("env/") or len(token) <= 4:
        raise ForwardEmailConfigError(
            "forward_email.token must be an env/VAR reference (never a literal secret)"
        )
    token_env = token[len("env/") :]

    raw_directory = block.get("directory", DEFAULT_DIRECTORY)
    if not isinstance(raw_directory, str) or not raw_directory.strip():
        raise ForwardEmailConfigError(f"forward_email.directory must be a non-empty string, got {raw_directory!r}")
    directory = Path(raw_directory)
    if not directory.is_absolute():
        directory = cfg_file.resolve().parent / directory

    raw_domains = block.get("domains") or []
    if not isinstance(raw_domains, list) or not raw_domains:
        raise ForwardEmailConfigError("forward_email.domains must be a non-empty list")
    domains: list[str] = []
    for d in raw_domains:
        n = _normalize_domain(d)
        if n in domains:
            raise ForwardEmailConfigError(f"forward_email.domains: duplicate entry {n!r}")
        domains.append(n)

    defaults = _section("forward_email.defaults", block, "defaults")
    _check_keys("forward_email.defaults", defaults, DEFAULTS_FIELDS)
    settings_over = _section("forward_email.defaults.settings", defaults, "settings")
    expect_over = _section("forward_email.defaults.expect", defaults, "expect")
    alias_over = _section("forward_email.defaults.alias", defaults, "alias")
    _check_keys("forward_email.defaults.settings", settings_over, SETTINGS_FIELDS)
    _check_keys("forward_email.defaults.expect", expect_over, EXPECT_FIELDS)
    _check_alias_keys("forward_email.defaults.alias", alias_over, ALIAS_DEFAULTABLE)
    _check_types("forward_email.defaults.settings", settings_over, SETTINGS_TYPES)
    _check_types("forward_email.defaults.expect", expect_over, EXPECT_TYPES)
    _check_types("forward_email.defaults.alias", alias_over, ALIAS_TYPES)

    return ForwardEmailConfig(
        token_env=token_env,
        directory=directory,
        domains=domains,
        settings={**DEFAULT_SETTINGS, **settings_over},
        expect={**DEFAULT_EXPECT, **expect_over},
        alias={**DEFAULT_ALIAS, **alias_over},
    )


def _as_list(where: str, value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(v, str) for v in value):
        return list(value)
    raise ForwardEmailConfigError(f"{where}: expected a string or a list of strings, got {value!r}")


def load_domain_file(path: Path, domain: str) -> DesiredDomain:
    """Parse one per-domain desired-state file for `domain` (bare, lowercase)."""
    data = _load_yaml(Path(path))
    declared = data.get("domain")
    if declared is not None and _normalize_domain(declared) != domain:
        raise ForwardEmailConfigError(
            f"{path}: domain key {declared!r} does not match file domain {domain!r}"
        )
    _check_keys(f"{path}", data, frozenset({"domain", "settings", "expect", "aliases"}))

    settings = _section(f"{path}: settings", data, "settings")
    expect = _section(f"{path}: expect", data, "expect")
    _check_keys(f"{path}: settings", settings, SETTINGS_FIELDS)
    _check_keys(f"{path}: expect", expect, EXPECT_FIELDS)
    _check_types(f"{path}: settings", settings, SETTINGS_TYPES)
    _check_types(f"{path}: expect", expect, EXPECT_TYPES)

    raw_aliases = data.get("aliases")
    if raw_aliases is None:
        raw_aliases = []
    if not isinstance(raw_aliases, list):
        raise ForwardEmailConfigError(f"{path}: aliases must be a list")

    aliases: list[DesiredAlias] = []
    seen: set[str] = set()
    for i, raw in enumerate(raw_aliases):
        if not isinstance(raw, dict) or "name" not in raw:
            raise ForwardEmailConfigError(f"{path}: aliases[{i}] needs a name")
        where = f"{path}: alias {raw['name']!r}"
        _check_alias_keys(where, raw, ALIAS_FIELDS)
        _check_types(where, raw, ALIAS_TYPES)
        name = raw["name"]
        if name in seen:
            raise ForwardEmailConfigError(f"{path}: duplicate alias {name!r}")
        seen.add(name)
        aliases.append(
            DesiredAlias(
                name=name,
                recipients=_as_list(f"{where}: recipients", raw.get("recipients")),
                description=raw.get("description"),
                is_enabled=raw.get("is_enabled"),
                error_code_if_disabled=raw.get("error_code_if_disabled"),
                has_imap=raw.get("has_imap"),
                has_pgp=raw.get("has_pgp"),
                public_key=raw.get("public_key"),
                has_recipient_verification=raw.get("has_recipient_verification"),
                max_quota=raw.get("max_quota"),
                vacation_responder=raw.get("vacation_responder"),
            )
        )

    return DesiredDomain(domain=domain, settings=dict(settings), expect=dict(expect), aliases=aliases)
