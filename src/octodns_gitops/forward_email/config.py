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

from dataclasses import dataclass, field
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

# Alias fields the alias create/update endpoints accept.
ALIAS_FIELDS: frozenset[str] = frozenset(
    {
        "name",
        "recipients",
        "description",
        "labels",
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
    "labels": [],
}

DEFAULT_DIRECTORY = "mail/forward-email"
DEFAULT_TOKEN_ENV = "FORWARD_EMAIL_API_TOKEN"


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
    labels: list[str] = field(default_factory=list)
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
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    if not isinstance(data, dict):
        raise ForwardEmailConfigError(f"{path}: expected a mapping at top level")
    return data


def _check_keys(where: str, given: dict, allowed: frozenset[str]) -> None:
    unknown = sorted(set(given) - allowed)
    if unknown:
        raise ForwardEmailConfigError(f"{where}: unknown or read-only field(s): {', '.join(unknown)}")


def _normalize_domain(name: str) -> str:
    return str(name).strip().rstrip(".").lower()


def load_forward_email(config_path: str) -> ForwardEmailConfig | None:
    """Parse the `forward_email:` block. Returns None when the repo has not opted in."""
    cfg_file = Path(config_path)
    cfg = _load_yaml(cfg_file)
    block = cfg.get("forward_email")
    if not block:
        return None
    if not isinstance(block, dict):
        raise ForwardEmailConfigError("forward_email: expected a mapping")

    token = block.get("token", f"env/{DEFAULT_TOKEN_ENV}")
    if not isinstance(token, str) or not token.startswith("env/") or len(token) <= 4:
        raise ForwardEmailConfigError(
            "forward_email.token must be an env/VAR reference (never a literal secret)"
        )
    token_env = token[len("env/") :]

    directory = Path(block.get("directory", DEFAULT_DIRECTORY))
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

    defaults = block.get("defaults") or {}
    if not isinstance(defaults, dict):
        raise ForwardEmailConfigError("forward_email.defaults: expected a mapping")
    settings_over = defaults.get("settings") or {}
    expect_over = defaults.get("expect") or {}
    alias_over = defaults.get("alias") or {}
    _check_keys("forward_email.defaults.settings", settings_over, SETTINGS_FIELDS)
    _check_keys("forward_email.defaults.expect", expect_over, EXPECT_FIELDS)
    _check_keys("forward_email.defaults.alias", alias_over, ALIAS_FIELDS - {"name", "recipients"})

    return ForwardEmailConfig(
        token_env=token_env,
        directory=directory,
        domains=domains,
        settings={**DEFAULT_SETTINGS, **settings_over},
        expect={**DEFAULT_EXPECT, **expect_over},
        alias={**DEFAULT_ALIAS, **alias_over},
    )


def _as_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    raise ForwardEmailConfigError(f"expected a string or list, got {type(value).__name__}")


def load_domain_file(path: Path, domain: str) -> DesiredDomain:
    """Parse one per-domain desired-state file for `domain` (bare, lowercase)."""
    data = _load_yaml(Path(path))
    declared = data.get("domain")
    if declared is not None and _normalize_domain(declared) != domain:
        raise ForwardEmailConfigError(
            f"{path}: domain key {declared!r} does not match file domain {domain!r}"
        )
    _check_keys(f"{path}", data, frozenset({"domain", "settings", "expect", "aliases"}))

    settings = data.get("settings") or {}
    expect = data.get("expect") or {}
    _check_keys(f"{path}: settings", settings, SETTINGS_FIELDS)
    _check_keys(f"{path}: expect", expect, EXPECT_FIELDS)

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
        _check_keys(f"{path}: alias {raw['name']!r}", raw, ALIAS_FIELDS)
        name = str(raw["name"])
        if name in seen:
            raise ForwardEmailConfigError(f"{path}: duplicate alias {name!r}")
        seen.add(name)
        aliases.append(
            DesiredAlias(
                name=name,
                recipients=_as_list(raw.get("recipients")),
                description=raw.get("description"),
                labels=_as_list(raw.get("labels")),
                is_enabled=raw.get("is_enabled"),
                error_code_if_disabled=raw.get("error_code_if_disabled"),
                has_imap=raw.get("has_imap"),
                has_pgp=raw.get("has_pgp"),
                public_key=raw.get("public_key"),
                has_recipient_verification=raw.get("has_recipient_verification"),
                max_quota=None if raw.get("max_quota") is None else str(raw["max_quota"]),
                vacation_responder=raw.get("vacation_responder"),
            )
        )

    return DesiredDomain(domain=domain, settings=dict(settings), expect=dict(expect), aliases=aliases)
