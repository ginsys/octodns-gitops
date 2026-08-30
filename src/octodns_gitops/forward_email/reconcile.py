"""Diff desired state (git) against live state (API) for one domain.

Pure functions: no I/O. The CLI fetches, calls `plan_domain`, prints, and applies.

Rules that are easy to get wrong, all decided in the 2026-08-30 audit:

- Settings equal to the resolved default are still *enforced* — the default is desired state,
  not "don't care". Only the file omits them.
- Write-only settings (`WRITE_ONLY_SETTINGS`) cannot be read back, so they never create a diff
  on their own; they ride along in every domain PUT that a verifiable change triggers.
- Alias `max_quota` is bytes on GET and a human string on PUT; absent on GET means "domain
  default". A live value differing from the desired one is reset with a blank PUT.
- `labels` is server-applied (`catch-all`): never compared here, rejected by the config loader.
- A prune never deletes an alias with `has_imap` or stored mail: that is a mailbox. Such an
  alias missing from git is an error that blocks the run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .config import (
    EXPECT_FIELDS,
    SETTINGS_FIELDS,
    WRITE_ONLY_SETTINGS,
    DesiredAlias,
    DesiredDomain,
    ForwardEmailConfig,
)

_UNITS = {"B": 1, "KB": 1024, "MB": 1024**2, "GB": 1024**3, "TB": 1024**4}
_QUOTA_RE = re.compile(r"^\s*(\d+(?:\.\d+)?)\s*([KMGT]?B)\s*$", re.IGNORECASE)


def parse_quota(value: str | int) -> int:
    """'1 GB' -> bytes, 1024-based (matches the `bytes` package Forward Email uses)."""
    if isinstance(value, int):
        return value
    m = _QUOTA_RE.match(str(value))
    if not m:
        raise ValueError(f"unparseable quota {value!r} (expected e.g. '1 GB')")
    return int(float(m.group(1)) * _UNITS[m.group(2).upper()])


@dataclass(frozen=True)
class SettingChange:
    field: str
    live: object
    desired: object


@dataclass(frozen=True)
class AliasChange:
    action: str  # create | update | delete
    name: str
    alias_id: str | None
    body: dict
    changes: list[str] = field(default_factory=list)


@dataclass
class DomainPlan:
    domain: str
    settings: list[SettingChange] = field(default_factory=list)
    write_only: dict = field(default_factory=dict)
    aliases: list[AliasChange] = field(default_factory=list)
    unmanaged: list[str] = field(default_factory=list)
    expect_mismatch: list[SettingChange] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    # ids seen in the listing the plan was built from; the apply path re-lists before a prune
    live_alias_ids: set = field(default_factory=set)

    def is_empty(self) -> bool:
        """Nothing to write and nothing wrong. `unmanaged` alone is informational."""
        return not (self.settings or self.aliases or self.expect_mismatch or self.errors)

    def settings_body(self) -> dict:
        if not self.settings:
            return {}
        body = {c.field: c.desired for c in self.settings}
        body.update(self.write_only)
        return body


# Alias fields compared field-by-field (everything else needs special handling).
_ALIAS_SIMPLE = ("is_enabled", "error_code_if_disabled", "has_imap", "has_pgp", "has_recipient_verification")


def _resolve_alias(desired: DesiredAlias, defaults: dict) -> dict:
    """Desired alias with repo/package defaults filled in for undeclared fields."""
    out = {"name": desired.name, "recipients": list(desired.recipients)}
    for f in _ALIAS_SIMPLE:
        v = getattr(desired, f)
        out[f] = defaults[f] if v is None else v
    out["description"] = desired.description if desired.description is not None else defaults["description"]
    out["public_key"] = desired.public_key
    out["max_quota"] = desired.max_quota
    out["vacation_responder"] = desired.vacation_responder
    return out


def _norm_desc(v) -> str:
    return "" if v is None else str(v)


def _vacation_enabled(v) -> bool:
    return bool(v) and bool(v.get("is_enabled"))


def _alias_body(resolved: dict) -> dict:
    """Write body: name/recipients plus every resolved flag, explicitly.

    The server's own defaults are not ours (a repo may default `is_enabled: false`, or a
    non-empty description), so a create never leaves a flag for the server to choose.
    """
    body = {"name": resolved["name"], "recipients": resolved["recipients"]}
    for f in _ALIAS_SIMPLE:
        body[f] = resolved[f]
    if _norm_desc(resolved["description"]):
        body["description"] = resolved["description"]
    if resolved["public_key"]:
        body["public_key"] = resolved["public_key"]
    if resolved["max_quota"] is not None:
        body["max_quota"] = resolved["max_quota"]
    if _vacation_enabled(resolved["vacation_responder"]):
        body["vacation_responder"] = resolved["vacation_responder"]
    return body


def _diff_alias(resolved: dict, live: dict, defaults: dict, domain_quota: int) -> AliasChange | None:
    changes: list[str] = []
    body = _alias_body(resolved)

    if sorted(resolved["recipients"]) != sorted(live.get("recipients") or []):
        changes.append("recipients")
    for f in _ALIAS_SIMPLE:
        if resolved[f] != live.get(f, defaults[f]):
            changes.append(f)
    if _norm_desc(resolved["description"]) != _norm_desc(live.get("description")):
        changes.append("description")
        body["description"] = _norm_desc(resolved["description"])
    if (resolved["public_key"] or "") != (live.get("public_key") or ""):
        changes.append("public_key")
        body["public_key"] = resolved["public_key"] or ""

    # Quota: compare in bytes; None desired means "domain default".
    desired_bytes = parse_quota(resolved["max_quota"]) if resolved["max_quota"] else domain_quota
    live_quota = live.get("max_quota")
    live_bytes = domain_quota if live_quota is None else int(live_quota)
    if desired_bytes != live_bytes:
        changes.append("max_quota")
        body["max_quota"] = resolved["max_quota"] or ""

    want_vac = resolved["vacation_responder"]
    if _vacation_enabled(want_vac) != _vacation_enabled(live.get("vacation_responder")) or (
        _vacation_enabled(want_vac) and want_vac != live.get("vacation_responder")
    ):
        changes.append("vacation_responder")
        body["vacation_responder"] = want_vac or {"is_enabled": False}

    if not changes:
        return None
    return AliasChange("update", resolved["name"], live.get("id"), body, changes)


def plan_domain(
    desired: DesiredDomain,
    cfg: ForwardEmailConfig,
    live_domain: dict,
    live_aliases: list[dict],
    *,
    prune: bool,
) -> DomainPlan:
    plan = DomainPlan(desired.domain)
    settings = {**cfg.settings, **desired.settings}
    expect = {**cfg.expect, **desired.expect}

    for f in sorted(SETTINGS_FIELDS & set(settings)):
        if f in WRITE_ONLY_SETTINGS:
            plan.write_only[f] = settings[f]
        elif live_domain.get(f) != settings[f]:
            plan.settings.append(SettingChange(f, live_domain.get(f), settings[f]))

    for f in sorted(EXPECT_FIELDS & set(expect)):
        if live_domain.get(f) != expect[f]:
            plan.expect_mismatch.append(SettingChange(f, live_domain.get(f), expect[f]))

    domain_quota = parse_quota(settings.get("max_quota_per_alias") or 0)
    live_by_name = {a["name"]: a for a in live_aliases}

    for want in desired.aliases:
        resolved = _resolve_alias(want, cfg.alias)
        live = live_by_name.get(want.name)
        if live is None:
            plan.aliases.append(AliasChange("create", want.name, None, _alias_body(resolved), ["new"]))
            continue
        chg = _diff_alias(resolved, live, cfg.alias, domain_quota)
        if chg:
            plan.aliases.append(chg)

    wanted = {a.name for a in desired.aliases}
    for live in live_aliases:
        if live["name"] in wanted:
            continue
        plan.unmanaged.append(live["name"])
        if not prune:
            continue
        if live.get("has_imap") or (live.get("storage_used") or 0) > 0:
            plan.errors.append(
                f"refusing to prune {live['name']}@{desired.domain}: it is a mailbox "
                f"(has_imap={live.get('has_imap')}, storage_used={live.get('storage_used')}); "
                "add it to git or delete it in the web UI"
            )
            continue
        plan.aliases.append(AliasChange("delete", live["name"], live.get("id"), {}, ["prune"]))

    return plan
