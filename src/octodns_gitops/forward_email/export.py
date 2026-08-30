"""Render live API state as a per-domain desired-state file.

Hand-rolled emitter rather than `yaml.dump`: key order, quoting and the omission of
default-valued fields are the contract. Regex alias names (`/^([\\w\\-\\.]+)$/`) are
single-quoted — a double-quoted YAML scalar would read `\\w` as an escape sequence.
"""

from __future__ import annotations

import json
import re

from .config import (
    EXPECT_FIELDS,
    SETTINGS_FIELDS,
    VACATION_RESPONDER_KEYS,
    WRITE_ONLY_SETTINGS,
    ForwardEmailConfig,
)
from .reconcile import _ALIAS_SIMPLE, _norm_desc, _vacation_enabled, parse_quota

# Plain scalars must start with a letter, `_` or `$` (`$1@…` recipients): anything starting
# with a digit — dates, `1e3`, `"25"` — is quoted so YAML cannot retype it.
_PLAIN_OK = re.compile(r"^[A-Za-z$_][A-Za-z0-9$_@.+\- ]*$")
_YAML_WORDS = {"true", "false", "null", "yes", "no", "on", "off", "~"}
_QUOTA_UNITS = (("TB", 1024**4), ("GB", 1024**3), ("MB", 1024**2), ("KB", 1024))


def _scalar(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    if isinstance(v, (dict, list)):
        # JSON is valid YAML flow style; keeps nested values typed on reload.
        return json.dumps(v, ensure_ascii=False)
    s = str(v)
    if bool(_PLAIN_OK.match(s)) and s == s.strip() and s.lower() not in _YAML_WORDS:
        return s
    if "\n" in s or "\r" in s or "\t" in s:
        # A single-quoted YAML scalar folds newlines; a JSON string is a valid double-quoted one.
        return json.dumps(s, ensure_ascii=False)
    return "'" + s.replace("'", "''") + "'"


def human_quota(nbytes: int) -> str:
    for unit, size in _QUOTA_UNITS:
        if nbytes % size == 0:
            return f"{nbytes // size} {unit}"
    return f"{nbytes} B"


def _list(lines: list[str], key: str, values: list, indent: str) -> None:
    if not values:
        lines.append(f"{indent}{key}: []")
        return
    lines.append(f"{indent}{key}:")
    lines.extend(f"{indent}  - {_scalar(v)}" for v in values)


def _alias_lines(live: dict, defaults: dict, domain_quota: int) -> list[str]:
    ind = "    "
    out = [f"  - name: {_scalar(live['name'])}"]
    _list(out, "recipients", live.get("recipients") or [], ind)
    # Written whenever it differs from the resolved default — including a blank live value
    # under a non-empty repo default, or reloading would inherit the default and plan an update.
    desc = _norm_desc(live.get("description"))
    if desc != _norm_desc(defaults["description"]):
        out.append(f"{ind}description: {_scalar(desc)}")
    for f in _ALIAS_SIMPLE:
        if live.get(f, defaults[f]) != defaults[f]:
            out.append(f"{ind}{f}: {_scalar(live[f])}")
    if live.get("public_key"):
        out.append(f"{ind}public_key: {_scalar(live['public_key'])}")
    if live.get("max_quota") is not None and int(live["max_quota"]) != domain_quota:
        out.append(f"{ind}max_quota: {human_quota(int(live['max_quota']))}")
    vac = live.get("vacation_responder")
    if _vacation_enabled(vac):
        # Only the schema keys: the loader rejects anything else, and the reconciler compares
        # exactly these, so an extra live key is neither written nor a diff.
        out.append(f"{ind}vacation_responder:")
        out.extend(f"{ind}  {k}: {_scalar(vac[k])}" for k in VACATION_RESPONDER_KEYS if k in vac)
    return out


def export_domain(
    cfg: ForwardEmailConfig, live_domain: dict, live_aliases: list[dict], *, write_only: dict | None = None
) -> str:
    """Return the YAML text for `live_domain`, omitting everything equal to the resolved defaults.

    `write_only` carries `WRITE_ONLY_SETTINGS` values the API cannot return (taken from the file
    being overwritten); they are emitted like any other non-default setting.
    """
    lines = [f"domain: {_scalar(live_domain['name'])}"]

    readable = {f: live_domain[f] for f in SETTINGS_FIELDS - WRITE_ONLY_SETTINGS if f in live_domain}
    preserved = {f: v for f, v in (write_only or {}).items() if f in WRITE_ONLY_SETTINGS}
    settings = {f: v for f, v in sorted({**readable, **preserved}.items()) if v != cfg.settings.get(f)}
    if settings:
        lines.append("settings:")
        lines.extend(f"  {k}: {_scalar(v)}" for k, v in settings.items())

    expect = {
        f: live_domain[f]
        for f in sorted(EXPECT_FIELDS)
        if f in live_domain and live_domain[f] != cfg.expect.get(f)
    }
    if expect:
        lines.append("expect:")
        lines.extend(f"  {k}: {_scalar(v)}" for k, v in expect.items())

    # Alias quotas resolve against the per-domain default the reloaded file will carry — a
    # preserved `max_quota_per_alias` included — or an omitted alias quota reloads as a reset.
    domain_quota = parse_quota({**cfg.settings, **preserved}.get("max_quota_per_alias") or 0)
    if not live_aliases:
        lines.append("aliases: []")
    else:
        lines.append("aliases:")
        for a in sorted(live_aliases, key=lambda a: a["name"]):
            lines.extend(_alias_lines(a, cfg.alias, domain_quota))
    return "\n".join(lines) + "\n"
