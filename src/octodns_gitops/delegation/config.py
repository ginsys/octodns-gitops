"""Parse the opt-in `delegation:` config and derive per-zone signer settings.

Everything comes from the existing octoDNS `config.yaml`:
- `providers:` gives each target's provider `class:`.
- `zones:` gives each zone's `targets:`.
- `delegation:` (our top-level opt-in block) lists the zones to manage.

The signer target is *derived* (not hard-coded) as the zone target whose provider
class is DNSSEC-capable (default `octodns_desec.DesecProvider`), with an optional
per-zone `signer_target` override. Exactly one signer target must exist.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

# Provider classes that sign zones and thus can be a delegation signer, mapped to
# the nameservers a delegation to them should use (adapter defaults; overridable
# per zone). Extend this when adding another signing provider.
SIGNER_PROVIDER_DEFAULT_NS: dict[str, list[str]] = {
    "octodns_desec.DesecProvider": ["ns1.desec.io", "ns2.desec.org"],
}


class DelegationConfigError(ValueError):
    """Raised when the delegation config is invalid or ambiguous."""


@dataclass(frozen=True)
class DelegationZone:
    """One opted-in zone's resolved delegation settings."""

    zone: str  # normalized, trailing dot (octoDNS zone key)
    registrar: str
    signer_target: str
    target_nameservers: list[str]
    dnssec: bool = False  # opt-in per zone; the DS step skips zones without it
    allow_extra_ds: bool = False
    registrar_options: dict = field(default_factory=dict)  # e.g. {"env_prefix": ...}
    overrides: dict = field(default_factory=dict)

    @property
    def domain(self) -> str:
        """Bare domain for registrar/DNS calls (no trailing dot)."""
        return self.zone.rstrip(".")


def _load_yaml(config_path: str) -> dict:
    p = Path(config_path)
    if not p.exists():
        raise DelegationConfigError(f"config not found: {config_path}")
    with open(p) as f:
        return yaml.safe_load(f) or {}


def derive_signer_target(
    cfg: dict,
    zone: str,
    override: str | None = None,
    signer_classes: tuple[str, ...] = tuple(SIGNER_PROVIDER_DEFAULT_NS),
) -> str:
    """Return the single signer target for `zone`.

    Validates the zone is an octoDNS zone and has exactly one signer-class target
    (or the `override`, which must itself be a signer-class target of the zone).
    """
    zones = cfg.get("zones") or {}
    if zone not in zones:
        raise DelegationConfigError(f"{zone} is not an octoDNS zone in config")
    providers = cfg.get("providers") or {}
    targets = (zones[zone] or {}).get("targets") or []

    def provider_class(target: str) -> str | None:
        return (providers.get(target) or {}).get("class")

    signer_targets = [t for t in targets if provider_class(t) in signer_classes]

    if override is not None:
        if override not in targets:
            raise DelegationConfigError(
                f"{zone}: signer_target {override!r} is not a target of the zone"
            )
        if provider_class(override) not in signer_classes:
            raise DelegationConfigError(
                f"{zone}: signer_target {override!r} is not a signing provider"
            )
        return override

    if len(signer_targets) == 0:
        raise DelegationConfigError(
            f"{zone}: no signing-provider target found (classes {signer_classes})"
        )
    if len(signer_targets) > 1:
        raise DelegationConfigError(
            f"{zone}: multiple signer targets {signer_targets}; set signer_target"
        )
    return signer_targets[0]


def default_nameservers(cfg: dict, signer_target: str) -> list[str]:
    """Adapter-default nameservers for a signer target, by its provider class."""
    providers = cfg.get("providers") or {}
    cls = (providers.get(signer_target) or {}).get("class")
    ns = SIGNER_PROVIDER_DEFAULT_NS.get(cls)
    if not ns:
        raise DelegationConfigError(
            f"no default nameservers known for signer {signer_target!r} "
            f"(class {cls!r}); set target_nameservers explicitly"
        )
    return list(ns)


def signer_zones(config_path: str) -> list[tuple[str, str, list[str]]]:
    """All octoDNS zones that have a signer target (for read-only observation).

    Returns `(zone, signer_target, target_nameservers)` tuples; zones with no
    signing-provider target are skipped.
    """
    cfg = _load_yaml(config_path)
    out: list[tuple[str, str, list[str]]] = []
    for zone in cfg.get("zones") or {}:
        try:
            st = derive_signer_target(cfg, zone)
            ns = default_nameservers(cfg, st)
        except DelegationConfigError:
            continue
        out.append((zone, st, [n.lower().rstrip(".") for n in ns]))
    return out


def load_delegation(config_path: str) -> list[DelegationZone]:
    """Parse the `delegation:` block into resolved per-zone settings.

    Returns an empty list when no `delegation:` block is present.
    """
    cfg = _load_yaml(config_path)
    block = cfg.get("delegation")
    if not block:
        return []

    default_registrar = block.get("registrar")
    default_dnssec = bool(block.get("dnssec", False))
    # Per-registrar backend options, e.g. {"ovh": {"env_prefix": "OVH_AUTOPS"}}.
    registrar_config = block.get("registrar_config") or {}
    zones_block = block.get("zones") or {}

    out: list[DelegationZone] = []
    for zone, raw in zones_block.items():
        raw = raw or {}
        registrar = raw.get("registrar", default_registrar)
        if not registrar:
            raise DelegationConfigError(
                f"{zone}: no registrar (set delegation.registrar or per-zone)"
            )
        signer_target = derive_signer_target(cfg, zone, raw.get("signer_target"))
        nameservers = raw.get("target_nameservers") or default_nameservers(
            cfg, signer_target
        )
        # per-zone `registrar_options` overrides the shared `registrar_config` entry
        options = {
            **(registrar_config.get(registrar) or {}),
            **(raw.get("registrar_options") or {}),
        }
        out.append(
            DelegationZone(
                zone=zone,
                registrar=registrar,
                signer_target=signer_target,
                target_nameservers=[ns.lower().rstrip(".") for ns in nameservers],
                dnssec=bool(raw.get("dnssec", default_dnssec)),
                allow_extra_ds=bool(raw.get("allow_extra_ds", False)),
                registrar_options=options,
                overrides=raw,
            )
        )
    return out
