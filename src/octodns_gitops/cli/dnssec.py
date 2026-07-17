#!/usr/bin/env python3
"""Validate DNSSEC delegation for managed zones (read-only).

For each zone: report DS at the authoritative parent AND via a recursive resolver
(propagation view), whether the chain validates (AD bit from a validating
resolver), and DS set-membership vs the signer's intended DS.

Scopes:
  --scope delegation          opt-in `delegation:` zones (default)
  --scope all-signed-targets  every octoDNS zone with a signer target (observe)
"""

from __future__ import annotations

import argparse
import sys

from octodns_gitops.delegation.config import load_delegation, signer_zones
from octodns_gitops.delegation.signer import (
    SignerIntentError,
    resolve_intended_delegation,
)
from octodns_gitops.dnssec import source as dns_source
from octodns_gitops.dnssec.keys import compare_ds


def _zones(config: str, scope: str) -> list[tuple[str, str, list[str], bool, bool]]:
    """Return (zone, signer_target, nameservers, allow_extra_ds, dnssec) per scope.

    `dnssec` marks whether the zone is opted in to DNSSEC; NS-only zones are shown
    but never counted as failures.
    """
    if scope == "delegation":
        return [
            (z.zone, z.signer_target, z.target_nameservers, z.allow_extra_ds, z.dnssec)
            for z in load_delegation(config)
        ]
    # Observation scope: dnssec intent unknown, so never a failure.
    return [(z, st, ns, False, False) for (z, st, ns) in signer_zones(config)]


def check_zone(zone: str, nameservers: list[str], allow_extra_ds: bool) -> dict:
    """Gather the DNSSEC status of one zone (all read-only DNS queries)."""
    row: dict = {"zone": zone, "ok": False, "notes": []}
    try:
        sk = dns_source.fetch_from_signer(zone, nameservers)
        intended = resolve_intended_delegation(zone, sk)
    except (SignerIntentError, Exception) as e:  # noqa: BLE001 - report, don't crash
        row["notes"].append(f"signer: {e}")
        return row

    parent_auth = dns_source.parent_ds_authoritative(zone)
    parent_rec = dns_source.parent_ds_recursive(zone)
    cmp = compare_ds(parent_auth, intended.ds_records)
    ad = dns_source.check_ad(zone)

    row.update(
        ds_parent=len(parent_auth),
        ds_recursive=len(parent_rec),
        ds_source=intended.source,
        validated=ad.validated,
        missing=len(cmp.missing),
        extra=len(cmp.extra),
    )
    if cmp.extra and not allow_extra_ds:
        row["notes"].append(f"{len(cmp.extra)} extra/stale DS at parent (warning)")
    if not parent_auth:
        row["notes"].append("no DS at parent (delegation not enabled yet)")
    row["ok"] = cmp.ok and ad.validated
    return row


def main() -> int:
    p = argparse.ArgumentParser(description="Validate DNSSEC delegation (read-only)")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--zone", help="Limit to a single zone (trailing dot)")
    p.add_argument(
        "--scope",
        choices=["delegation", "all-signed-targets"],
        default="delegation",
    )
    args = p.parse_args()

    zones = _zones(args.config, args.scope)
    if args.zone:
        zones = [z for z in zones if z[0] == args.zone]
    if not zones:
        print("No zones in scope.")
        return 0

    any_bad = False
    print(f"{'zone':<28} {'DS@parent':>9} {'recur':>6} {'valid':>6}  notes")
    for zone, _signer, ns, allow_extra, dnssec in zones:
        if not dnssec and args.scope == "delegation":
            # NS-only zone: DNSSEC not expected here — report, never fail.
            print(f"{zone:<28} {'-':>9} {'-':>6} {'n/a':>6}  DNSSEC not enabled (NS-only)")
            continue
        row = check_zone(zone, ns, allow_extra)
        valid = "yes" if row.get("validated") else "no"
        dsp = row.get("ds_parent", "-")
        dsr = row.get("ds_recursive", "-")
        notes = "; ".join(row["notes"])
        print(f"{zone:<28} {dsp!s:>9} {dsr!s:>6} {valid:>6}  {notes}")
        # A DNSSEC-enabled managed zone that doesn't validate is a failure.
        if args.scope == "delegation" and not row["ok"]:
            any_bad = True

    return 1 if any_bad else 0


if __name__ == "__main__":
    sys.exit(main())
