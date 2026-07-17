#!/usr/bin/env python3
"""Enable DNSSEC delegation for opt-in zones (NS cutover + DS publish).

Opt-in only: acts solely on zones listed under `delegation:` in config.yaml.
Idempotent per-zone state machine; `--dry-run` (default) performs read-only
network access (signer DNS, registrar reads, octoDNS planning) but creates no
registrar tasks. `--doit` performs the writes.

Ordering (safety): parity guard -> NS cutover -> wait for the delegation to be
live -> DS publish. DS is never published while the zone still resolves via the
old (unsigned) provider.
"""

from __future__ import annotations

import argparse
import io
import logging
import os
import sys
from dataclasses import dataclass, field
from typing import Callable

from octodns_gitops.delegation.config import DelegationZone, load_delegation
from octodns_gitops.delegation.signer import (
    SignerIntentError,
    resolve_intended_delegation,
)
from octodns_gitops.dnssec import source as dns_source
from octodns_gitops.dnssec.keys import compare_ds
from octodns_gitops.registrar.base import RegistrarBackend
from octodns_gitops.registrar.manual import ManualRegistrar
from octodns_gitops.registrar.ovh import OvhRegistrar

def _make_ovh(opts: dict) -> RegistrarBackend:
    return OvhRegistrar(env_prefix=opts.get("env_prefix", "OVH"))


def _make_manual(opts: dict) -> RegistrarBackend:
    return ManualRegistrar()


BACKENDS: dict[str, Callable[[dict], RegistrarBackend]] = {
    "ovh": _make_ovh,
    "manual": _make_manual,
}


def build_backend(name: str, options: dict | None = None) -> RegistrarBackend:
    try:
        return BACKENDS[name](options or {})
    except KeyError:
        raise SystemExit(f"unknown registrar backend: {name!r}")


def default_parity_ok(config_path: str, zone: str, signer_target: str) -> bool:
    """True when the signer target has an empty change set (machine-readable).

    Uses octoDNS's own change count (`Manager.sync` returns total_changes),
    scoped to the zone + signer target, dry-run + force — no text scraping.
    """
    from octodns.manager import Manager

    m = Manager(config_path)
    # octoDNS emits INFO/WARNING chatter (processor lenient, root-NS notes) during
    # planning; quiet it so the delegate output stays clean.
    previous = logging.root.manager.disable
    logging.disable(logging.WARNING)
    try:
        changes = m.sync(
            eligible_zones=[zone],
            eligible_targets=[signer_target],
            dry_run=True,
            force=True,
            plan_output_fh=io.StringIO(),
        )
    finally:
        logging.disable(previous)
    return changes == 0


@dataclass
class Deps:
    """Injectable side-effecting helpers (defaults hit the network/octoDNS)."""

    fetch_signer: Callable = dns_source.fetch_from_signer
    parent_ds: Callable = dns_source.parent_ds_authoritative
    observed_ns: Callable = dns_source.observed_nameservers
    parity_ok: Callable = default_parity_ok


def _norm(nslist: list[str]) -> list[str]:
    return sorted(n.lower().rstrip(".") for n in nslist)


def process_zone(
    dz: DelegationZone,
    config_path: str,
    backend: RegistrarBackend,
    doit: bool,
    deps: Deps,
    step: str = "ns",
) -> dict:
    """Advance one zone by one stage for the given step ('ns' or 'ds').

    The two steps are deliberately separate: the NS step never touches DNSSEC, and
    the DS step only runs for zones with `dnssec: true` and only once NS is live.
    """
    domain = dz.domain
    rep: dict = {"zone": dz.zone, "stage": None, "actions": [], "error": None}

    def done(stage: str) -> dict:
        rep["stage"] = stage
        return rep

    def fail(msg: str) -> dict:
        rep["stage"] = "blocked"
        rep["error"] = msg
        return rep

    # Observed registry-side delegation state is the source of truth.
    current_ns = _norm(backend.get_nameservers(domain))
    target_ns = _norm(dz.target_nameservers)
    ns_live = current_ns == target_ns

    if step == "ns":
        return _step_ns(dz, config_path, backend, doit, deps, rep, done, fail,
                        current_ns, target_ns, ns_live)
    if step == "ds":
        return _step_ds(dz, backend, doit, deps, rep, done, fail)
    return fail(f"unknown step {step!r}")


def _step_ns(dz, config_path, backend, doit, deps, rep, done, fail,
             current_ns, target_ns, ns_live) -> dict:
    """NS cutover only — never publishes DS.

    Idempotent: if a delegation task is already in flight at the registrar, report
    it and do NOT submit another (even before the parent shows the new NS).
    """
    pending = backend.pending_nameserver_tasks(dz.domain)
    if pending:
        rep["actions"].append(
            f"NS change already in progress: task(s) {', '.join(pending)}"
        )
        return done("ns-task-pending")

    if ns_live:
        rep["actions"].append(f"delegated to {', '.join(target_ns)} (no change)")
        return done("ns-live")

    # Preflight: only replace NS on an external-NS domain.
    nstype = backend.nameserver_type(dz.domain)
    if nstype != "external":
        return fail(f"nameserver type is {nstype!r}, not 'external'")

    # Parity guard (hard): signer must have an empty change set before we move authority.
    if not deps.parity_ok(config_path, dz.zone, dz.signer_target):
        return fail("parity: signer target has pending changes; sync the signer first")

    change = f"NS {', '.join(current_ns) or '(none)'} -> {', '.join(target_ns)}"
    if not backend.writable:
        res = backend.set_nameservers(dz.domain, dz.target_nameservers)
        rep["actions"].append(f"{res.detail or res}  [current: {', '.join(current_ns) or 'none'}]")
        return done("manual-required")
    if doit:
        res = backend.set_nameservers(dz.domain, dz.target_nameservers)
        rep["actions"].append(f"submitted: {change} [{res.status} {res.task_id or ''}]".rstrip())
    else:
        rep["actions"].append(f"would change {change}")
    return done("ns-cutover-submitted")


def _step_ds(dz, backend, doit, deps, rep, done, fail) -> dict:
    """DS publish only — requires per-zone opt-in and a live delegation.

    Safety: publish DS only once the *parent* delegation actually points at the
    signer's nameservers (a registrar's internal record can flip before the
    registry/DNS does). Publishing DS while resolvers still see the old unsigned
    delegation would break validation (SERVFAIL).
    """
    if not dz.dnssec:
        rep["actions"].append("dnssec not enabled for this zone (set dnssec: true)")
        return done("dnssec-not-enabled")
    pending = backend.pending_nameserver_tasks(dz.domain)
    if pending:
        rep["actions"].append(f"pending NS tasks: {pending}")
        return done("ns-task-pending")

    # Parent-authoritative delegation must already be the signer's NS.
    observed = _norm(deps.observed_ns(dz.zone))
    target = _norm(dz.target_nameservers)
    if observed != target:
        return fail(
            f"parent delegation not live yet (resolvers see {', '.join(observed) or 'none'}); "
            "wait until it shows the signer NS before publishing DS"
        )

    try:
        sk = deps.fetch_signer(dz.zone, dz.target_nameservers)
        intended = resolve_intended_delegation(dz.zone, sk)
    except SignerIntentError as e:
        return fail(str(e))
    rep.setdefault("warnings", []).extend(intended.warnings)

    ds_txt = "; ".join(d.to_text() for d in intended.ds_records)
    if compare_ds(deps.parent_ds(dz.domain), intended.ds_records).ok:
        return done("done")  # DS live at the parent

    if not backend.writable:
        res = backend.set_delegation_signer(dz.domain, intended.ds_records, intended.dnskey_records)
        rep["actions"].append(res.detail or str(res))
        return done("manual-required")

    # Registrar-side idempotency: if the registrar already holds the intended DS,
    # it's submitted — don't queue a duplicate, just await parent propagation.
    try:
        held = backend.get_ds(dz.domain)
    except Exception:  # noqa: BLE001 - treat unreadable as not-held
        held = []
    if compare_ds(held, intended.ds_records).ok:
        rep["actions"].append(f"DS already set at registrar; awaiting propagation: {ds_txt}")
        return done("ds-set")

    if doit:
        res = backend.set_delegation_signer(dz.domain, intended.ds_records, intended.dnskey_records)
        rep["actions"].append(f"DS published ({intended.source}) [{res.status}]: {ds_txt}")
    else:
        rep["actions"].append(f"would publish DS ({intended.source}): {ds_txt}")
    return done("ds-published")


def main() -> int:
    p = argparse.ArgumentParser(description="Enable DNSSEC delegation (opt-in)")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--zone", help="Limit to a single zone (trailing dot)")
    p.add_argument("--doit", action="store_true", help="Perform writes (default dry-run)")
    p.add_argument(
        "--step",
        choices=["ns", "ds"],
        default="ns",
        help="Which step to run: 'ns' (delegation cutover, default) or 'ds' "
        "(publish DNSSEC DS; only for zones with dnssec: true). The two are "
        "separate — the ns step never touches DNSSEC.",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Preview only (the default; accepted for symmetry with --doit)",
    )
    p.add_argument(
        "--allow-manual-pending",
        action="store_true",
        help="Treat manual-required zones as informational (exit 0) rather than failing",
    )
    args = p.parse_args()

    zones = load_delegation(args.config)
    if args.zone:
        zones = [z for z in zones if z.zone == args.zone]
    if not zones:
        print("No opted-in zones (delegation:) in scope.")
        return 0

    mode = "APPLYING changes (--doit)" if args.doit else "DRY-RUN (default): no changes"
    print(f"{mode} — step: {args.step}")

    # Cache backends by (registrar, options) so distinct OVH accounts (env
    # prefixes) get distinct clients.
    cache: dict[tuple, RegistrarBackend] = {}

    def backend_for(dz) -> RegistrarBackend:
        key = (dz.registrar, tuple(sorted(dz.registrar_options.items())))
        if key not in cache:
            cache[key] = build_backend(dz.registrar, dz.registrar_options)
        return cache[key]

    # Preflight credentials for each distinct backend, once, before any work.
    seen: set = set()
    for dz in zones:
        key = (dz.registrar, tuple(sorted(dz.registrar_options.items())))
        if key in seen:
            continue
        seen.add(key)
        backend = backend_for(dz)
        missing = [v for v in backend.required_env() if not os.environ.get(v)]
        if missing:
            print(
                f"registrar {dz.registrar!r}: missing env vars {missing}",
                file=sys.stderr,
            )
            return 2

    deps = Deps()
    rc = 0
    for dz in zones:
        backend = backend_for(dz)
        try:
            rep = process_zone(dz, args.config, backend, args.doit, deps, args.step)
        except Exception as e:  # noqa: BLE001 - one zone's failure isn't fatal
            print(f"{dz.zone:<28} ERROR  {e}")
            rc = 1
            continue
        for w in rep.get("warnings", []):
            print(f"  warning: {w}")
        note = rep["error"] or "; ".join(str(a) for a in rep["actions"])
        print(f"{dz.zone:<28} {rep['stage']:<22} {note}")
        if rep["stage"] == "blocked":
            rc = 1
        elif rep["stage"] == "manual-required" and not args.allow_manual_pending:
            # Never let a manual (e.g. Gandi) zone read as "done".
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
