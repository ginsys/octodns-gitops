"""Reconcile Forward Email domain settings and aliases with per-domain files in git.

Opt-in only: acts solely on domains listed under `forward_email:` in config.yaml.
`--dry-run` (default) reads the account and prints the diff; `--doit` writes it.
Domains are never created or deleted — a claimed domain missing from the account is
an error. `--prune` (off by default) deletes aliases absent from git, except mailboxes
(`has_imap` or stored mail), which block the run instead.

Modes:
  plan / apply   diff desired state against the account (default)
  --export       write `<directory>/<domain>.yaml` from live state (bootstrap / re-baseline)
  --drift        compare FE's generated DNS records and read-only expectations with the repo

Exit codes: 0 nothing wrong; 1 a drift finding (`--drift` only — plan/apply print `expect:`
mismatches but do not fail on them, they are read-only), a refused prune, a blocked alias, or any
per-domain error (a bad per-domain file included — the other domains still run); 2 the invocation
itself is invalid (the `forward_email:` block, a missing token, an unclaimed `--domain`, `--prune`
outside plan/apply, `--dry-run` with `--export`). In `--drift` an alias the plan would refuse on
the file alone (no recipients and no mailbox) is a finding as well; guards that need live state
(the mailbox update guard, prune) are plan/apply only, since drift never reads the live aliases.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TextIO

from octodns_gitops.forward_email.api import ForwardEmailApiError, ForwardEmailClient
from octodns_gitops.forward_email.config import (
    WRITE_ONLY_SETTINGS,
    ForwardEmailConfig,
    ForwardEmailConfigError,
    load_domain_file,
    load_forward_email,
    load_yaml_strict,
)
from octodns_gitops.forward_email.drift import check_zone, merge_zones
from octodns_gitops.forward_email.export import export_domain
from octodns_gitops.forward_email.reconcile import DomainPlan, plan_domain


class AmbiguousZoneDirectory(ValueError):
    """Several YamlProviders and nothing saying which one holds this domain's zone file."""


@dataclass(frozen=True)
class ZoneLookup:
    """Where each domain's octoDNS zone file lives, from `providers:` and `zones:` in config.yaml.

    Resolved per domain: with several YamlProviders, "the first one" would check a directory the
    domain is not sourced from and report the file as merely absent (rc 0).
    """

    yaml_dirs: dict[str, Path]  # YamlProvider name -> directory (absolute)
    sources: dict[str, list[str]]  # bare zone name (or "*") -> its `sources:` provider names

    @classmethod
    def single(cls, directory: Path) -> ZoneLookup:
        return cls({"zones": directory}, {})

    def directories(self, domain: str) -> list[Path]:
        """The zone directories for `domain`, in `sources:` order; empty when it has no zone file
        in this repo. octoDNS merges every source, so drift must read every YAML one."""
        named = self.sources.get(domain, self.sources.get("*"))
        if named is not None:
            return [self.yaml_dirs[p] for p in named if p in self.yaml_dirs]
        if len(self.yaml_dirs) <= 1:
            return list(self.yaml_dirs.values())
        raise AmbiguousZoneDirectory(
            f"ambiguous: {len(self.yaml_dirs)} YamlProviders ({', '.join(sorted(self.yaml_dirs))}) and "
            f"zones.{domain}.sources does not name one"
        )


def zone_lookup(config_path: str) -> ZoneLookup:
    """Parse the octoDNS `providers:`/`zones:` blocks; directories resolve relative to config.yaml."""
    cfg_file = Path(config_path)
    with open(cfg_file) as f:
        cfg = load_yaml_strict(f) or {}
    base = cfg_file.resolve().parent
    yaml_dirs: dict[str, Path] = {}
    providers = cfg.get("providers")
    for name, prov in (providers.items() if isinstance(providers, dict) else ()):
        if isinstance(prov, dict) and str(prov.get("class", "")).endswith("YamlProvider"):
            d = Path(prov.get("directory", "./zones"))
            yaml_dirs[str(name)] = d if d.is_absolute() else base / d
    sources: dict[str, list[str]] = {}
    zones = cfg.get("zones")
    for zone, spec in (zones.items() if isinstance(zones, dict) else ()):
        if isinstance(spec, dict) and isinstance(spec.get("sources"), list):
            sources[str(zone).rstrip(".").lower()] = [str(s) for s in spec["sources"]]
    return ZoneLookup(yaml_dirs, sources)


def _print_plan(plan: DomainPlan, out: TextIO) -> None:
    n = len(plan.settings) + len(plan.aliases)
    head = f"{n} change(s)" if n else "no changes"
    out.write(f"{plan.domain:<28} {head}\n")
    if plan.settings:
        parts = [f"{c.field} {c.live!r} -> {c.desired!r}" for c in plan.settings]
        extra = ", ".join(f"{k}={v!r}" for k, v in plan.write_only.items())
        out.write(f"  settings: {'; '.join(parts)}")
        out.write(f"  (+ write-only, unverifiable: {extra})\n" if extra else "\n")
    for chg in plan.aliases:
        detail = "" if chg.action == "create" else f"  [{', '.join(chg.changes)}]"
        out.write(f"  alias {chg.action:<6} {chg.name}{detail}\n")
    if plan.unmanaged:
        out.write(f"  unmanaged (not in git, not pruned): {', '.join(plan.unmanaged)}\n")
    out.writelines(
        f"  expect: {m.field} is {m.live!r}, expected {m.desired!r} (read-only, not written)\n"
        for m in plan.expect_mismatch
    )
    out.writelines(f"  WARNING: {w}\n" for w in plan.warnings)
    out.writelines(f"  ERROR: {e}\n" for e in plan.errors)


def _prune_still_safe(plan: DomainPlan, deletes: list, client, out: TextIO) -> bool:
    """A0: never prune from a single listing — re-fetch and require the same id set, and for
    every planned delete the same name and still no mailbox (a mailbox may appear under an
    unchanged id between the two listings)."""
    before = plan.live_alias_ids
    relisted = {a.get("id"): a for a in client.list_aliases(plan.domain)}
    if before != set(relisted):
        out.write(
            f"  ERROR: alias list for {plan.domain} changed between listings "
            f"({len(before)} -> {len(relisted)} ids); prune aborted, re-run\n"
        )
        return False
    for chg in deletes:
        now = relisted[chg.alias_id]
        if now.get("name") != chg.name or now.get("has_imap") or (now.get("storage_used") or 0) > 0:
            out.write(
                f"  ERROR: alias {chg.name} ({chg.alias_id}) changed between listings "
                f"(now name={now.get('name')!r}, has_imap={now.get('has_imap')}, "
                f"storage_used={now.get('storage_used')}); prune aborted, re-run\n"
            )
            return False
    return True


def _apply(plan: DomainPlan, client, out: TextIO) -> bool:
    """Perform the writes for one domain. Returns False if the prune guard aborted or any
    alias write failed — the domain's remaining, independent alias writes are still attempted
    (ginsys/octodns-gitops#2: one 400 must not hold the rest of its domain hostage).

    Order: settings PUT, prune re-list, creates/updates, deletes. The re-list must precede
    our own creates — they change the id set, so a create+delete plan would otherwise always
    abort half-applied. A settings PUT failure still aborts the domain: it is domain-level,
    not one alias's problem.
    """
    body = plan.settings_body()
    if body:
        client.update_domain(plan.domain, body)
        out.write(f"  applied settings: {sorted(body)}\n")
    deletes = [c for c in plan.aliases if c.action == "delete"]
    if deletes and not _prune_still_safe(plan, deletes, client, out):
        return False
    ok = True
    for chg in plan.aliases:
        try:
            if chg.action == "create":
                client.create_alias(plan.domain, chg.body)
            elif chg.action == "update":
                client.update_alias(plan.domain, chg.alias_id, chg.body)
            else:
                continue
        except ForwardEmailApiError as e:
            out.write(f"  ERROR  alias {chg.action} {chg.name}: {e}\n")
            ok = False
            continue
        out.write(f"  applied alias {chg.action} {chg.name}\n")
    for chg in deletes:
        try:
            client.delete_alias(plan.domain, chg.alias_id)
        except ForwardEmailApiError as e:
            out.write(f"  ERROR  alias delete {chg.name}: {e}\n")
            ok = False
            continue
        out.write(f"  applied alias delete {chg.name}\n")
    return ok


def _preserved_write_only(path: Path) -> dict:
    """Write-only settings declared in the existing per-domain file: the API cannot return them,
    so an export that overwrote the file would drop them and the next domain PUT would send the
    repo default instead."""
    if not path.exists():
        return {}
    with open(path) as f:
        existing = load_yaml_strict(f) or {}
    settings = existing.get("settings") if isinstance(existing, dict) else None
    if not isinstance(settings, dict):
        return {}
    return {k: v for k, v in settings.items() if k in WRITE_ONLY_SETTINGS}


def run(
    cfg: ForwardEmailConfig,
    client,
    *,
    domains: list[str] | None,
    doit: bool,
    prune: bool,
    mode: str,
    zones: ZoneLookup | None,
    out: TextIO,
) -> int:
    scope = list(cfg.domains)
    if domains:
        unclaimed = [d for d in domains if d not in cfg.domains]
        if unclaimed:
            out.write(f"not claimed under forward_email.domains: {', '.join(unclaimed)}\n")
            return 2
        scope = [d for d in scope if d in domains]

    if mode == "plan":
        out.write("APPLYING changes (--doit)\n" if doit else "DRY-RUN (default): no changes\n")
    try:
        live_domains = {d["name"].lower(): d for d in client.list_domains()}
    except Exception as e:  # noqa: BLE001 - any failure here means nothing can be judged
        out.write(f"ERROR  listing domains: {type(e).__name__}: {e}\n")
        return 1

    rc = 0
    for domain in scope:
        if domain not in live_domains:
            out.write(f"{domain:<28} ERROR  not in the account (domains are never created from git)\n")
            rc = 1
            continue
        try:
            live = client.get_domain(domain)
            if mode == "export":
                aliases = client.list_aliases(domain)
                cfg.directory.mkdir(parents=True, exist_ok=True)
                path = cfg.directory / f"{domain}.yaml"
                write_only = _preserved_write_only(path)
                path.write_text(export_domain(cfg, live, aliases, write_only=write_only))
                out.write(f"{domain:<28} wrote {path} ({len(aliases)} aliases)\n")
                if write_only:
                    out.write(f"  preserved write-only settings from the previous file: {sorted(write_only)}\n")
                continue

            path = cfg.directory / f"{domain}.yaml"
            desired = load_domain_file(path, domain)

            if mode == "drift":
                findings = []
                plan = plan_domain(desired, cfg, live, [], prune=False)
                findings += [(m.field, f"{m.field} is {m.live!r}, expected {m.desired!r}") for m in plan.expect_mismatch]
                # A file plan/apply refuses is drift too — "clean" here must not contradict `make mail-plan`.
                findings += [("alias", e) for e in plan.errors]
                zone_files: list[Path] = []
                try:
                    zone_dirs = zones.directories(domain) if zones else []
                except AmbiguousZoneDirectory as e:
                    # A finding, not "not checked": rc 0 here would hide a never-compared zone file.
                    findings.append(("zone", f"{e}; DNS records not compared"))
                else:
                    zone_files = [p for p in (d / f"{domain}.yaml" for d in zone_dirs) if p.exists()]
                    if not zone_files:
                        out.write(f"{domain:<28} no zone file in this repo; DNS records not checked\n")
                if zone_files:
                    parts = []
                    for zone_file in zone_files:
                        with open(zone_file) as f:
                            parts.append(load_yaml_strict(f) or {})
                    settings = {**cfg.settings, **desired.settings}
                    for fnd in check_zone(live, merge_zones(parts), expect_mx=not settings.get("ignore_mx_check")):
                        findings.append((fnd.field, fnd.message))
                if findings:
                    rc = 1
                    out.write(f"{domain:<28} {len(findings)} finding(s)\n")
                    out.writelines(f"  {field}: {msg}\n" for field, msg in findings)
                elif zone_files:
                    out.write(f"{domain:<28} clean\n")
                continue

            aliases = client.list_aliases(domain)
            plan = plan_domain(desired, cfg, live, aliases, prune=prune)
            plan.live_alias_ids = {a.get("id") for a in aliases}
            _print_plan(plan, out)
            if plan.errors:
                rc = 1
                continue
            if doit and not plan.is_empty() and not _apply(plan, client, out):
                rc = 1
        except (ForwardEmailConfigError, ForwardEmailApiError) as e:
            out.write(f"{domain:<28} ERROR  {e}\n")
            rc = 1
        except Exception as e:  # noqa: BLE001 - one domain's failure must not abort the others
            out.write(f"{domain:<28} ERROR  {type(e).__name__}: {e}\n")
            rc = 1
    return rc


def main() -> int:
    p = argparse.ArgumentParser(description="Reconcile Forward Email settings and aliases (opt-in)")
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--domain", action="append", help="Limit to this domain (repeatable)")
    w = p.add_mutually_exclusive_group()
    w.add_argument("--doit", action="store_true", help="Perform writes (default dry-run)")
    w.add_argument("--dry-run", action="store_true", help="Preview only (the default; accepted for symmetry)")
    p.add_argument("--prune", action="store_true", help="Delete aliases absent from git (never mailboxes)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--export", action="store_true", help="Write per-domain files from live state")
    g.add_argument("--drift", action="store_true", help="Check FE DNS records and expectations against the repo")
    args = p.parse_args()
    if args.prune and (args.export or args.drift):
        # Accepted-and-ignored would read as a prune that silently did nothing.
        p.error("--prune only applies to plan/apply; --export and --drift never delete anything")
    if args.dry_run and args.export:
        # --export always writes the files; a "dry run" of it would overwrite every selected one.
        p.error("--dry-run cannot be combined with --export, which always writes the domain files")

    try:
        cfg = load_forward_email(args.config)
    except ForwardEmailConfigError as e:
        print(f"config error: {e}", file=sys.stderr)
        return 2
    if cfg is None:
        print("Forward Email not configured (no forward_email: block in config.yaml).")
        return 0
    token = os.environ.get(cfg.token_env)
    if not token:
        print(f"missing env var {cfg.token_env} (forward_email.token)", file=sys.stderr)
        return 2

    mode = "export" if args.export else "drift" if args.drift else "plan"
    client = ForwardEmailClient(token)
    return run(
        cfg,
        client,
        domains=[d.lower().rstrip(".") for d in args.domain] if args.domain else None,
        doit=args.doit and mode == "plan",
        prune=args.prune,
        mode=mode,
        zones=zone_lookup(args.config) if mode == "drift" else None,
        out=sys.stdout,
    )


if __name__ == "__main__":
    sys.exit(main())
