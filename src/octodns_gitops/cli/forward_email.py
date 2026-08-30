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
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path
from typing import TextIO

import yaml

from octodns_gitops.forward_email.api import ForwardEmailApiError, ForwardEmailClient
from octodns_gitops.forward_email.config import (
    WRITE_ONLY_SETTINGS,
    ForwardEmailConfig,
    ForwardEmailConfigError,
    load_domain_file,
    load_forward_email,
)
from octodns_gitops.forward_email.drift import check_zone
from octodns_gitops.forward_email.export import export_domain
from octodns_gitops.forward_email.reconcile import DomainPlan, plan_domain


def zone_directory(config_path: str) -> Path | None:
    """The YamlProvider's `directory`, resolved relative to config.yaml."""
    cfg_file = Path(config_path)
    with open(cfg_file) as f:
        cfg = yaml.safe_load(f) or {}
    for prov in (cfg.get("providers") or {}).values():
        if isinstance(prov, dict) and str(prov.get("class", "")).endswith("YamlProvider"):
            d = Path(prov.get("directory", "./zones"))
            return d if d.is_absolute() else cfg_file.resolve().parent / d
    return None


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
    """Perform the writes for one domain. Returns False if the prune guard aborted.

    Order: settings PUT, prune re-list, creates/updates, deletes. The re-list must precede
    our own creates — they change the id set, so a create+delete plan would otherwise always
    abort half-applied.
    """
    body = plan.settings_body()
    if body:
        client.update_domain(plan.domain, body)
        out.write(f"  applied settings: {sorted(body)}\n")
    deletes = [c for c in plan.aliases if c.action == "delete"]
    if deletes and not _prune_still_safe(plan, deletes, client, out):
        return False
    for chg in plan.aliases:
        if chg.action == "create":
            client.create_alias(plan.domain, chg.body)
        elif chg.action == "update":
            client.update_alias(plan.domain, chg.alias_id, chg.body)
        else:
            continue
        out.write(f"  applied alias {chg.action} {chg.name}\n")
    for chg in deletes:
        client.delete_alias(plan.domain, chg.alias_id)
        out.write(f"  applied alias delete {chg.name}\n")
    return True


def _preserved_write_only(path: Path) -> dict:
    """Write-only settings declared in the existing per-domain file: the API cannot return them,
    so an export that overwrote the file would drop them and the next domain PUT would send the
    repo default instead."""
    if not path.exists():
        return {}
    with open(path) as f:
        existing = yaml.safe_load(f) or {}
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
    zone_dir: Path | None,
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
                zone_file = (zone_dir / f"{domain}.yaml") if zone_dir else None
                if zone_file is None or not zone_file.exists():
                    out.write(f"{domain:<28} no zone file in this repo; DNS records not checked\n")
                else:
                    with open(zone_file) as f:
                        zone = yaml.safe_load(f) or {}
                    settings = {**cfg.settings, **desired.settings}
                    for fnd in check_zone(live, zone, expect_mx=not settings.get("ignore_mx_check")):
                        findings.append((fnd.field, fnd.message))
                if findings:
                    rc = 1
                    out.write(f"{domain:<28} {len(findings)} finding(s)\n")
                    out.writelines(f"  {field}: {msg}\n" for field, msg in findings)
                elif zone_file is not None and zone_file.exists():
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
        zone_dir=zone_directory(args.config) if mode == "drift" else None,
        out=sys.stdout,
    )


if __name__ == "__main__":
    sys.exit(main())
