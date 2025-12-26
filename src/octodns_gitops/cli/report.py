#!/usr/bin/env python3
"""
Query live nameservers and show DNS consistency report.

Uses octodns-report to query multiple nameservers and compare responses,
showing any inconsistencies between nameservers.
"""

import argparse
import csv
import io
import os
import subprocess
import sys

import yaml
from tabulate import tabulate

from octodns_gitops.utils.config import (
    format_missing_credentials_error,
    is_credentials_error,
)


def zone_to_filename(zone: str) -> str:
    z = zone.rstrip(".")
    return f"zones/{z}.yaml"


def apex_nameservers(zone_file: str) -> list[str]:
    try:
        with open(zone_file, "r") as fh:
            data = yaml.safe_load(fh)
    except FileNotFoundError:
        return []

    apex = data.get("") or data.get(None)
    if not apex:
        return []

    # apex can be a single dict or a list of dicts
    records = apex if isinstance(apex, list) else [apex]

    for rec in records:
        if isinstance(rec, dict) and rec.get("type") == "NS":
            vals = rec.get("values") or []
            return [v.rstrip(".") for v in vals]
    return []


def iter_zones(cfg: dict, only_zone: str | None) -> list[str]:
    zones = list(cfg.get("zones", {}).keys())
    if only_zone:
        # ensure trailing dot for consistency
        z = only_zone if only_zone.endswith(".") else only_zone + "."
        return [z] if z in zones else []
    return zones


def truncate_value(value: str, max_len: int = 50) -> str:
    """Truncate long values for display."""
    if len(value) <= max_len:
        return value
    return value[: max_len - 3] + "..."


def format_report_output(csv_output: str, zone: str) -> None:
    """Parse CSV output from octodns-report and display formatted results."""
    if not csv_output.strip():
        print(f"No output for {zone}")
        return

    # Parse CSV
    reader = csv.DictReader(io.StringIO(csv_output))
    rows = list(reader)

    if not rows:
        print(f"No records found for {zone}")
        return

    # Separate consistent and inconsistent records
    inconsistent = [r for r in rows if r.get("Consistent") == "False"]

    # Print summary of inconsistencies
    if inconsistent:
        print(f"\nWarning: INCONSISTENCIES DETECTED ({len(inconsistent)} records)")
        print("=" * 80)
        summary_headers = ["Name", "Type", "Status"]
        summary_data = []
        for record in inconsistent:
            summary_data.append(
                [truncate_value(record["Name"], 40), record["Type"], "Inconsistent"]
            )
        print(tabulate(summary_data, headers=summary_headers, tablefmt="simple"))
        print()
    else:
        print(f"\nAll records consistent across nameservers")

    # Print full table with truncated values for readability
    print(f"\nFULL REPORT")
    print("=" * 80)

    # Determine server columns dynamically
    server_cols = [
        k for k in rows[0].keys() if k not in ["Name", "Type", "TTL", "Consistent"]
    ]

    headers = ["Name", "Type", "TTL"] + server_cols + ["OK"]
    table_data = []

    for record in rows:
        row = [truncate_value(record["Name"], 30), record["Type"], record["TTL"]]
        # Add server responses (truncated)
        for server in server_cols:
            row.append(truncate_value(record.get(server, ""), 40))
        # Consistent column
        row.append("Y" if record.get("Consistent") == "True" else "N")
        table_data.append(row)

    print(tabulate(table_data, headers=headers, tablefmt="grid"))
    print()


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--config", default="config.yaml")
    p.add_argument("--zone")
    p.add_argument("--source", default="zones")
    p.add_argument("--logging-config")
    args = p.parse_args()

    with open(args.config, "r") as fh:
        cfg = yaml.safe_load(fh)

    zones = iter_zones(cfg, args.zone or os.environ.get("ZONE"))
    if not zones:
        print("No zones to report", file=sys.stderr)
        return 1

    bin_dir = os.path.dirname(sys.executable)
    report_bin = os.path.join(bin_dir, "octodns-report")

    # verbosity flags: prefer DEBUG over QUIET
    debug = os.environ.get("DEBUG")
    quiet = os.environ.get("QUIET", "1")
    verbosity = "--debug" if debug else ("--quiet" if quiet else "")

    rc = 0
    for zone in zones:
        zone_file = zone_to_filename(zone)
        servers = apex_nameservers(zone_file)
        if not servers:
            # default to Hetzner authoritative NS if not present in file
            servers = [
                "helium.ns.hetzner.de",
                "hydrogen.ns.hetzner.com",
                "oxygen.ns.hetzner.com",
            ]

        cmd = [
            report_bin,
            "--config-file",
            args.config,
            "--zone",
            zone,
            "--source",
            args.source,
        ]
        if args.logging_config:
            cmd.extend(["--logging-config", args.logging_config])
        elif verbosity:
            cmd.append(verbosity)
        cmd.extend(servers)

        print(f"\n{'=' * 80}")
        print(f"  ZONE: {zone}")
        print(f"{'=' * 80}")
        try:
            result = subprocess.run(cmd, check=True, capture_output=True, text=True)
            format_report_output(result.stdout, zone)
        except subprocess.CalledProcessError as e:
            stderr = e.stderr or ""
            if is_credentials_error(stderr):
                print(
                    format_missing_credentials_error(args.config, stderr),
                    file=sys.stderr,
                )
            else:
                print(f"Error querying {zone}:", file=sys.stderr)
                # Only print the last line of stderr if it's a traceback
                if "Traceback" in stderr:
                    lines = stderr.strip().split("\n")
                    print(f"  {lines[-1]}", file=sys.stderr)
                else:
                    print(f"  {stderr}", file=sys.stderr)
            rc = e.returncode or 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
