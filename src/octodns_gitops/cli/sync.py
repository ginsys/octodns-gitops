#!/usr/bin/env python3
"""
Sync DNS zones with improved output formatting and safety thresholds.

Wrapper around octodns-sync with:
- Compact, readable output format
- Safety threshold warnings (30% update/delete)
- Improved error messages
"""

import argparse
import os
import re
import subprocess
import sys

from octodns_gitops.utils.config import (
    format_missing_credentials_error,
    is_credentials_error,
)


def parse_record_change(line: str) -> dict | None:
    """Parse a record from octodns output like '<ARecord A 1800, name., ['value']>'"""
    # Extract: type, name, TTL, values
    # Format: <ARecord A 1800, horseboxesheymans.be., ['5.134.5.11']>
    # Note: the line might have " ->" or " (zones)" after the >
    match = re.search(r"<(\w+Record)\s+(\w+)\s+(\d+),\s+([^,]+?)\.,\s+(.+?)>", line)
    if match:
        record_class, rtype, ttl, full_name, values = match.groups()
        # Extract subdomain from full domain name
        # e.g., "www.horseboxesheymans.be" -> "www", "horseboxesheymans.be" -> "@"
        # The last part is always the zone name, we want the subdomain part
        parts = full_name.split(".")
        if len(parts) <= 2:  # Zone apex (domain.tld)
            name = "@"
        else:
            # Take all parts except last 2 (which is domain.tld), join with dots
            name = ".".join(parts[:-2])

        return {"type": rtype, "name": name, "ttl": int(ttl), "values": values.strip()}
    return None


def format_zone_changes(zone_data: dict) -> list[str]:
    """Format a zone's changes compactly"""
    lines = []

    # Zone header with counts
    counts = []
    if zone_data["creates"]:
        counts.append(
            f"{zone_data['creates']} create{'s' if zone_data['creates'] != 1 else ''}"
        )
    if zone_data["updates"]:
        counts.append(
            f"{zone_data['updates']} update{'s' if zone_data['updates'] != 1 else ''}"
        )
    if zone_data["deletes"]:
        counts.append(
            f"{zone_data['deletes']} delete{'s' if zone_data['deletes'] != 1 else ''}"
        )

    if not counts:
        return []  # Skip zones with no changes

    lines.append(f"{zone_data['name']} ({', '.join(counts)})")

    # Format each change
    for change in zone_data["changes"]:
        lines.append(f"  {change}")

    return lines


def detect_threshold_violations(zones: list[dict]) -> list[dict]:
    """Detect zones exceeding 30% safety threshold"""
    violations = []
    for zone_data in zones:
        existing = zone_data.get("existing", 0)
        if existing < 10:
            continue  # Threshold only applies for zones with >= 10 records

        updates = zone_data.get("updates", 0)
        deletes = zone_data.get("deletes", 0)

        update_pct = (updates / existing * 100) if existing > 0 else 0
        delete_pct = (deletes / existing * 100) if existing > 0 else 0

        if update_pct > 30:
            violations.append(
                {
                    "zone": zone_data["name"],
                    "type": "updates",
                    "count": updates,
                    "total": existing,
                    "pct": update_pct,
                }
            )
        elif delete_pct > 30:
            violations.append(
                {
                    "zone": zone_data["name"],
                    "type": "deletes",
                    "count": deletes,
                    "total": existing,
                    "pct": delete_pct,
                }
            )

    return violations


def parse_octodns_output(output: str) -> list[dict]:
    """Parse octodns-sync output and extract zone changes"""
    zones = []
    current_zone = None
    lines = output.split("\n")
    i = 0

    while i < len(lines):
        line = lines[i]

        # Zone header: "* zonename." (ends with period, no parentheses)
        if line.startswith("* ") and not line.startswith("*   ") and "(" not in line:
            zone_name = line[2:].strip()
            if zone_name.endswith("."):  # Only process zone names (not provider names)
                current_zone = {
                    "name": zone_name,
                    "changes": [],
                    "creates": 0,
                    "updates": 0,
                    "deletes": 0,
                    "existing": 0,
                }
                zones.append(current_zone)

        # Summary line: "*   Summary: ..."
        elif "*   Summary:" in line and current_zone:
            # Parse: Summary: Creates=0, Updates=3, Deletes=0, Existing=4, Meta=False
            match = re.search(
                r"Creates=(\d+), Updates=(\d+), Deletes=(\d+), Existing=(\d+)", line
            )
            if match:
                current_zone["creates"] = int(match.group(1))
                current_zone["updates"] = int(match.group(2))
                current_zone["deletes"] = int(match.group(3))
                current_zone["existing"] = int(match.group(4))

        # Change lines start with "*   Create/Update/Delete"
        elif line.startswith("*   Create ") and current_zone:
            # Format: *   Create <ARecord A 1800, name., ['value']> (source)
            record = parse_record_change(line)
            if record:
                current_zone["changes"].append(
                    f"+ {record['type']} {record['name']} {record['values']}"
                )

        elif line.startswith("*   Update") and current_zone:
            # Next 2 lines have old -> new
            if i + 2 < len(lines):
                old_line = lines[i + 1]
                new_line = lines[i + 2]
                old_rec = parse_record_change(old_line)
                new_rec = parse_record_change(new_line)

                if old_rec and new_rec:
                    # Check if it's TTL-only or value change
                    if old_rec["values"] == new_rec["values"]:
                        # TTL change only
                        current_zone["changes"].append(
                            f"~ {new_rec['type']} {new_rec['name']} TTL {old_rec['ttl']}->{new_rec['ttl']}"
                        )
                    else:
                        # Value change
                        current_zone["changes"].append(
                            f"~ {new_rec['type']} {new_rec['name']} {old_rec['values']}->{new_rec['values']}"
                        )
                i += 3  # Skip Update line + old line + new line, then continue
                continue

        elif line.startswith("*   Delete ") and current_zone:
            # Format: *   Delete <ARecord A 1800, name., ['value']>
            record = parse_record_change(line)
            if record:
                current_zone["changes"].append(f"- {record['type']} {record['name']}")

        i += 1

    return zones


def main() -> int:
    p = argparse.ArgumentParser(
        description="Sync DNS zones (wrapper around octodns-sync)"
    )
    p.add_argument("--config", default="config.yaml", help="Config file")
    p.add_argument("--logging-config", help="Logging config file")
    p.add_argument("--zone", help="Specific zone to sync (optional)")
    p.add_argument(
        "--doit", action="store_true", help="Actually apply changes (not dry-run)"
    )
    p.add_argument(
        "--force", action="store_true", help="Force apply despite safety thresholds"
    )
    args = p.parse_args()

    bin_dir = os.path.dirname(sys.executable)
    sync_bin = os.path.join(bin_dir, "octodns-sync")

    # verbosity flags
    debug = os.environ.get("DEBUG")
    quiet = os.environ.get("QUIET", "1")

    cmd = [sync_bin, "--config-file", args.config]

    if args.doit:
        cmd.append("--doit")

    # For plan mode (dry-run), always force to see all changes
    # For apply mode, only force if user explicitly requests it
    if not args.doit:
        cmd.append("--force")
    elif args.force:
        cmd.append("--force")

    if args.logging_config:
        cmd.extend(["--logging-config", args.logging_config])
    elif debug:
        cmd.append("--debug")
    elif quiet:
        cmd.append("--quiet")

    if args.zone:
        cmd.append(args.zone)

    # Set PYTHONPATH
    env = os.environ.copy()
    env["PYTHONPATH"] = os.getcwd()

    result = subprocess.run(cmd, env=env, capture_output=True, text=True)

    if result.returncode != 0:
        # Error occurred - provide clean error message
        stderr = result.stderr or ""

        if is_credentials_error(stderr):
            print(
                format_missing_credentials_error(args.config, stderr), file=sys.stderr
            )
        else:
            action = "apply changes" if args.doit else "sync zones"
            print(f"Failed to {action}", file=sys.stderr)
            if stderr:
                # Only print the last line if it's a traceback
                if "Traceback" in stderr:
                    lines = stderr.strip().split("\n")
                    print(f"  {lines[-1]}", file=sys.stderr)
                else:
                    # Print stderr but limit to last 10 lines
                    lines = stderr.strip().split("\n")
                    for line in lines[-10:]:
                        print(f"  {line}", file=sys.stderr)

        return result.returncode or 1

    # Success - parse and reformat output
    # octodns outputs to stderr (plan/logging output)
    stderr = result.stderr or ""

    # Check if there are no changes
    if "No changes were planned" in stderr:
        print("No changes")
        return 0

    # Parse the octodns output (from stderr)
    zones = parse_octodns_output(stderr)

    # Print compact formatted output
    for zone_data in zones:
        formatted = format_zone_changes(zone_data)
        for line in formatted:
            print(line)
        if formatted:  # Add blank line between zones
            print()

    # Detect and warn about threshold violations
    violations = detect_threshold_violations(zones)
    if violations:
        print("Warning: Safety threshold exceeded:")
        for v in violations:
            print(
                f"   {v['zone']}: {v['pct']:.0f}% {v['type']} ({v['count']}/{v['total']} records)"
            )
        print(f"\n   To apply: make apply FORCE=1")

    return 0


if __name__ == "__main__":
    sys.exit(main())
