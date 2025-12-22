#!/usr/bin/env python3
"""
Check for drift between live DNS and local zone files.

Uses octodns-sync in reverse direction (live as source, local as target)
to detect if live DNS has drifted from the configured zones.

Exit codes:
  0 - No drift detected (live matches local)
  1 - Drift detected (live differs from local)
  2 - Error occurred
"""

import argparse
import os
import subprocess
import sys
import tempfile

import yaml

from octodns_gitops.utils.config import (
    format_missing_credentials_error,
    is_credentials_error,
)


def generate_drift_config(config_path: str, output_path: str) -> None:
    """
    Generate a config for drift detection by reversing source/target.

    For each zone:
      - Original: sources=[zones], targets=[live-provider]
      - Reversed: sources=[live-provider], targets=[zones]
    """
    with open(config_path, "r") as f:
        cfg = yaml.safe_load(f)

    providers = cfg.get("providers", {})
    zones = cfg.get("zones", {})

    # Build reversed zone config
    reversed_zones = {}
    for zone_name, zone_cfg in zones.items():
        targets = zone_cfg.get("targets", [])
        if not targets:
            continue

        reversed_zones[zone_name] = {
            "sources": list(targets),  # Live providers become sources
            "targets": ["zones"],  # Local YAML becomes target
        }

    out_cfg = {
        "providers": providers,
        "zones": reversed_zones,
    }

    # Copy processors and manager config
    if "processors" in cfg:
        out_cfg["processors"] = cfg["processors"]
    if "manager" in cfg:
        out_cfg["manager"] = cfg["manager"]

    with open(output_path, "w") as f:
        yaml.safe_dump(out_cfg, f, sort_keys=False)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Check for drift between live DNS and local zones"
    )
    p.add_argument("--config", default="config.yaml", help="Config file")
    p.add_argument("--logging-config", help="Logging config file")
    p.add_argument("--zone", help="Specific zone to check (optional)")
    args = p.parse_args()

    bin_dir = os.path.dirname(sys.executable)
    sync_bin = os.path.join(bin_dir, "octodns-sync")

    # Generate reversed config in temp file
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        drift_config_path = f.name

    try:
        generate_drift_config(args.config, drift_config_path)

        # Run octodns-sync in dry-run mode (no --doit)
        cmd = [
            sync_bin,
            "--config-file",
            drift_config_path,
            "--force",  # Show all changes regardless of threshold
        ]

        debug = os.environ.get("DEBUG")
        quiet = os.environ.get("QUIET", "1")

        if args.logging_config:
            cmd.extend(["--logging-config", args.logging_config])
        elif debug:
            cmd.append("--debug")
        elif quiet:
            cmd.append("--quiet")

        if args.zone:
            cmd.append(args.zone)

        env = os.environ.copy()
        env["PYTHONPATH"] = os.getcwd()

        result = subprocess.run(cmd, env=env, capture_output=True, text=True)

        if result.returncode != 0:
            stderr = result.stderr or ""
            if is_credentials_error(stderr):
                print(
                    format_missing_credentials_error(args.config, stderr),
                    file=sys.stderr,
                )
            else:
                print("Failed to check drift", file=sys.stderr)
                if stderr:
                    lines = stderr.strip().split("\n")
                    for line in lines[-10:]:
                        print(f"  {line}", file=sys.stderr)
            return 2

        stderr = result.stderr or ""

        # Check if there are no changes (no drift)
        if "No changes were planned" in stderr:
            print("No drift detected")
            return 0

        # Drift detected - show what's different
        print("Drift detected: live DNS differs from local zones")
        print()
        print("Changes needed to sync live -> local:")
        print(stderr)
        return 1

    finally:
        # Clean up temp file
        if os.path.exists(drift_config_path):
            os.unlink(drift_config_path)


if __name__ == "__main__":
    sys.exit(main())
