"""
Check for drift between live DNS and local zone files.

Uses octodns-sync in reverse direction (live as source, local as target)
to detect if live DNS has drifted from the configured zones.

One reversed run per live provider: reversing a multi-target zone's full
targets list into a single sources list would populate one octoDNS zone
object from every live provider, and any record present in more than one
of them raises DuplicateRecordException (octoDNS populates with
lenient=False). With a shadow-provider setup every record collides, so a
combined run can never work (#4).

Exit codes:
  0 - No drift detected (live matches local for every provider)
  1 - Drift detected (live differs from local in at least one provider)
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


def live_providers(zones: dict) -> list:
    """Every live provider named in any zone's targets, deduplicated,
    in first-appearance order."""
    providers = []
    for zone_cfg in zones.values():
        # a bare `targets:` key loads as None -- treat as empty, like
        # octoDNS's own manager does
        for target in (zone_cfg or {}).get("targets") or []:
            if target not in providers:
                providers.append(target)
    return providers


def generate_drift_config(config_path: str, output_path: str, provider: str) -> dict:
    """
    Generate a drift-detection config for ONE live provider.

    For each zone that targets `provider`:
      - Original: sources=[zones], targets=[..., provider, ...]
      - Reversed: sources=[provider], targets=[zones]

    Zones that do not target `provider` are excluded from this config.
    Returns the reversed zones mapping (useful to know whether a --zone
    filter applies to this provider at all).
    """
    with open(config_path, "r") as f:
        cfg = yaml.safe_load(f)

    providers = cfg.get("providers", {})
    zones = cfg.get("zones", {})

    # Build reversed zone config, scoped to this provider
    reversed_zones = {}
    for zone_name, zone_cfg in zones.items():
        targets = (zone_cfg or {}).get("targets") or []
        if provider not in targets:
            continue

        reversed_zones[zone_name] = {
            "sources": [provider],  # This live provider becomes the source
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

    return reversed_zones


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

    with open(args.config, "r") as f:
        cfg = yaml.safe_load(f)
    providers = live_providers(cfg.get("zones", {}))

    debug = os.environ.get("DEBUG")
    quiet = os.environ.get("QUIET", "1")
    env = os.environ.copy()
    env["PYTHONPATH"] = os.getcwd()

    drifted = {}  # provider -> octodns-sync plan output
    temp_paths = []
    try:
        for provider in providers:
            # One generated config and one octodns-sync run per provider
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".yaml", delete=False
            ) as f:
                drift_config_path = f.name
            temp_paths.append(drift_config_path)

            reversed_zones = generate_drift_config(
                args.config, drift_config_path, provider
            )

            if (
                args.zone
                and args.zone not in reversed_zones
                # a '*'-prefixed key is a dynamic zone entry only octoDNS
                # can expand -- the concrete zone may match it, so the
                # skip is only decidable when every key is concrete
                and not any(name.startswith("*") for name in reversed_zones)
            ):
                # This provider does not serve the requested zone
                continue

            # Run octodns-sync in dry-run mode (no --doit)
            cmd = [
                sync_bin,
                "--config-file",
                drift_config_path,
                "--force",  # Show all changes regardless of threshold
            ]

            if args.logging_config:
                cmd.extend(["--logging-config", args.logging_config])
            elif debug:
                cmd.append("--debug")
            elif quiet:
                cmd.append("--quiet")

            if args.zone:
                cmd.append(args.zone)

            result = subprocess.run(
                cmd, env=env, capture_output=True, text=True, check=False
            )

            if result.returncode != 0:
                stderr = result.stderr or ""
                if is_credentials_error(stderr):
                    print(
                        format_missing_credentials_error(args.config, stderr),
                        file=sys.stderr,
                    )
                else:
                    print(
                        f"Failed to check drift (provider: {provider})",
                        file=sys.stderr,
                    )
                    if stderr:
                        lines = stderr.strip().split("\n")
                        for line in lines[-10:]:
                            print(f"  {line}", file=sys.stderr)
                return 2

            stderr = result.stderr or ""

            # "No changes were planned" means this provider matches local
            if "No changes were planned" not in stderr:
                drifted[provider] = stderr

        if not drifted:
            print("No drift detected")
            return 0

        # Drift detected - show what's different, per provider
        print("Drift detected: live DNS differs from local zones")
        for provider, stderr in drifted.items():
            print()
            print(f"Changes needed to sync live -> local (provider: {provider}):")
            print(stderr)
        return 1

    finally:
        # Clean up temp files
        for path in temp_paths:
            if os.path.exists(path):
                os.unlink(path)


if __name__ == "__main__":
    sys.exit(main())
