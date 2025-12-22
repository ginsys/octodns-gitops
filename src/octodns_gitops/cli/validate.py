#!/usr/bin/env python3
"""
Validate DNS zone files.

Wrapper around octodns-validate with improved error messages.
"""

import argparse
import os
import subprocess
import sys

from octodns_gitops.utils.config import (
    format_missing_credentials_error,
    is_credentials_error,
)


def main() -> int:
    p = argparse.ArgumentParser(
        description="Validate DNS zones (wrapper around octodns-validate)"
    )
    p.add_argument("--config", default="config.yaml", help="Config file")
    p.add_argument("--logging-config", help="Logging config file")
    args = p.parse_args()

    bin_dir = os.path.dirname(sys.executable)
    validate_bin = os.path.join(bin_dir, "octodns-validate")

    # verbosity flags
    debug = os.environ.get("DEBUG")
    quiet = os.environ.get("QUIET", "1")

    cmd = [validate_bin, "--config-file", args.config]

    if args.logging_config:
        cmd.extend(["--logging-config", args.logging_config])
    elif debug:
        cmd.append("--debug")
    elif quiet:
        cmd.append("--quiet")

    # Set PYTHONPATH
    env = os.environ.copy()
    env["PYTHONPATH"] = os.getcwd()

    result = subprocess.run(cmd, env=env, capture_output=True, text=True)

    if result.returncode == 0:
        # Success - print output
        if result.stdout:
            print(result.stdout, end="")
        if result.stderr:
            print(result.stderr, end="", file=sys.stderr)
        return 0

    # Error occurred - provide clean error message
    stderr = result.stderr or ""

    if is_credentials_error(stderr):
        print(format_missing_credentials_error(args.config, stderr), file=sys.stderr)
    else:
        print("Validation failed", file=sys.stderr)
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


if __name__ == "__main__":
    sys.exit(main())
