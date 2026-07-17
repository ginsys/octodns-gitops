#!/usr/bin/env python3
"""Request a least-privilege OVH consumer key for the delegate/dnssec tooling.

OVH consumer keys can't be edited after creation, and hand-building access rules
in the web console is tedious. This requests a consumer key with the exact rules
pre-specified (`OVH_ACCESS_RULES`) via the OVH API; you then just open the
returned validation URL once (log in + confirm) instead of clicking rules.

Uses the application key/secret only (a consumer key is what we're creating), read
from `<prefix>_ENDPOINT/APPLICATION_KEY/APPLICATION_SECRET`.
"""

from __future__ import annotations

import argparse
import os
import sys

from octodns_gitops.registrar.ovh import OVH_ACCESS_RULES


def request_consumer_key(client, access_rules=OVH_ACCESS_RULES) -> dict:
    """Ask OVH for a consumer key scoped to `access_rules` (injectable client)."""
    return client.request_consumerkey(access_rules)


def _build_client(prefix: str):
    endpoint = os.environ.get(f"{prefix}_ENDPOINT")
    app_key = os.environ.get(f"{prefix}_APPLICATION_KEY")
    app_secret = os.environ.get(f"{prefix}_APPLICATION_SECRET")
    missing = [
        n
        for n, v in [
            (f"{prefix}_ENDPOINT", endpoint),
            (f"{prefix}_APPLICATION_KEY", app_key),
            (f"{prefix}_APPLICATION_SECRET", app_secret),
        ]
        if not v
    ]
    if missing:
        raise SystemExit(f"missing env vars: {missing}")
    import ovh  # lazy

    return ovh.Client(
        endpoint=endpoint, application_key=app_key, application_secret=app_secret
    )


def main() -> int:
    p = argparse.ArgumentParser(
        description="Request a least-privilege OVH consumer key"
    )
    p.add_argument(
        "--env-prefix",
        default="OVH",
        help="Credential env-var prefix (e.g. OVH_AUTOPS)",
    )
    args = p.parse_args()

    client = _build_client(args.env_prefix)
    res = request_consumer_key(client)

    print("Requested access rules (least-privilege):")
    for r in OVH_ACCESS_RULES:
        print(f"  {r['method']:5} {r['path']}")
    print()
    print(f"Consumer key : {res['consumerKey']}")
    print(f"Validate here: {res['validationUrl']}")
    print("  -> open the URL, log in, confirm (choose 'Unlimited' validity).")
    print()
    print("Then set and re-source:")
    print(f"  export {args.env_prefix}_CONSUMER_KEY={res['consumerKey']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
