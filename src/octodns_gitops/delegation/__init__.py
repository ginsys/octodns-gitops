"""Opt-in DNSSEC delegation configuration and orchestration.

`config.py` parses the `delegation:` block and derives, per opted-in zone, the
octoDNS signer target and the nameservers to delegate to — all from the existing
`config.yaml`, no vendor lock-in.
"""
