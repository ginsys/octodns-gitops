"""DNSSEC delegation helpers: key parsing, DS derivation, and set comparison.

`keys.py` is pure logic (no network) and is the unit-tested core used by both the
`delegate` (write) and `dnssec` (validate) CLIs.
"""
