"""Compare Forward Email's server-generated DNS records with the repo's octoDNS zone file.

`smtp_dns_records` (DKIM key, return-path CNAME, suggested DMARC) and `verification_record`
are *inputs* to the zone file, so a mismatch means the zone file is stale, not the account.
DMARC is special: FE suggests `p=reject`, the repo publishes its own ramped policy — only the
FE `rua` address must be present. `has_strict_dmarc` is derived by FE from what it sees in
DNS, so the expectation is derived from the zone file's own `p=` value.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

FE_MX = {"mx1.forwardemail.net", "mx2.forwardemail.net"}


@dataclass(frozen=True)
class DriftFinding:
    field: str
    message: str


def _records(zone: dict, name: str, rtype: str) -> list[dict]:
    entry = zone.get(name)
    if entry is None:
        return []
    entries = entry if isinstance(entry, list) else [entry]
    return [r for r in entries if r.get("type") == rtype]


def _values(zone: dict, name: str, rtype: str) -> list:
    out = []
    for r in _records(zone, name, rtype):
        if "values" in r:
            out.extend(r["values"])
        elif "value" in r:
            out.append(r["value"])
    return out


def _unescape_txt(v: str) -> str:
    return re.sub(r"\s+", " ", v.replace("\\;", ";")).strip()


def _dmarc_tags(v: str) -> dict:
    tags = {}
    for part in _unescape_txt(v).split(";"):
        if "=" in part:
            k, val = part.split("=", 1)
            tags[k.strip().lower()] = val.strip()
    return tags


def check_zone(live_domain: dict, zone: dict, *, expect_mx: bool) -> list[DriftFinding]:
    findings: list[DriftFinding] = []
    recs = live_domain.get("smtp_dns_records") or {}

    dkim = recs.get("dkim")
    if dkim:
        got = [_unescape_txt(v) for v in _values(zone, dkim["name"], "TXT")]
        if _unescape_txt(dkim["value"]) not in got:
            findings.append(
                DriftFinding("dkim", f"{dkim['name']} TXT: zone has {got or 'nothing'}, FE issues a different key")
            )

    rp = recs.get("return_path")
    if rp:
        got = [v.rstrip(".") for v in _values(zone, rp["name"], "CNAME")]
        if rp["value"].rstrip(".") not in got:
            findings.append(DriftFinding("return_path", f"{rp['name']} CNAME: expected {rp['value']}, zone has {got}"))

    token = live_domain.get("verification_record")
    if token:
        want = f"forward-email-site-verification={token}"
        if want not in [_unescape_txt(v) for v in _values(zone, "", "TXT")]:
            findings.append(DriftFinding("verification", f"apex TXT {want} missing"))

    dmarc = recs.get("dmarc")
    zone_dmarc = _values(zone, "_dmarc", "TXT")
    if dmarc:
        fe_rua = _dmarc_tags(dmarc["value"]).get("rua", "")
        published = [_dmarc_tags(v) for v in zone_dmarc]
        if not any(fe_rua and fe_rua in t.get("rua", "") for t in published):
            findings.append(DriftFinding("dmarc", f"_dmarc TXT does not report to FE ({fe_rua or 'no rua'})"))

    if "has_strict_dmarc" in live_domain and zone_dmarc:
        strict = any(_dmarc_tags(v).get("p", "").lower() == "reject" for v in zone_dmarc)
        if bool(live_domain["has_strict_dmarc"]) != strict:
            findings.append(
                DriftFinding(
                    "has_strict_dmarc",
                    f"FE reports has_strict_dmarc={live_domain['has_strict_dmarc']}, zone publishes "
                    f"p={'reject' if strict else 'non-reject'} (FE re-derives this on its next verification)",
                )
            )

    if expect_mx:
        got = {v["exchange"].rstrip(".").lower() for v in _values(zone, "", "MX") if isinstance(v, dict)}
        if not FE_MX <= got:
            findings.append(DriftFinding("mx", f"apex MX {sorted(got) or 'missing'} does not include {sorted(FE_MX)}"))

    return findings
