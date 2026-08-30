"""Compare Forward Email's server-generated DNS records with the repo's octoDNS zone file.

`smtp_dns_records` (DKIM key, return-path CNAME, suggested DMARC) and `verification_record`
are *inputs* to the zone file, so a mismatch means the zone file is stale, not the account.
DMARC is special: FE suggests `p=reject`, the repo publishes its own ramped policy — only the
FE `rua` address must be present. `has_strict_dmarc` is derived by FE from what it sees in
DNS, so the expectation is derived from the zone file's own `p=` value.

MX (unless the domain sets `ignore_mx_check`): FE documents itself as the domain's only mail
exchanger, so the apex must list exactly `mx1`/`mx2.forwardemail.net` at one shared preference.
Any other exchanger is a finding — a lower preference routes mail away from FE, a higher one is a
backup FE knows nothing about; split routing opts out with `ignore_mx_check`.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

FE_MX = {"mx1.forwardemail.net", "mx2.forwardemail.net"}


@dataclass(frozen=True)
class DriftFinding:
    field: str
    message: str


def merge_zones(zones: list[dict]) -> dict:
    """One record set from several YAML sources of the same zone (octoDNS merges its sources):
    entries under the same name concatenate, so `_records` sees all of them."""
    merged: dict = {}
    for zone in zones:
        for name, entry in zone.items():
            if name in merged:
                prev = merged[name]
                merged[name] = (prev if isinstance(prev, list) else [prev]) + (
                    entry if isinstance(entry, list) else [entry]
                )
            else:
                merged[name] = entry
    return merged


def _records(zone: dict, name: str, rtype: str) -> list[dict]:
    """Records of `name`/`rtype`; DNS names are case-insensitive, so the key match is too."""
    want = name.lower()
    entries: list = []
    for key, entry in zone.items():
        if entry is None or str(key).lower() != want:
            continue
        entries.extend(entry if isinstance(entry, list) else [entry])
    return [r for r in entries if isinstance(r, dict) and r.get("type") == rtype]


def _values(zone: dict, name: str, rtype: str) -> list:
    """All values of `name`/`rtype`; `value:` may itself hold a list in hand-written zone files."""
    out = []
    for r in _records(zone, name, rtype):
        for key in ("values", "value"):
            v = r.get(key)
            if v is None:
                continue
            out.extend(v if isinstance(v, list) else [v])
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


def _rua_uris(tag: str) -> set[str]:
    """The complete URIs of a `rua=` tag, compared exactly — never as substrings, which would
    accept `mailto:x@forwardemail.net.example.org`. Mail addresses compare case-insensitively
    and without an RFC 7489 `!size` suffix."""
    out = set()
    for uri in tag.split(","):
        uri = uri.strip()
        if uri.lower().startswith("mailto:"):
            uri = uri.split("!", 1)[0].lower()
        if uri:
            out.add(uri)
    return out


def check_zone(live_domain: dict, zone: dict, *, expect_mx: bool) -> list[DriftFinding]:
    findings: list[DriftFinding] = []
    recs = live_domain.get("smtp_dns_records") or {}
    # A key FE did not return is unverifiable, never "clean".
    findings.extend(
        DriftFinding(k, f"Forward Email returned no smtp_dns_records.{k}; cannot verify the zone file")
        for k in ("dkim", "return_path", "dmarc")
        if not recs.get(k)
    )

    dkim = recs.get("dkim")
    if dkim:
        got = [_unescape_txt(v) for v in _values(zone, dkim["name"], "TXT")]
        if _unescape_txt(dkim["value"]) not in got:
            findings.append(
                DriftFinding("dkim", f"{dkim['name']} TXT: zone has {got or 'nothing'}, FE issues a different key")
            )

    rp = recs.get("return_path")
    if rp:
        # Hostnames are case-insensitive: `ForwardEmail.NET.` is the same target.
        got = [str(v).rstrip(".").lower() for v in _values(zone, rp["name"], "CNAME")]
        if rp["value"].rstrip(".").lower() not in got:
            findings.append(DriftFinding("return_path", f"{rp['name']} CNAME: expected {rp['value']}, zone has {got}"))

    token = live_domain.get("verification_record")
    if not token:
        findings.append(
            DriftFinding("verification", "Forward Email returned no verification_record; cannot verify the apex TXT")
        )
    else:
        want = f"forward-email-site-verification={token}"
        if want not in [_unescape_txt(v) for v in _values(zone, "", "TXT")]:
            findings.append(DriftFinding("verification", f"apex TXT {want} missing"))

    dmarc = recs.get("dmarc")
    zone_dmarc = _values(zone, "_dmarc", "TXT")
    if dmarc:
        fe_rua = _rua_uris(_dmarc_tags(dmarc["value"]).get("rua", ""))
        published = [_rua_uris(_dmarc_tags(v).get("rua", "")) for v in zone_dmarc]
        if not fe_rua or not any(fe_rua <= p for p in published):
            findings.append(
                DriftFinding("dmarc", f"_dmarc TXT does not report to FE ({', '.join(sorted(fe_rua)) or 'no rua'})")
            )

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
        findings.extend(_check_mx(_values(zone, "", "MX")))

    return findings


def _check_mx(values: list) -> list[DriftFinding]:
    """octoDNS accepts `exchange`/`preference` and the legacy `value`/`priority` spellings.

    Every preference of every entry is kept (a host may be listed twice), so the FE pair must
    resolve to exactly one integer preference across all of its entries. An entry that is not an
    exchange mapping is reported, never skipped: "exactly FE" cannot be claimed over it.
    """
    prefs: dict[str, set] = {}
    malformed = []
    for v in values:
        host = str(v.get("exchange", v.get("value", ""))).rstrip(".").lower() if isinstance(v, dict) else ""
        if not host:
            malformed.append(v)
            continue
        prefs.setdefault(host, set()).add(v.get("preference", v.get("priority")))
    out = []
    if malformed:
        out.append(DriftFinding("mx", f"apex MX has malformed value(s) {malformed!r}; expected exchange/preference mappings"))
    if not FE_MX <= set(prefs):
        out.append(DriftFinding("mx", f"apex MX {sorted(prefs) or 'missing'} does not include {sorted(FE_MX)}"))
        return out
    fe_prefs = set().union(*(prefs[h] for h in FE_MX))
    if len(fe_prefs) != 1 or not all(isinstance(p, int) and not isinstance(p, bool) for p in fe_prefs):
        out.append(
            DriftFinding(
                "mx",
                f"apex MX preferences for the FE exchangers are {sorted(map(str, fe_prefs))}; "
                "both must share exactly one integer preference",
            )
        )
    others = sorted(set(prefs) - FE_MX)
    if others:
        out.append(
            DriftFinding(
                "mx",
                f"apex MX also lists {others}; Forward Email must be the only exchanger "
                "(set ignore_mx_check: true for deliberate split routing)",
            )
        )
    return out
