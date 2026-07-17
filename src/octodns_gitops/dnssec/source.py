"""DNS-based (provider-agnostic) source of signer keys and parent DS state.

We read the signer's *intent* straight from DNS rather than a vendor API:
- CDS/CDNSKEY/DNSKEY from the signer's authoritative nameservers (works
  pre-cutover because we query those nameservers directly);
- DS from the authoritative parent nameservers (source of truth) and from a
  recursive resolver (propagation view);
- the AD bit from a validating resolver.

The single network primitive `_query` is module-level so tests can monkeypatch it.
"""

from __future__ import annotations

from dataclasses import dataclass

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver

from octodns_gitops.dnssec.keys import DnskeyRecord, DsRecord, parse_dnskey, parse_ds

DEFAULT_VALIDATING_RESOLVER = "1.1.1.1"


@dataclass(frozen=True)
class SignerKeys:
    dnskeys: list[DnskeyRecord]
    cds: list[DsRecord]
    cdnskey: list[DnskeyRecord]


@dataclass(frozen=True)
class AdResult:
    rcode: str
    ad: bool
    ra: bool

    @property
    def validated(self) -> bool:
        # Design contract: NOERROR + recursion-available + authenticated-data.
        return self.rcode == "NOERROR" and self.ad and self.ra


def _resolve_host(host: str) -> list[str]:
    """Resolve a nameserver hostname to IP addresses (A + AAAA)."""
    ips: list[str] = []
    for rd in ("A", "AAAA"):
        try:
            ans = dns.resolver.resolve(host, rd)
            ips.extend(r.address for r in ans)
        except Exception:
            pass
    return ips


def _query(qname: str, rdtype: str, server_ip: str, timeout: float = 5.0):
    """Query one server for (qname, rdtype). Returns rdata text strings.

    Tries UDP then TCP on truncation. Module-level so tests can monkeypatch it.
    """
    name = dns.name.from_text(qname)
    q = dns.message.make_query(
        name, dns.rdatatype.from_text(rdtype), want_dnssec=True
    )
    resp = dns.query.udp(q, server_ip, timeout=timeout)
    if resp.flags & dns.flags.TC:
        resp = dns.query.tcp(q, server_ip, timeout=timeout)
    out: list[str] = []
    wanted = dns.rdatatype.from_text(rdtype)
    for rrset in resp.answer:
        if rrset.rdtype == wanted:
            out.extend(r.to_text() for r in rrset)
    return out


def _query_via_hosts(qname: str, rdtype: str, nameservers: list[str]) -> list[str]:
    """Query the first reachable nameserver (by hostname) for records."""
    last_err: Exception | None = None
    for host in nameservers:
        for ip in _resolve_host(host):
            try:
                return _query(qname, rdtype, ip)
            except Exception as e:  # try the next server/ip
                last_err = e
    if last_err:
        raise last_err
    return []


def fetch_from_signer(zone: str, nameservers: list[str]) -> SignerKeys:
    """Fetch DNSKEY, CDS and CDNSKEY for `zone` from the signer's nameservers."""
    dnskeys = [parse_dnskey(t) for t in _query_via_hosts(zone, "DNSKEY", nameservers)]
    cds = [parse_ds(t) for t in _query_via_hosts(zone, "CDS", nameservers)]
    cdnskey = [
        parse_dnskey(t) for t in _query_via_hosts(zone, "CDNSKEY", nameservers)
    ]
    return SignerKeys(dnskeys=dnskeys, cds=cds, cdnskey=cdnskey)


def _parent_nameserver_ips(domain: str) -> list[str]:
    """IPs of the authoritative nameservers of `domain`'s parent zone."""
    name = dns.name.from_text(domain)
    parent = name.parent()
    ns_hosts = [r.target.to_text() for r in dns.resolver.resolve(parent, "NS")]
    ips: list[str] = []
    for h in ns_hosts:
        ips.extend(_resolve_host(h))
    return ips


def parent_ds_authoritative(domain: str) -> list[DsRecord]:
    """DS for `domain` as published by the authoritative parent nameservers."""
    for ip in _parent_nameserver_ips(domain):
        try:
            return [parse_ds(t) for t in _query(domain, "DS", ip)]
        except Exception:
            continue
    return []


def parent_ds_recursive(
    domain: str, resolver: str = DEFAULT_VALIDATING_RESOLVER
) -> list[DsRecord]:
    """DS for `domain` as observed via a recursive resolver (propagation view)."""
    return [parse_ds(t) for t in _query(domain, "DS", resolver)]


def observed_nameservers(zone: str) -> list[str]:
    """Currently-authoritative NS for `zone` (lowercased, no trailing dot).

    Used to observe delegation state when there is no registrar API (manual
    zones): once the NS at the registrar are changed and propagate, this reflects
    the new (signer) nameservers.
    """
    try:
        ans = dns.resolver.resolve(zone, "NS")
    except Exception:
        return []
    return sorted(r.target.to_text().lower().rstrip(".") for r in ans)


def check_ad(zone: str, resolver: str = DEFAULT_VALIDATING_RESOLVER) -> AdResult:
    """Query an existing record (SOA) with AD requested; report rcode/ad/ra.

    Equivalent to `dig +adflag +dnssec SOA <zone>. @<resolver>` — the AD bit is
    the validating resolver's verdict; bare +dnssec doesn't guarantee AD.
    """
    name = dns.name.from_text(zone)
    q = dns.message.make_query(name, dns.rdatatype.SOA, want_dnssec=True)
    q.flags |= dns.flags.AD  # request AD explicitly
    resp = dns.query.udp(q, resolver, timeout=5.0)
    if resp.flags & dns.flags.TC:
        resp = dns.query.tcp(q, resolver, timeout=5.0)
    return AdResult(
        rcode=dns.rcode.to_text(resp.rcode()),
        ad=bool(resp.flags & dns.flags.AD),
        ra=bool(resp.flags & dns.flags.RA),
    )
