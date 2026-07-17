"""Resolve the intended DS + DNSKEY material to publish, from signer DNS data.

CDS/CDNSKEY are the source of truth (they express the signer's intended parent
state and stay correct across rollovers). We validate them against the
authoritative DNSKEY RRset before trusting them, refuse RFC 8078 delete signals
during enablement, and fall back to DNSKEY-derived DS (with a warning) only when
no CDS/CDNSKEY is published.
"""

from __future__ import annotations

from dataclasses import dataclass

from octodns_gitops.dnssec.keys import (
    DEFAULT_DIGEST_TYPES,
    DIGEST_SHA256,
    DnskeyRecord,
    DsRecord,
    cdnskey_ds_in_intended_set,
    cds_consistent_with_dnskeys,
    dnskey_to_ds,
    select_delegation_dnskeys,
)
from octodns_gitops.dnssec.source import SignerKeys


class SignerIntentError(ValueError):
    """The signer's published key material is unusable for enablement."""


@dataclass(frozen=True)
class IntendedDelegation:
    ds_records: list[DsRecord]
    dnskey_records: list[DnskeyRecord]
    source: str  # "cds" or "dnskey-derived"
    warnings: list[str]


def resolve_intended_delegation(
    zone: str,
    sk: SignerKeys,
    digest_types: tuple[int, ...] = DEFAULT_DIGEST_TYPES,
) -> IntendedDelegation:
    """Compute the DS + DNSKEY to publish for `zone` from signer DNS data."""
    warnings: list[str] = []

    # Refuse delete signals during initial enablement.
    if any(d.is_delete_signal() for d in sk.cds) or any(
        k.is_delete_signal() for k in sk.cdnskey
    ):
        raise SignerIntentError(
            f"{zone}: signer publishes an RFC 8078 delete signal; refusing to "
            "publish DS (this turns DNSSEC OFF, not on)"
        )

    dnskeys = select_delegation_dnskeys(sk.dnskeys)
    if not dnskeys:
        raise SignerIntentError(f"{zone}: no KSK (flag-257) DNSKEY at the signer")

    if sk.cds:
        if not cds_consistent_with_dnskeys(sk.cds, sk.dnskeys, zone):
            raise SignerIntentError(
                f"{zone}: published CDS is inconsistent with the DNSKEY RRset; "
                "refusing to trust it"
            )
        # CDS is the source of truth: publish only the DNSKEYs it selects, so a
        # pre-published/retiring KSK present in the DNSKEY RRset but intentionally
        # absent from CDS is NOT sent to the registrar.
        cds_keytags = {d.keytag for d in sk.cds}
        intended_dnskeys = [
            k
            for k in dnskeys
            if dnskey_to_ds(zone, k, (DIGEST_SHA256,))[0].keytag in cds_keytags
        ]
        if not intended_dnskeys:
            raise SignerIntentError(
                f"{zone}: CDS keytags {sorted(cds_keytags)} match no DNSKEY"
            )
        # If CDNSKEY is also published, it must agree with the intended DS set.
        if sk.cdnskey and not cdnskey_ds_in_intended_set(
            sk.cdnskey, list(sk.cds), zone
        ):
            raise SignerIntentError(
                f"{zone}: published CDNSKEY is inconsistent with CDS; refusing"
            )
        return IntendedDelegation(
            ds_records=list(sk.cds),
            dnskey_records=intended_dnskeys,
            source="cds",
            warnings=warnings,
        )

    # No CDS, but CDNSKEY also expresses parent-delegation intent: treat it as
    # the source of truth (each CDNSKEY must be in the authoritative DNSKEY set).
    if sk.cdnskey:
        for ck in sk.cdnskey:
            if ck not in sk.dnskeys:
                raise SignerIntentError(
                    f"{zone}: published CDNSKEY is not in the DNSKEY RRset; refusing"
                )
        intended_dnskeys = [k for k in sk.cdnskey if k.is_ksk()]
        if not intended_dnskeys:
            raise SignerIntentError(f"{zone}: CDNSKEY contains no KSK (flag-257)")
        ds = []
        for k in intended_dnskeys:
            ds.extend(dnskey_to_ds(zone, k, digest_types))
        return IntendedDelegation(
            ds_records=ds,
            dnskey_records=intended_dnskeys,
            source="cdnskey",
            warnings=warnings,
        )

    # No CDS/CDNSKEY: derive DS from the KSK(s), with a warning.
    warnings.append(
        f"{zone}: signer publishes no CDS/CDNSKEY; deriving DS from DNSKEY (weaker intent)"
    )
    ds: list[DsRecord] = []
    for k in dnskeys:
        ds.extend(dnskey_to_ds(zone, k, digest_types))
    return IntendedDelegation(
        ds_records=ds,
        dnskey_records=dnskeys,
        source="dnskey-derived",
        warnings=warnings,
    )
