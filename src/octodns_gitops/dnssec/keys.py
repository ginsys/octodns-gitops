"""Pure DNSSEC key/DS logic — parsing, DS derivation, and set comparison.

No network here. DS digests are computed with dnspython (`dns.dnssec.make_ds`) so
key-tag and digest calculation follow RFC 4034 exactly rather than being
re-implemented.

Terminology:
- A *DNSKEY* (or CDNSKEY) is ``<flags> <protocol> <algorithm> <base64 pubkey>``.
- A *DS* (or CDS) is ``<keytag> <algorithm> <digest_type> <digest hex>``.

Digest types we derive/compare: SHA-256 (2) as the minimum, SHA-384 (4) optional.
"""

from __future__ import annotations

from dataclasses import dataclass

import dns.dnssec
import dns.name
import dns.rdata
import dns.rdataclass
import dns.rdatatype

# Digest types (IANA). SHA-256 is the mandatory minimum; SHA-384 optional.
DIGEST_SHA256 = 2
DIGEST_SHA384 = 4
DEFAULT_DIGEST_TYPES = (DIGEST_SHA256,)

_DIGEST_NAME = {DIGEST_SHA256: "SHA256", DIGEST_SHA384: "SHA384"}

# RFC 8078 "delete" signals — used to turn DNSSEC *off*. We must never act on
# these during initial enablement.
CDS_DELETE = (0, 0, 0, "00")
CDNSKEY_DELETE = (0, 3, 0, "AA==")


@dataclass(frozen=True)
class DnskeyRecord:
    """A DNSKEY / CDNSKEY record."""

    flags: int
    protocol: int
    algorithm: int
    public_key: str  # base64, no whitespace

    def is_delete_signal(self) -> bool:
        return (
            self.flags,
            self.protocol,
            self.algorithm,
            self.public_key,
        ) == CDNSKEY_DELETE

    def is_ksk(self) -> bool:
        # Secure Entry Point bit (flag 257); KSK/CSK are used for the DS.
        return self.flags == 257

    def to_text(self) -> str:
        return f"{self.flags} {self.protocol} {self.algorithm} {self.public_key}"


@dataclass(frozen=True)
class DsRecord:
    """A DS / CDS record, normalized for comparison.

    Equality/hash use the ``(keytag, algorithm, digest_type, digest)`` tuple with
    an uppercase hex digest, so one digest type never masks another.
    """

    keytag: int
    algorithm: int
    digest_type: int
    digest: str  # hex, uppercase, no whitespace

    def __post_init__(self) -> None:
        object.__setattr__(self, "digest", self.digest.replace(" ", "").upper())

    def is_delete_signal(self) -> bool:
        return (
            self.keytag,
            self.algorithm,
            self.digest_type,
            self.digest,
        ) == (CDS_DELETE[0], CDS_DELETE[1], CDS_DELETE[2], CDS_DELETE[3].upper())

    @property
    def key(self) -> tuple[int, int, int, str]:
        return (self.keytag, self.algorithm, self.digest_type, self.digest)

    def to_text(self) -> str:
        return f"{self.keytag} {self.algorithm} {self.digest_type} {self.digest}"


def parse_dnskey(text: str) -> DnskeyRecord:
    """Parse a ``flags protocol algorithm base64...`` DNSKEY/CDNSKEY string."""
    parts = text.split()
    if len(parts) < 4:
        raise ValueError(f"malformed DNSKEY: {text!r}")
    flags, protocol, algorithm = (int(parts[0]), int(parts[1]), int(parts[2]))
    public_key = "".join(parts[3:])  # base64 may be space-split across fields
    return DnskeyRecord(flags, protocol, algorithm, public_key)


def parse_ds(text: str) -> DsRecord:
    """Parse a ``keytag algorithm digest_type digest...`` DS/CDS string."""
    parts = text.split()
    if len(parts) < 4:
        raise ValueError(f"malformed DS: {text!r}")
    keytag, algorithm, digest_type = (int(parts[0]), int(parts[1]), int(parts[2]))
    digest = "".join(parts[3:])
    return DsRecord(keytag, algorithm, digest_type, digest)


def dnskey_to_ds(
    owner: str,
    dnskey: DnskeyRecord,
    digest_types: tuple[int, ...] = DEFAULT_DIGEST_TYPES,
) -> list[DsRecord]:
    """Derive DS record(s) for a DNSKEY at ``owner`` for the given digest types.

    Uses dnspython so key-tag and digest match RFC 4034. ``owner`` is the zone
    name (trailing dot optional).
    """
    name = dns.name.from_text(owner)
    rdata = dns.rdata.from_text(
        dns.rdataclass.IN, dns.rdatatype.DNSKEY, dnskey.to_text()
    )
    out: list[DsRecord] = []
    for dt in digest_types:
        algo = _DIGEST_NAME.get(dt)
        if algo is None:
            raise ValueError(f"unsupported digest type {dt}")
        ds = dns.dnssec.make_ds(name, rdata, algo)
        out.append(
            DsRecord(ds.key_tag, ds.algorithm, ds.digest_type, ds.digest.hex())
        )
    return out


def select_delegation_dnskeys(dnskeys: list[DnskeyRecord]) -> list[DnskeyRecord]:
    """Keys eligible to anchor the delegation: flag-257, non-delete.

    (A DNS source has no 'managed' flag; a vendor adapter may pre-filter.)
    """
    return [k for k in dnskeys if k.is_ksk() and not k.is_delete_signal()]


def cds_consistent_with_dnskeys(
    cds: list[DsRecord],
    dnskeys: list[DnskeyRecord],
    owner: str,
    digest_types: tuple[int, ...] = (DIGEST_SHA256, DIGEST_SHA384),
) -> bool:
    """Every CDS digest must match a DNSKEY in the authoritative DNSKEY RRset.

    Pre-cutover we can't validate CDS through the parent chain, so this
    authoritative-consistency check is the guard: derive DS (for the relevant
    digest types) from every DNSKEY and require each CDS to be a member.
    """
    if not cds:
        return False
    derivable: set[tuple[int, int, int, str]] = set()
    for k in dnskeys:
        if k.is_delete_signal():
            continue
        for ds in dnskey_to_ds(owner, k, digest_types):
            derivable.add(ds.key)
    return all(c.key in derivable for c in cds)


def cdnskey_ds_in_intended_set(
    cdnskeys: list[DnskeyRecord],
    intended: list[DsRecord],
    owner: str,
    digest_types: tuple[int, ...] = DEFAULT_DIGEST_TYPES,
) -> bool:
    """Every CDNSKEY's derived DS (for our digest types) must be in ``intended``."""
    if not cdnskeys:
        return False
    intended_keys = {d.key for d in intended}
    for k in cdnskeys:
        if k.is_delete_signal():
            continue
        derived = dnskey_to_ds(owner, k, digest_types)
        if not any(d.key in intended_keys for d in derived):
            return False
    return True


@dataclass(frozen=True)
class DsComparison:
    """Result of comparing parent DS against the signer's intended DS set.

    ``present``/``missing``/``extra`` are exact-tuple lists (so one digest type
    never masks another, for precise reporting). ``ok`` is keytag-anchored: every
    intended KSK must have at least one *exact* intended DS present at the parent.
    A parent that publishes only one of several intended digest types (common —
    registries may keep a single digest) is therefore still OK.
    """

    present: list[DsRecord]  # intended DS also present at the parent (exact)
    missing: list[DsRecord]  # intended DS absent at the parent (exact)
    extra: list[DsRecord]  # parent DS not in the intended set (stale/rollover)
    anchored_keytags: frozenset  # intended keytags with an exact DS at the parent
    intended_keytags: frozenset  # all keytags the signer intends to anchor

    @property
    def ok(self) -> bool:
        return bool(self.intended_keytags) and self.intended_keytags <= self.anchored_keytags


def compare_ds(parent: list[DsRecord], intended: list[DsRecord]) -> DsComparison:
    """Set-membership comparison over normalized tuples (not exact equality).

    ``extra`` parent DS is surfaced as a warning by callers, not a hard failure —
    planned key rollovers have legitimate overlap windows. ``ok`` requires each
    intended keytag to be anchored by at least one exact DS at the parent.
    """
    parent_keys = {d.key for d in parent}
    intended_keys = {d.key for d in intended}
    present = [d for d in intended if d.key in parent_keys]
    missing = [d for d in intended if d.key not in parent_keys]
    extra = [d for d in parent if d.key not in intended_keys]
    return DsComparison(
        present=present,
        missing=missing,
        extra=extra,
        anchored_keytags=frozenset(d.keytag for d in present),
        intended_keytags=frozenset(d.keytag for d in intended),
    )
