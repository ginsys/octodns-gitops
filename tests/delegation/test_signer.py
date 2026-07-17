"""Tests for delegation/signer.py (CDS-first intent + rollover filtering)."""

import pytest

from octodns_gitops.delegation.signer import (
    SignerIntentError,
    resolve_intended_delegation,
)
from octodns_gitops.dnssec.keys import (
    DnskeyRecord,
    DsRecord,
    dnskey_to_ds,
    parse_dnskey,
    parse_ds,
)
from octodns_gitops.dnssec.source import SignerKeys

ZONE = "autops.be."
KSK = parse_dnskey(
    "257 3 13 He11//F3RBWpxom1j5BviVSClPyJ8Y/ep80RQhMy61auVOcGuNM+IyXV"
    "bxyTIyyu72HajDAEEHOVccvnjlbV6A=="
)
DS256 = parse_ds(
    "27674 13 2 885E4E565FE94EA4E6FACD8931BF4D57CE870BD013FECB5BCF7BFAB45BD8142F"
)
# A second, unrelated KSK (valid base64, different key -> different keytag).
OTHER_KSK = DnskeyRecord(257, 3, 13, "B" + "A" * 63)  # 64 chars, valid base64


def test_cds_selects_only_cds_keys():
    # DNSKEY RRset has the retiring OTHER_KSK too, but CDS lists only KSK ->
    # only KSK's DNSKEY is sent to the registrar.
    sk = SignerKeys(dnskeys=[KSK, OTHER_KSK], cds=[DS256], cdnskey=[])
    out = resolve_intended_delegation(ZONE, sk)
    assert out.source == "cds"
    assert out.dnskey_records == [KSK]  # OTHER_KSK excluded
    assert out.ds_records == [DS256]


def test_inconsistent_cds_rejected():
    sk = SignerKeys(dnskeys=[KSK], cds=[DsRecord(12345, 13, 2, "DE" * 32)], cdnskey=[])
    with pytest.raises(SignerIntentError, match="inconsistent with the DNSKEY"):
        resolve_intended_delegation(ZONE, sk)


def test_inconsistent_cdnskey_rejected():
    sk = SignerKeys(dnskeys=[KSK, OTHER_KSK], cds=[DS256], cdnskey=[OTHER_KSK])
    with pytest.raises(SignerIntentError, match="CDNSKEY is inconsistent"):
        resolve_intended_delegation(ZONE, sk)


def test_delete_signal_refused():
    sk = SignerKeys(dnskeys=[KSK], cds=[DsRecord(0, 0, 0, "00")], cdnskey=[])
    with pytest.raises(SignerIntentError, match="delete signal"):
        resolve_intended_delegation(ZONE, sk)


def test_no_ksk_errors():
    zsk = DnskeyRecord(256, 3, 13, "AAAA")
    with pytest.raises(SignerIntentError, match="no KSK"):
        resolve_intended_delegation(ZONE, SignerKeys(dnskeys=[zsk], cds=[], cdnskey=[]))


def test_cdnskey_used_as_intent_when_no_cds():
    # No CDS, but CDNSKEY expresses intent -> use it (select only its KSKs).
    sk = SignerKeys(dnskeys=[KSK, OTHER_KSK], cds=[], cdnskey=[KSK])
    out = resolve_intended_delegation(ZONE, sk)
    assert out.source == "cdnskey"
    assert out.dnskey_records == [KSK]  # OTHER_KSK excluded
    assert out.ds_records == dnskey_to_ds(ZONE, KSK)


def test_cdnskey_not_in_dnskey_rrset_rejected():
    sk = SignerKeys(dnskeys=[KSK], cds=[], cdnskey=[OTHER_KSK])
    with pytest.raises(SignerIntentError, match="not in the DNSKEY RRset"):
        resolve_intended_delegation(ZONE, sk)


def test_dnskey_fallback_when_no_cds_or_cdnskey():
    sk = SignerKeys(dnskeys=[KSK], cds=[], cdnskey=[])
    out = resolve_intended_delegation(ZONE, sk)
    assert out.source == "dnskey-derived"
    assert out.warnings  # warns about weaker intent
    assert out.ds_records == dnskey_to_ds(ZONE, KSK)  # SHA-256
