"""Tests for dnssec/keys.py (pure logic; verified against a real deSEC key)."""

from octodns_gitops.dnssec.keys import (
    DIGEST_SHA256,
    DIGEST_SHA384,
    DnskeyRecord,
    DsRecord,
    cdnskey_ds_in_intended_set,
    cds_consistent_with_dnskeys,
    compare_ds,
    dnskey_to_ds,
    parse_dnskey,
    parse_ds,
    select_delegation_dnskeys,
)

# Real autops.be CSK/KSK observed at ns1.desec.io (dig DNSKEY / CDS), used as a
# ground-truth vector for DS derivation. dig wrapped the base64 with a space,
# which parse_dnskey must join.
AUTOPS_DNSKEY = (
    "257 3 13 He11//F3RBWpxom1j5BviVSClPyJ8Y/ep80RQhMy61auVOcGuNM+IyXV "
    "bxyTIyyu72HajDAEEHOVccvnjlbV6A=="
)
AUTOPS_ZONE = "autops.be."
AUTOPS_DS_SHA256 = (
    "27674 13 2 885E4E565FE94EA4E6FACD8931BF4D57CE870BD013FECB5BCF7BFAB45BD8142F"
)
AUTOPS_DS_SHA384 = (
    "27674 13 4 8810EAB1C9C882EF13C4C0E09A0F93DD4F367CDD1A36679EBC00C19C"
    "9A1318524D8509C6CAA69B97F7232560B9F63A6A"
)


class TestParsing:
    def test_parse_dnskey_joins_split_base64(self):
        k = parse_dnskey(AUTOPS_DNSKEY)
        assert (k.flags, k.protocol, k.algorithm) == (257, 3, 13)
        assert " " not in k.public_key
        assert k.public_key.endswith("lbV6A==")

    def test_parse_ds_normalizes_digest_uppercase(self):
        d = parse_ds("27674 13 2 885e4e56...ff")
        assert d.digest == "885E4E56...FF"  # uppercased
        assert (d.keytag, d.algorithm, d.digest_type) == (27674, 13, 2)

    def test_ds_equality_by_tuple(self):
        a = parse_ds(AUTOPS_DS_SHA256)
        b = parse_ds(AUTOPS_DS_SHA256.lower())
        assert a == b and hash(a) == hash(b)


class TestDnskeyToDs:
    def test_matches_real_vector_sha256(self):
        k = parse_dnskey(AUTOPS_DNSKEY)
        (ds,) = dnskey_to_ds(AUTOPS_ZONE, k, (DIGEST_SHA256,))
        assert ds == parse_ds(AUTOPS_DS_SHA256)
        assert ds.keytag == 27674  # RFC 4034 key tag

    def test_matches_real_vector_sha384(self):
        k = parse_dnskey(AUTOPS_DNSKEY)
        (ds,) = dnskey_to_ds(AUTOPS_ZONE, k, (DIGEST_SHA384,))
        assert ds == parse_ds(AUTOPS_DS_SHA384)

    def test_both_digest_types(self):
        k = parse_dnskey(AUTOPS_DNSKEY)
        out = dnskey_to_ds(AUTOPS_ZONE, k, (DIGEST_SHA256, DIGEST_SHA384))
        assert {d.digest_type for d in out} == {2, 4}


class TestKeySelection:
    def test_selects_257_non_delete(self):
        ksk = parse_dnskey(AUTOPS_DNSKEY)
        zsk = DnskeyRecord(256, 3, 13, "AAAA")
        delete = DnskeyRecord(0, 3, 0, "AA==")
        assert select_delegation_dnskeys([ksk, zsk, delete]) == [ksk]

    def test_delete_signal_detection(self):
        assert DnskeyRecord(0, 3, 0, "AA==").is_delete_signal()
        assert DsRecord(0, 0, 0, "00").is_delete_signal()
        assert not parse_dnskey(AUTOPS_DNSKEY).is_delete_signal()


class TestCdsConsistency:
    def test_consistent_cds_passes(self):
        k = parse_dnskey(AUTOPS_DNSKEY)
        cds = [parse_ds(AUTOPS_DS_SHA256)]
        assert cds_consistent_with_dnskeys(cds, [k], AUTOPS_ZONE)

    def test_inconsistent_cds_fails(self):
        k = parse_dnskey(AUTOPS_DNSKEY)
        bogus = DsRecord(12345, 13, 2, "DE" * 32)
        assert not cds_consistent_with_dnskeys([bogus], [k], AUTOPS_ZONE)

    def test_empty_cds_fails(self):
        k = parse_dnskey(AUTOPS_DNSKEY)
        assert not cds_consistent_with_dnskeys([], [k], AUTOPS_ZONE)

    def test_cdnskey_ds_in_intended(self):
        k = parse_dnskey(AUTOPS_DNSKEY)
        intended = dnskey_to_ds(AUTOPS_ZONE, k, (DIGEST_SHA256,))
        assert cdnskey_ds_in_intended_set([k], intended, AUTOPS_ZONE)
        assert not cdnskey_ds_in_intended_set(
            [k], [DsRecord(1, 1, 2, "AA")], AUTOPS_ZONE
        )


class TestCompareDs:
    def test_one_digest_at_parent_is_ok(self):
        # Intended SHA-256 + SHA-384 for one KSK; parent publishes only SHA-256.
        # The KSK is anchored -> ok, even though SHA-384 is "missing".
        a = parse_ds(AUTOPS_DS_SHA256)
        b = parse_ds(AUTOPS_DS_SHA384)
        stale = DsRecord(9999, 13, 2, "FF" * 32)
        cmp = compare_ds(parent=[a, stale], intended=[a, b])
        assert cmp.present == [a]
        assert cmp.missing == [b]  # still reported precisely
        assert cmp.extra == [stale]  # warning, not failure
        assert cmp.ok  # keytag 27674 is anchored by SHA-256

    def test_ok_when_one_present(self):
        a = parse_ds(AUTOPS_DS_SHA256)
        assert compare_ds(parent=[a], intended=[a]).ok

    def test_not_ok_when_keytag_absent(self):
        a = parse_ds(AUTOPS_DS_SHA256)
        cmp = compare_ds(parent=[], intended=[a])
        assert not cmp.ok and cmp.missing == [a]

    def test_digest_type_not_masking(self):
        # Same keytag, different digest_type are distinct records (precise
        # reporting); a parent SHA-256 does not satisfy an intended-only SHA-384.
        sha256 = parse_ds(AUTOPS_DS_SHA256)
        sha384 = parse_ds(AUTOPS_DS_SHA384)
        cmp = compare_ds(parent=[sha256], intended=[sha384])
        assert cmp.missing == [sha384]
        assert cmp.extra == [sha256]
        assert not cmp.ok  # no exact intended DS present for the keytag
