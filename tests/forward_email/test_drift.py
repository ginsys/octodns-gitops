"""Tests for forward_email/drift.py — FE server-generated records vs the octoDNS zone file."""

import copy

import pytest
from octodns_gitops.forward_email.drift import check_zone

DKIM = "v=DKIM1; k=rsa; p=MIIBIjANBg;"
LIVE = {
    "name": "autops.eu",
    "verification_record": "WPoBifGj1Z",
    "has_strict_dmarc": False,
    "smtp_dns_records": {
        "dkim": {"name": "fe-53661bcfc9._domainkey", "value": DKIM},
        "return_path": {"name": "fe-bounces", "value": "forwardemail.net"},
        "dmarc": {
            "name": "_dmarc",
            "value": "v=DMARC1; p=reject; pct=100; rua=mailto:dmarc-6a61b3b09bc@forwardemail.net;",
        },
    },
}
ZONE = {
    "": [
        {"type": "A", "value": "91.98.1.229"},
        {
            "type": "MX",
            "values": [
                {"exchange": "mx1.forwardemail.net.", "preference": 10},
                {"exchange": "mx2.forwardemail.net.", "preference": 10},
            ],
        },
        {
            "type": "TXT",
            "values": [
                "forward-email-site-verification=WPoBifGj1Z",
                "v=spf1 include:spf.forwardemail.net ~all",
            ],
        },
    ],
    "_dmarc": {
        "type": "TXT",
        "value": r"v=DMARC1\; p=quarantine\; pct=25\; rua=mailto:dmarc-6a61b3b09bc@forwardemail.net,mailto:dmarc-report@ginsys.net\;",
    },
    "fe-53661bcfc9._domainkey": {"type": "TXT", "value": DKIM.replace(";", r"\;")},
    "fe-bounces": {"type": "CNAME", "value": "forwardemail.net."},
}


def _zone(**edits):
    z = copy.deepcopy(ZONE)
    for name, rec in edits.items():
        if rec is None:
            z.pop(name, None)
        else:
            z[name] = rec
    return z


def _fields(findings):
    return sorted(f.field for f in findings)


class TestClean:
    def test_matching_zone_has_no_findings(self):
        assert check_zone(LIVE, ZONE, expect_mx=True) == []


class TestFindings:
    def test_dkim_value_mismatch(self):
        z = _zone(**{"fe-53661bcfc9._domainkey": {"type": "TXT", "value": r"v=DKIM1\; p=OLD\;"}})
        (f,) = check_zone(LIVE, z, expect_mx=True)
        assert f.field == "dkim"
        assert "fe-53661bcfc9._domainkey" in f.message

    def test_dkim_record_missing(self):
        z = _zone(**{"fe-53661bcfc9._domainkey": None})
        assert _fields(check_zone(LIVE, z, expect_mx=True)) == ["dkim"]

    def test_return_path_cname_missing(self):
        z = _zone(**{"fe-bounces": None})
        assert _fields(check_zone(LIVE, z, expect_mx=True)) == ["return_path"]

    def test_hostnames_and_record_names_compare_case_insensitively(self):
        # DNS names are case-insensitive: a hand-written `ForwardEmail.NET.` or an upper-cased
        # record key is the same record, not drift.
        z = _zone(**{"fe-53661bcfc9._domainkey": None})
        z["FE-53661BCFC9._domainkey"] = {"type": "TXT", "value": DKIM.replace(";", r"\;")}
        z["fe-bounces"] = {"type": "CNAME", "value": "ForwardEmail.NET."}
        assert check_zone(LIVE, z, expect_mx=True) == []
        live = copy.deepcopy(LIVE)
        live["smtp_dns_records"]["return_path"]["name"] = "FE-Bounces"
        assert check_zone(live, ZONE, expect_mx=True) == []

    def test_verification_txt_missing_from_apex(self):
        z = _zone()
        z[""][2]["values"] = ["v=spf1 include:spf.forwardemail.net ~all"]
        assert _fields(check_zone(LIVE, z, expect_mx=True)) == ["verification"]

    def test_dmarc_rua_must_include_fe_address(self):
        z = _zone(_dmarc={"type": "TXT", "value": r"v=DMARC1\; p=none\; rua=mailto:x@y.z\;"})
        assert _fields(check_zone(LIVE, z, expect_mx=True)) == ["dmarc"]

    def test_dmarc_rua_is_matched_as_a_whole_uri_not_a_substring(self):
        z = _zone(_dmarc={"type": "TXT", "value": r"v=DMARC1\; p=none\; rua=mailto:dmarc-6a61b3b09bc@forwardemail.net.example.org\;"})
        assert _fields(check_zone(LIVE, z, expect_mx=True)) == ["dmarc"]
        z = _zone(_dmarc={"type": "TXT", "value": r"v=DMARC1\; p=none\; rua=mailto:x@y.z, mailto:DMARC-6a61b3b09bc@ForwardEmail.net!10m\;"})
        assert check_zone(LIVE, z, expect_mx=True) == []

    @pytest.mark.parametrize("token", [None, ""])
    def test_missing_verification_record_is_unverifiable_not_clean(self, token):
        live = {k: v for k, v in LIVE.items() if k != "verification_record"}
        if token is not None:
            live["verification_record"] = token
        (f,) = check_zone(live, ZONE, expect_mx=True)
        assert f.field == "verification"
        assert "cannot verify" in f.message

    def test_dmarc_policy_may_differ_from_fe_suggestion(self):
        # FE suggests p=reject; the ramp deliberately publishes quarantine. Not a finding.
        assert check_zone(LIVE, ZONE, expect_mx=True) == []

    def test_strict_dmarc_expectation_derived_from_zone_policy(self):
        live = dict(LIVE, has_strict_dmarc=True)  # FE thinks reject, zone says quarantine
        assert _fields(check_zone(live, ZONE, expect_mx=True)) == ["has_strict_dmarc"]
        z = _zone(_dmarc={"type": "TXT", "value": r"v=DMARC1\; p=reject\; rua=mailto:dmarc-6a61b3b09bc@forwardemail.net\;"})
        assert check_zone(live, z, expect_mx=True) == []

    def test_apex_txt_value_may_be_a_list(self):
        # vanginderachter.name.yaml (live, 2026-08-30) writes `value: [a, b]` instead of `values:`.
        z = _zone()
        z[""][2] = {"type": "TXT", "value": ["forward-email-site-verification=WPoBifGj1Z", "v=spf1 -all"]}
        assert check_zone(LIVE, z, expect_mx=True) == []

    def test_missing_generated_records_on_the_fe_side_are_unverifiable_not_clean(self):
        live = dict(LIVE, smtp_dns_records={})
        assert _fields(check_zone(live, ZONE, expect_mx=True)) == ["dkim", "dmarc", "return_path"]
        live = {k: v for k, v in LIVE.items() if k != "smtp_dns_records"}
        assert _fields(check_zone(live, ZONE, expect_mx=True)) == ["dkim", "dmarc", "return_path"]

    def test_mx_checked_unless_domain_ignores_it(self):
        z = _zone()
        z[""][1]["values"] = [{"exchange": "aspmx.l.google.com.", "preference": 1}]
        assert _fields(check_zone(LIVE, z, expect_mx=True)) == ["mx"]
        assert check_zone(LIVE, z, expect_mx=False) == []

    @pytest.mark.parametrize(
        ("values", "needle"),
        [
            # FE present, but a lower-preference exchanger routes mail elsewhere first.
            (
                [
                    {"exchange": "mx1.forwardemail.net.", "preference": 10},
                    {"exchange": "mx2.forwardemail.net.", "preference": 10},
                    {"exchange": "aspmx.l.google.com.", "preference": 1},
                ],
                "aspmx.l.google.com",
            ),
            # A higher-preference extra is a backup FE does not know about: still a finding.
            (
                [
                    {"exchange": "mx1.forwardemail.net.", "preference": 10},
                    {"exchange": "mx2.forwardemail.net.", "preference": 10},
                    {"exchange": "backup.example.org.", "preference": 20},
                ],
                "backup.example.org",
            ),
            # Both FE hosts present at different preferences.
            (
                [
                    {"exchange": "mx1.forwardemail.net.", "preference": 10},
                    {"exchange": "mx2.forwardemail.net.", "preference": 20},
                ],
                "preference",
            ),
            # Only one FE host.
            ([{"exchange": "mx1.forwardemail.net.", "preference": 10}], "mx2.forwardemail.net"),
            # Both FE hosts without any preference: "shared" None is not a valid preference.
            ([{"exchange": "mx1.forwardemail.net."}, {"exchange": "mx2.forwardemail.net."}], "preference"),
            # A duplicate FE entry at another preference must not be hidden by the later one.
            (
                [
                    {"exchange": "mx1.forwardemail.net.", "preference": 20},
                    {"exchange": "mx1.forwardemail.net.", "preference": 10},
                    {"exchange": "mx2.forwardemail.net.", "preference": 10},
                ],
                "preference",
            ),
            # An entry that is not an exchange/preference mapping is not "no exchanger".
            (
                [
                    {"exchange": "mx1.forwardemail.net.", "preference": 10},
                    {"exchange": "mx2.forwardemail.net.", "preference": 10},
                    "mx3.example.org.",
                ],
                "malformed",
            ),
            (
                [
                    {"exchange": "mx1.forwardemail.net.", "preference": 10},
                    {"exchange": "mx2.forwardemail.net.", "preference": 10},
                    {"preference": 5},
                ],
                "malformed",
            ),
        ],
    )
    def test_mx_requires_exactly_fe_at_one_shared_preference(self, values, needle):
        z = _zone()
        z[""][1]["values"] = values
        findings = check_zone(LIVE, z, expect_mx=True)
        assert _fields(findings) == ["mx"], findings
        assert needle in findings[0].message
        assert check_zone(LIVE, z, expect_mx=False) == []

    def test_mx_accepts_octodns_legacy_priority_value_keys(self):
        z = _zone()
        z[""][1]["values"] = [
            {"value": "MX1.forwardemail.net.", "priority": 10},
            {"value": "mx2.forwardemail.net", "priority": 10},
        ]
        assert check_zone(LIVE, z, expect_mx=True) == []
