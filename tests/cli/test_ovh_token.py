"""Tests for cli/ovh_token.py (consumer-key request; fake client)."""

from octodns_gitops.cli.ovh_token import request_consumer_key
from octodns_gitops.registrar.ovh import OVH_ACCESS_RULES


class FakeClient:
    def __init__(self):
        self.called_with = None

    def request_consumerkey(self, access_rules):
        self.called_with = access_rules
        return {"consumerKey": "CK123", "validationUrl": "https://ovh/validate/x"}


def test_requests_least_privilege_rules():
    c = FakeClient()
    res = request_consumer_key(c)
    assert res["consumerKey"] == "CK123"
    assert c.called_with is OVH_ACCESS_RULES


def test_access_rules_are_scoped_to_domain_and_no_wildcard_all():
    # Least-privilege: only /domain/* sub-paths, exactly one write per endpoint.
    paths = {(r["method"], r["path"]) for r in OVH_ACCESS_RULES}
    assert ("POST", "/domain/*/nameServers/update") in paths
    assert ("POST", "/domain/*/dsRecord") in paths
    # no blanket GET /domain/* and no PUT
    assert ("GET", "/domain/*") not in paths
    assert not any(m == "PUT" for m, _ in paths)
    # both collection and item reads present for the id-addressed resources
    for base in ("nameServer", "task", "dsRecord"):
        assert ("GET", f"/domain/*/{base}") in paths
        assert ("GET", f"/domain/*/{base}/*") in paths
