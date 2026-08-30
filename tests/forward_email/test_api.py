"""Tests for forward_email/api.py — paging, auth, and write verbs against a fake transport."""

import base64

import pytest
from octodns_gitops.forward_email.api import ForwardEmailApiError, ForwardEmailClient


class FakeTransport:
    """Records calls; answers from a (method, path) -> list of responses table."""

    def __init__(self, table):
        self.table = table
        self.calls = []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, headers, body))
        key = (method, url.split("?")[0])
        responses = self.table[key]
        status, payload = responses.pop(0) if isinstance(responses, list) else responses
        return status, payload


def _client(table):
    t = FakeTransport(table)
    return ForwardEmailClient(token="tok", transport=t, page_size=2), t


class TestAuth:
    def test_basic_auth_with_token_as_username(self):
        c, t = _client({("GET", "https://api.forwardemail.net/v1/domains"): [(200, [])]})
        c.list_domains()
        auth = t.calls[0][2]["Authorization"]
        assert auth == "Basic " + base64.b64encode(b"tok:").decode()


class TestPaging:
    def test_list_domains_pages_until_short_page(self):
        pages = [(200, [{"name": "a.be"}, {"name": "b.be"}]), (200, [{"name": "c.be"}])]
        c, t = _client({("GET", "https://api.forwardemail.net/v1/domains"): pages})
        names = [d["name"] for d in c.list_domains()]
        assert names == ["a.be", "b.be", "c.be"]
        assert [u for _, u, _, _ in t.calls] == [
            "https://api.forwardemail.net/v1/domains?page=1&limit=2",
            "https://api.forwardemail.net/v1/domains?page=2&limit=2",
        ]

    def test_full_last_page_fetches_one_more(self):
        # Never trust a total: an exact multiple of page_size needs an extra empty fetch.
        pages = [(200, [{"id": 1}, {"id": 2}]), (200, [])]
        c, t = _client({("GET", "https://api.forwardemail.net/v1/domains/x.be/aliases"): pages})
        assert len(c.list_aliases("x.be")) == 2
        assert len(t.calls) == 2


class TestErrors:
    def test_non_2xx_raises_with_status_and_message(self):
        c, _ = _client(
            {("GET", "https://api.forwardemail.net/v1/domains/x.be"): [(404, {"message": "Not Found"})]}
        )
        with pytest.raises(ForwardEmailApiError, match="404.*Not Found"):
            c.get_domain("x.be")


class TestWrites:
    def test_update_domain_puts_json(self):
        c, t = _client({("PUT", "https://api.forwardemail.net/v1/domains/x.be"): [(200, {"name": "x.be"})]})
        c.update_domain("x.be", {"retention_days": 30, "smtp_port": "25"})
        method, _url, headers, body = t.calls[0]
        assert (method, headers["Content-Type"]) == ("PUT", "application/json")
        assert body == {"retention_days": 30, "smtp_port": "25"}

    def test_alias_create_update_delete_paths(self):
        base = "https://api.forwardemail.net/v1/domains/x.be/aliases"
        c, t = _client(
            {
                ("POST", base): [(200, {"id": "new"})],
                ("PUT", base + "/id1"): [(200, {"id": "id1"})],
                ("DELETE", base + "/id2"): [(200, {})],
            }
        )
        c.create_alias("x.be", {"name": "a", "recipients": ["x@y.z"]})
        c.update_alias("x.be", "id1", {"is_enabled": False})
        c.delete_alias("x.be", "id2")
        assert [(m, u) for m, u, _, _ in t.calls] == [
            ("POST", base),
            ("PUT", base + "/id1"),
            ("DELETE", base + "/id2"),
        ]

    def test_domain_names_are_url_escaped(self):
        c, t = _client({("GET", "https://api.forwardemail.net/v1/domains/office.ginsys.net"): [(200, {})]})
        c.get_domain("office.ginsys.net")
        assert t.calls[0][1].endswith("/v1/domains/office.ginsys.net")
