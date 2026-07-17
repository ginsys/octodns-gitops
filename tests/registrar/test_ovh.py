"""Tests for the OVH registrar backend using a fake OVH client (no network)."""

from octodns_gitops.dnssec.keys import parse_dnskey
from octodns_gitops.registrar.base import OP_DS, OP_NAMESERVER
from octodns_gitops.registrar.ovh import OvhRegistrar

AUTOPS_DNSKEY = (
    "257 3 13 He11//F3RBWpxom1j5BviVSClPyJ8Y/ep80RQhMy61auVOcGuNM+IyXV"
    "bxyTIyyu72HajDAEEHOVccvnjlbV6A=="
)


class FakeClient:
    def __init__(self, gets):
        self.gets = gets
        self.posts = []

    def get(self, path):
        return self.gets[path]

    def post(self, path, **kwargs):
        self.posts.append((path, kwargs))
        return {"id": 999}


class TestCredentials:
    def test_required_env_uses_prefix(self):
        assert OvhRegistrar(env_prefix="OVH_AUTOPS").required_env() == [
            "OVH_AUTOPS_ENDPOINT",
            "OVH_AUTOPS_APPLICATION_KEY",
            "OVH_AUTOPS_APPLICATION_SECRET",
            "OVH_AUTOPS_CONSUMER_KEY",
        ]

    def test_default_prefix(self):
        assert OvhRegistrar().required_env()[0] == "OVH_ENDPOINT"


class TestNameservers:
    def test_type_external_non_ovh_hosts(self):
        c = FakeClient(
            {
                "/domain/autops.be/nameServer": [1, 2],
                "/domain/autops.be/nameServer/1": {"host": "helium.ns.hetzner.de"},
                "/domain/autops.be/nameServer/2": {"host": "hydrogen.ns.hetzner.com"},
            }
        )
        r = OvhRegistrar(client=c)
        assert r.nameserver_type("autops.be") == "external"

    def test_type_hosted_all_ovh(self):
        c = FakeClient(
            {
                "/domain/x.be/nameServer": [1, 2],
                "/domain/x.be/nameServer/1": {"host": "dns10.ovh.net"},
                "/domain/x.be/nameServer/2": {"host": "ns10.ovh.net"},
            }
        )
        assert OvhRegistrar(client=c).nameserver_type("x.be") == "hosted"

    def test_type_mixed_one_ovh(self):
        c = FakeClient(
            {
                "/domain/x.be/nameServer": [1, 2],
                "/domain/x.be/nameServer/1": {"host": "dns10.ovh.net"},
                "/domain/x.be/nameServer/2": {"host": "ns1.desec.io"},
            }
        )
        assert OvhRegistrar(client=c).nameserver_type("x.be") == "mixed"

    def test_get_nameservers_sorted(self):
        c = FakeClient(
            {
                "/domain/autops.be/nameServer": [1, 2],
                "/domain/autops.be/nameServer/1": {"host": "ns1.desec.io"},
                "/domain/autops.be/nameServer/2": {"host": "ns2.desec.org"},
            }
        )
        assert OvhRegistrar(client=c).get_nameservers("autops.be") == [
            "ns1.desec.io",
            "ns2.desec.org",
        ]

    def test_set_nameservers_payload_and_result(self):
        c = FakeClient({})
        res = OvhRegistrar(client=c).set_nameservers(
            "autops.be", ["ns1.desec.io", "ns2.desec.org"]
        )
        path, kwargs = c.posts[0]
        assert path == "/domain/autops.be/nameServers/update"
        assert kwargs == {
            "nameServers": [
                {"host": "ns1.desec.io"},
                {"host": "ns2.desec.org"},
            ]
        }
        assert res.op == OP_NAMESERVER and res.status == "pending" and res.task_id == "999"


class TestTasks:
    def test_pending_ns_tasks_filtered(self):
        c = FakeClient(
            {
                "/domain/x.be/task": [10, 11, 12],
                "/domain/x.be/task/10": {"function": "nameServerUpdate", "status": "doing"},
                "/domain/x.be/task/11": {"function": "contactUpdate", "status": "todo"},
                "/domain/x.be/task/12": {"function": "domainDnsUpdate", "status": "done"},
            }
        )
        # only the in-flight NS/DNS task, not the unrelated contact task nor the done one
        assert OvhRegistrar(client=c).pending_nameserver_tasks("x.be") == ["10"]

    def test_task_status_normalizes(self):
        c = FakeClient(
            {
                "/domain/x.be/task/1": {"status": "done"},
                "/domain/x.be/task/2": {"status": "error"},
                "/domain/x.be/task/3": {"status": "doing"},
            }
        )
        r = OvhRegistrar(client=c)
        assert r.task_status("x.be", "1") == "done"
        assert r.task_status("x.be", "2") == "error"
        assert r.task_status("x.be", "3") == "pending"


class TestDsPublish:
    def test_maps_dnskey_to_ovh_keys_with_computed_tag(self):
        c = FakeClient({})
        k = parse_dnskey(AUTOPS_DNSKEY)
        res = OvhRegistrar(client=c).set_delegation_signer("autops.be", [], [k])
        path, kwargs = c.posts[0]
        assert path == "/domain/autops.be/dsRecord"
        (key,) = kwargs["keys"]
        assert key["flags"] == 257 and key["algorithm"] == 13
        assert key["tag"] == 27674  # computed via dnspython
        assert key["publicKey"] == k.public_key
        assert res.op == OP_DS and res.status == "pending"

    def test_no_keys_is_noop(self):
        c = FakeClient({})
        res = OvhRegistrar(client=c).set_delegation_signer("x.be", [], [])
        assert res.status == "noop" and not c.posts

    def test_get_ds_derives_from_stored_dnskey(self):
        k = parse_dnskey(AUTOPS_DNSKEY)
        c = FakeClient(
            {
                "/domain/autops.be/dsRecord": [7],
                "/domain/autops.be/dsRecord/7": {
                    "flags": 257,
                    "algorithm": 13,
                    "publicKey": k.public_key,
                },
            }
        )
        ds = OvhRegistrar(client=c).get_ds("autops.be")
        assert any(d.keytag == 27674 and d.digest_type == 2 for d in ds)
