"""State-machine tests for cli/delegate.py (fake backend + injected deps)."""

from octodns_gitops.cli.delegate import Deps, process_zone
from octodns_gitops.delegation.config import DelegationZone
from octodns_gitops.dnssec.keys import DsRecord, parse_dnskey, parse_ds
from octodns_gitops.dnssec.source import SignerKeys
from octodns_gitops.registrar.base import OP_DS, OP_NAMESERVER, Result

DNSKEY = parse_dnskey(
    "257 3 13 He11//F3RBWpxom1j5BviVSClPyJ8Y/ep80RQhMy61auVOcGuNM+IyXV"
    "bxyTIyyu72HajDAEEHOVccvnjlbV6A=="
)
DS256 = parse_ds(
    "27674 13 2 885E4E565FE94EA4E6FACD8931BF4D57CE870BD013FECB5BCF7BFAB45BD8142F"
)
TARGET_NS = ["ns1.desec.io", "ns2.desec.org"]


def signer_keys(cds=(DS256,)):
    return SignerKeys(dnskeys=[DNSKEY], cds=list(cds), cdnskey=[DNSKEY])


class FakeBackend:
    ds_write_semantics = "replace"
    supports_ds_payload = False
    supports_dnskey_payload = True
    writable = True

    def __init__(self, ns=None, nstype="external", pending=None, held_ds=None):
        self._ns = ns or []
        self._nstype = nstype
        self._pending = pending or []
        self._held_ds = held_ds or []
        self.calls = []

    def required_env(self):
        return []

    def nameserver_type(self, d):
        return self._nstype

    def get_nameservers(self, d):
        return list(self._ns)

    def set_nameservers(self, d, ns):
        self.calls.append(("set_ns", ns))
        return Result(OP_NAMESERVER, "pending", "t1")

    def pending_nameserver_tasks(self, d):
        return list(self._pending)

    def task_status(self, d, i):
        return "pending"

    def get_ds(self, d):
        return list(self._held_ds)

    def set_delegation_signer(self, d, ds, dnskey):
        self.calls.append(("set_ds", ds, dnskey))
        return Result(OP_DS, "pending", "t2")


def zone(dnssec=False):
    return DelegationZone(
        zone="autops.be.",
        registrar="ovh",
        signer_target="desec",
        target_nameservers=TARGET_NS,
        dnssec=dnssec,
    )


def deps(parent_ds=(), parity=True, cds=(DS256,), observed=TARGET_NS):
    return Deps(
        fetch_signer=lambda z, ns: signer_keys(cds),
        parent_ds=lambda d: list(parent_ds),
        observed_ns=lambda z: list(observed),
        parity_ok=lambda c, z, t: parity,
    )


# --- NS step -------------------------------------------------------------

def test_ns_parity_failure_blocks_before_cutover():
    b = FakeBackend(ns=[])  # NS not live
    rep = process_zone(zone(), "cfg", b, doit=True, deps=deps(parity=False), step="ns")
    assert rep["stage"] == "blocked" and "parity" in rep["error"]
    assert b.calls == []


def test_ns_type_not_external_blocks():
    b = FakeBackend(ns=[], nstype="hosted")
    rep = process_zone(zone(), "cfg", b, doit=True, deps=deps(), step="ns")
    assert rep["stage"] == "blocked" and "external" in rep["error"]


def test_ns_cutover_submitted_when_not_live():
    b = FakeBackend(ns=["helium.ns.hetzner.de"])
    rep = process_zone(zone(), "cfg", b, doit=True, deps=deps(), step="ns")
    assert rep["stage"] == "ns-cutover-submitted"
    assert b.calls == [("set_ns", TARGET_NS)]


def test_ns_dry_run_does_not_write():
    b = FakeBackend(ns=["helium.ns.hetzner.de"])
    rep = process_zone(zone(), "cfg", b, doit=False, deps=deps(), step="ns")
    assert rep["stage"] == "ns-cutover-submitted" and b.calls == []


def test_ns_live_reports_and_never_publishes_ds():
    # NS live; the NS step reports ns-live and never touches DS, even if DS is missing.
    b = FakeBackend(ns=TARGET_NS)
    rep = process_zone(zone(dnssec=True), "cfg", b, doit=True, deps=deps(parent_ds=[]), step="ns")
    assert rep["stage"] == "ns-live" and b.calls == []


def test_ns_step_pending_task_when_live():
    b = FakeBackend(ns=TARGET_NS, pending=["t1"])
    rep = process_zone(zone(), "cfg", b, doit=True, deps=deps(), step="ns")
    assert rep["stage"] == "ns-task-pending" and b.calls == []


def test_ns_step_idempotent_while_task_pending_not_yet_live():
    # NS not yet live at the registrar record, but a task is already queued ->
    # report it, do NOT submit a duplicate.
    b = FakeBackend(ns=["helium.ns.hetzner.de"], pending=["595693827"])
    rep = process_zone(zone(), "cfg", b, doit=True, deps=deps(), step="ns")
    assert rep["stage"] == "ns-task-pending"
    assert b.calls == []  # no duplicate set_nameservers
    assert "595693827" in rep["actions"][0]


# --- DS step (separate, opt-in) ------------------------------------------

def test_ds_skipped_when_not_enabled():
    b = FakeBackend(ns=TARGET_NS)
    rep = process_zone(zone(dnssec=False), "cfg", b, doit=True, deps=deps(parent_ds=[]), step="ds")
    assert rep["stage"] == "dnssec-not-enabled" and b.calls == []


def test_ds_blocks_when_parent_delegation_not_live():
    # Registrar record may show the new NS, but resolvers still see the old NS ->
    # do NOT publish DS (SERVFAIL hazard).
    b = FakeBackend(ns=TARGET_NS)
    rep = process_zone(
        zone(dnssec=True), "cfg", b, doit=True,
        deps=deps(observed=["helium.ns.hetzner.de"], parent_ds=[]), step="ds",
    )
    assert rep["stage"] == "blocked" and "parent delegation not live" in rep["error"]
    assert b.calls == []


def test_ds_waits_for_pending_ns_task():
    b = FakeBackend(ns=TARGET_NS, pending=["t1"])
    rep = process_zone(zone(dnssec=True), "cfg", b, doit=True, deps=deps(), step="ds")
    assert rep["stage"] == "ns-task-pending" and b.calls == []


def test_ds_publishes_when_missing():
    b = FakeBackend(ns=TARGET_NS, pending=[])
    rep = process_zone(zone(dnssec=True), "cfg", b, doit=True, deps=deps(parent_ds=[]), step="ds")
    assert rep["stage"] == "ds-published"
    assert b.calls[0][0] == "set_ds"


def test_ds_idempotent_when_registrar_already_holds():
    # DS submitted (registrar holds it) but not yet at the parent -> don't resubmit.
    b = FakeBackend(ns=TARGET_NS, held_ds=[DS256])
    rep = process_zone(zone(dnssec=True), "cfg", b, doit=True, deps=deps(parent_ds=[]), step="ds")
    assert rep["stage"] == "ds-set" and b.calls == []


def test_ds_done_when_already_present():
    b = FakeBackend(ns=TARGET_NS)
    rep = process_zone(zone(dnssec=True), "cfg", b, doit=True, deps=deps(parent_ds=[DS256]), step="ds")
    assert rep["stage"] == "done" and b.calls == []


def test_ds_delete_signal_blocks():
    b = FakeBackend(ns=TARGET_NS)
    d = deps(cds=[DsRecord(0, 0, 0, "00")])
    rep = process_zone(zone(dnssec=True), "cfg", b, doit=True, deps=d, step="ds")
    assert rep["stage"] == "blocked" and "delete signal" in rep["error"]


# --- manual (read-only) backend ------------------------------------------

class ManualFake(FakeBackend):
    writable = False

    def set_nameservers(self, d, ns):
        return Result(OP_NAMESERVER, "manual", detail=f"set NS to {','.join(ns)}")

    def set_delegation_signer(self, d, ds, dnskey):
        return Result(OP_DS, "manual", detail=f"publish DS: {[x.to_text() for x in ds]}")


def test_manual_ns_not_live_reports_manual_required():
    b = ManualFake(ns=["ns1.gandi.net"])
    rep = process_zone(zone(), "cfg", b, doit=True, deps=deps(), step="ns")
    assert rep["stage"] == "manual-required"
    assert "set NS to" in rep["actions"][0]


def test_manual_ds_missing_reports_manual_required():
    b = ManualFake(ns=TARGET_NS)  # NS already changed manually
    rep = process_zone(zone(dnssec=True), "cfg", b, doit=True, deps=deps(parent_ds=[]), step="ds")
    assert rep["stage"] == "manual-required"
    assert "publish DS" in rep["actions"][0]


def test_manual_ds_done_when_present():
    b = ManualFake(ns=TARGET_NS)
    rep = process_zone(zone(dnssec=True), "cfg", b, doit=True, deps=deps(parent_ds=[DS256]), step="ds")
    assert rep["stage"] == "done"
