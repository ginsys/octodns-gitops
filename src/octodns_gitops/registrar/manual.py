"""Manual (read-only) registrar backend.

For domains whose registrar has no automation wired up (e.g. Gandi-held domains
awaiting transfer to OVH). It never writes: it observes delegation state from DNS
and lets the core report exactly what to set by hand, while the same parity guard
and `dnssec` validation still apply.

Nameserver observation is via public DNS (`observed_nameservers`); DS at the
parent is read the same way the core already does. The write methods exist to
satisfy the protocol but only return `manual` results and change nothing.
"""

from __future__ import annotations

from octodns_gitops.dnssec import source as dns_source
from octodns_gitops.dnssec.keys import DnskeyRecord, DsRecord
from octodns_gitops.registrar.base import (
    DS_WRITE_REPLACE,
    OP_DS,
    OP_NAMESERVER,
    Result,
)

STATUS_MANUAL = "manual"


class ManualRegistrar:
    """Read-only backend: observe via DNS, never write."""

    ds_write_semantics = DS_WRITE_REPLACE
    supports_ds_payload = True
    supports_dnskey_payload = True
    writable = False

    def required_env(self) -> list[str]:
        return []

    def nameserver_type(self, domain: str) -> str:
        # We can't ask the registrar; assume external (the core only consults this
        # when the delegation isn't already live, and won't write regardless).
        return "external"

    def get_nameservers(self, domain: str) -> list[str]:
        return dns_source.observed_nameservers(domain + ".")

    def set_nameservers(self, domain: str, nameservers: list[str]) -> Result:
        return Result(
            op=OP_NAMESERVER,
            status=STATUS_MANUAL,
            detail=f"set NS at the registrar to: {', '.join(nameservers)}",
        )

    def pending_nameserver_tasks(self, domain: str) -> list[str]:
        return []

    def task_status(self, domain: str, task_id: str) -> str:
        return "done"

    def get_ds(self, domain: str) -> list[DsRecord]:
        return dns_source.parent_ds_authoritative(domain + ".")

    def set_delegation_signer(
        self,
        domain: str,
        ds_records: list[DsRecord],
        dnskey_records: list[DnskeyRecord],
    ) -> Result:
        ds_fmt = "; ".join(d.to_text() for d in ds_records)
        dnskey_fmt = "; ".join(k.to_text() for k in dnskey_records)
        return Result(
            op=OP_DS,
            status=STATUS_MANUAL,
            detail=f"publish DS at the registrar — DS: [{ds_fmt}] | DNSKEY: [{dnskey_fmt}]",
        )
