"""OVH registrar backend.

Implements `RegistrarBackend` against the OVHcloud `/domain` API. The `ovh` SDK is
imported lazily so the package (and unit tests using a fake client) don't require
it. Credentials come from the standard OVH env vars.

API surface used (keep the consumer-key scope narrow to match):
- GET  /domain/{sn}/nameServer            + /{id}   — list / type / host
- POST /domain/{sn}/nameServers/update              — replace nameservers (task)
- GET  /domain/{sn}/task                   + /{id}  — task discovery / status
- GET  /domain/{sn}/dsRecord               + /{id}  — current DS (DNSKEY form)
- POST /domain/{sn}/dsRecord                        — publish DS (DNSKEY form, task)

OVH's dsRecord POST replaces the whole key set → `ds_write_semantics = "replace"`
(confirm on the pilot). OVH accepts the DNSKEY payload form only.
"""

from __future__ import annotations

import os

from octodns_gitops.dnssec.keys import DnskeyRecord, DsRecord, dnskey_to_ds
from octodns_gitops.registrar.base import (
    DS_WRITE_REPLACE,
    OP_DS,
    OP_NAMESERVER,
    STATUS_CHANGED,
    STATUS_NOOP,
    STATUS_PENDING,
    Result,
)

# Credential env vars are `<prefix>_<suffix>`; the prefix is configurable so
# separate OVH accounts (e.g. OVH_AUTOPS_*, OVH_GINSYS_*) can coexist.
OVH_ENV_SUFFIXES = [
    "ENDPOINT",
    "APPLICATION_KEY",
    "APPLICATION_SECRET",
    "CONSUMER_KEY",
]

# Least-privilege consumer-key scope: exactly the endpoints this backend calls.
# OVH's `*` spans path segments, so each `/{id}` collection *and* item needs its
# own rule. Requested by `octodns-gitops-ovh-token`; keep in sync with the calls
# below.
OVH_ACCESS_RULES = [
    {"method": "GET", "path": "/domain/*/nameServer"},
    {"method": "GET", "path": "/domain/*/nameServer/*"},
    {"method": "POST", "path": "/domain/*/nameServers/update"},
    {"method": "GET", "path": "/domain/*/task"},
    {"method": "GET", "path": "/domain/*/task/*"},
    {"method": "GET", "path": "/domain/*/dsRecord"},
    {"method": "GET", "path": "/domain/*/dsRecord/*"},
    {"method": "POST", "path": "/domain/*/dsRecord"},
]

# Hostname suffixes of OVH-operated nameservers (used to infer 'hosted' vs
# 'external' delegation without reading the domain object).
OVH_NS_SUFFIXES = ("ovh.net", "ovh.ca", "anycast.me")

# OVH task functions that concern NS/delegation (so DS isn't blocked by unrelated
# contact/renewal tasks). OVH names vary; match on substring, case-insensitive.
_NS_TASK_FUNCTIONS = ("nameserver", "dns", "delegation", "dnssec")
_PENDING_TASK_STATES = ("todo", "doing", "init")


class OvhRegistrar:
    """RegistrarBackend for OVH. Pass `client` to inject a fake in tests."""

    ds_write_semantics = DS_WRITE_REPLACE
    supports_ds_payload = False
    supports_dnskey_payload = True
    writable = True

    def __init__(self, env_prefix: str = "OVH", client=None):
        self.env_prefix = env_prefix
        self._client = client

    # -- client -----------------------------------------------------------
    @property
    def client(self):
        if self._client is None:
            try:
                import ovh  # lazy: only needed for real OVH calls
            except ImportError as e:  # pragma: no cover
                raise RuntimeError(
                    "the 'ovh' package is required for the OVH registrar backend "
                    "(pip install ovh)"
                ) from e
            creds = {s: os.environ.get(f"{self.env_prefix}_{s}") for s in OVH_ENV_SUFFIXES}
            self._client = ovh.Client(
                endpoint=creds["ENDPOINT"],
                application_key=creds["APPLICATION_KEY"],
                application_secret=creds["APPLICATION_SECRET"],
                consumer_key=creds["CONSUMER_KEY"],
            )
        return self._client

    def required_env(self) -> list[str]:
        return [f"{self.env_prefix}_{s}" for s in OVH_ENV_SUFFIXES]

    # -- nameservers ------------------------------------------------------
    def _nameserver_entries(self, domain: str) -> list[dict]:
        ids = self.client.get(f"/domain/{domain}/nameServer")
        entries = []
        for nid in ids:
            entry = self.client.get(f"/domain/{domain}/nameServer/{nid}")
            if not entry.get("toDelete"):
                entries.append(entry)
        return entries

    def nameserver_type(self, domain: str) -> str:
        """Infer external/hosted from the current NS hostnames.

        The domain-level `nameServerType` field lives on `GET /domain/{sn}`, which
        our least-privilege consumer key intentionally cannot read. Instead we
        derive it from the delegated nameservers (readable via
        `/domain/{sn}/nameServer`): OVH-operated DNS uses `*.ovh.net` etc., so a
        set with no OVH nameservers is 'external'.
        """
        hosts = self.get_nameservers(domain)
        if not hosts:
            return "unknown"
        ovh_hosts = [h for h in hosts if h.endswith(OVH_NS_SUFFIXES)]
        if len(ovh_hosts) == len(hosts):
            return "hosted"
        if ovh_hosts:
            return "mixed"
        return "external"

    def get_nameservers(self, domain: str) -> list[str]:
        return sorted(
            (e.get("host") or "").lower().rstrip(".")
            for e in self._nameserver_entries(domain)
            if e.get("host")
        )

    def set_nameservers(self, domain: str, nameservers: list[str]) -> Result:
        # OVH's nameServers/update items are keyed by `host` (optional `ip` for
        # in-bailiwick glue; deSEC's NS are out-of-bailiwick so none is needed).
        task = self.client.post(
            f"/domain/{domain}/nameServers/update",
            nameServers=[{"host": ns} for ns in nameservers],
        )
        task_id = _task_id(task)
        return Result(
            op=OP_NAMESERVER,
            status=STATUS_PENDING if task_id else STATUS_CHANGED,
            task_id=task_id,
        )

    # -- tasks ------------------------------------------------------------
    def pending_nameserver_tasks(self, domain: str) -> list[str]:
        out: list[str] = []
        for tid in self.client.get(f"/domain/{domain}/task"):
            t = self.client.get(f"/domain/{domain}/task/{tid}")
            fn = (t.get("function") or "").lower()
            st = (t.get("status") or "").lower()
            if any(k in fn for k in _NS_TASK_FUNCTIONS) and st in _PENDING_TASK_STATES:
                out.append(str(tid))
        return out

    def task_status(self, domain: str, task_id: str) -> str:
        t = self.client.get(f"/domain/{domain}/task/{task_id}")
        st = (t.get("status") or "").lower()
        if st == "done":
            return "done"
        if st in ("error", "cancelled", "problem"):
            return "error"
        return "pending"

    # -- DS ---------------------------------------------------------------
    def get_ds(self, domain: str) -> list[DsRecord]:
        """DS OVH currently holds, derived from its stored DNSKEY entries."""
        out: list[DsRecord] = []
        for did in self.client.get(f"/domain/{domain}/dsRecord"):
            e = self.client.get(f"/domain/{domain}/dsRecord/{did}")
            dnskey = DnskeyRecord(
                flags=int(e["flags"]),
                protocol=3,
                algorithm=int(e["algorithm"]),
                public_key=e["publicKey"],
            )
            out.extend(dnskey_to_ds(domain, dnskey))
        return out

    def set_delegation_signer(
        self,
        domain: str,
        ds_records: list[DsRecord],
        dnskey_records: list[DnskeyRecord],
    ) -> Result:
        if not dnskey_records:
            return Result(op=OP_DS, status=STATUS_NOOP)
        keys = []
        for k in dnskey_records:
            keytag = dnskey_to_ds(domain, k)[0].keytag
            keys.append(
                {
                    "flags": k.flags,
                    "algorithm": k.algorithm,
                    "publicKey": k.public_key,
                    "tag": keytag,
                }
            )
        task = self.client.post(f"/domain/{domain}/dsRecord", keys=keys)
        task_id = _task_id(task)
        return Result(
            op=OP_DS,
            status=STATUS_PENDING if task_id else STATUS_CHANGED,
            task_id=task_id,
        )


def _task_id(task) -> str | None:
    """Extract a task id from an OVH task response (shape varies)."""
    if isinstance(task, dict):
        for k in ("id", "taskId", "internalTaskId"):
            if task.get(k) is not None:
                return str(task[k])
    elif task is not None:
        return str(task)
    return None
