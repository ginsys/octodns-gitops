"""Registrar backend protocol and shared types.

A registrar backend performs the *parent-side* operations of DNSSEC delegation:
replacing a domain's nameservers and publishing its delegation-signer (DS)
material. Backends differ in what DS payload they accept — some take DNSKEY-style
records (OVH), some take DS digests only — and in whether a write *replaces* the
whole set or *adds/updates* it. The protocol makes both explicit so the core
delegation logic stays vendor-neutral.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from octodns_gitops.dnssec.keys import DnskeyRecord, DsRecord

# DS write semantics a backend advertises via `ds_write_semantics`.
DS_WRITE_REPLACE = "replace"  # parent DS set becomes exactly what we send
DS_WRITE_ADD = "add"  # best-effort add/update; stale entries may linger

# Operation kind and status for Result.
OP_NAMESERVER = "nameserver"
OP_DS = "ds"

STATUS_CHANGED = "changed"  # a write was submitted that alters state
STATUS_NOOP = "noop"  # already in the desired state, nothing done
STATUS_PENDING = "pending"  # an async registrar task is in flight
STATUS_FAILED = "failed"  # the operation did not succeed


@dataclass(frozen=True)
class Result:
    """Outcome of a registrar write, used as an idempotency marker.

    `op` distinguishes nameserver vs DS operations so re-used pending results stay
    legible in logs and on the next run. `task_id` is the backend's async task
    handle when `status == 'pending'`.
    """

    op: str
    status: str
    task_id: str | None = None
    detail: str | None = None


@runtime_checkable
class RegistrarBackend(Protocol):
    """Parent-side (registrar) operations for one domain.

    All `domain` arguments are the bare, normalized domain (no trailing dot).
    Implementations declare the credential env vars they need and the DS payload
    form(s) they accept.
    """

    #: One of DS_WRITE_REPLACE / DS_WRITE_ADD.
    ds_write_semantics: str
    #: Whether the backend accepts DS-digest / DNSKEY-style DS payloads.
    supports_ds_payload: bool
    supports_dnskey_payload: bool
    #: False for read-only backends (e.g. ManualRegistrar) that never write; the
    #: core reports such zones as `manual-required` with the values to set by hand.
    writable: bool

    def required_env(self) -> list[str]:
        """Env var names that must be set for this backend to operate."""
        ...

    def nameserver_type(self, domain: str) -> str:
        """Domain-level nameserver mode, e.g. 'external' / 'hosted' / 'mixed'."""
        ...

    def get_nameservers(self, domain: str) -> list[str]:
        """Current delegated nameservers (lowercased, no trailing dot)."""
        ...

    def set_nameservers(self, domain: str, nameservers: list[str]) -> Result:
        """Replace the domain's nameservers. Returns a Result (may be pending)."""
        ...

    def pending_nameserver_tasks(self, domain: str) -> list[str]:
        """IDs of in-flight NS/delegation tasks (excludes unrelated domain tasks)."""
        ...

    def task_status(self, domain: str, task_id: str) -> str:
        """Status of a task: 'done' / 'pending' / 'error' (normalized)."""
        ...

    def get_ds(self, domain: str) -> list[DsRecord]:
        """DS records currently published at the parent for this domain."""
        ...

    def set_delegation_signer(
        self,
        domain: str,
        ds_records: list[DsRecord],
        dnskey_records: list[DnskeyRecord],
    ) -> Result:
        """Publish DS at the parent.

        Both forms are always supplied; the backend picks the one it accepts
        (per `supports_ds_payload` / `supports_dnskey_payload`).
        """
        ...
