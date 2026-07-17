"""Registrar backends for DNSSEC delegation (NS + DS management at the registrar).

The core delegation logic is registrar-agnostic: it speaks to a `RegistrarBackend`
(see `base.py`) and never contains OVH- (or any vendor-) specific code. Concrete
backends live alongside, e.g. `ovh.py`.
"""

from octodns_gitops.registrar.base import (
    DS_WRITE_ADD,
    DS_WRITE_REPLACE,
    RegistrarBackend,
    Result,
)

__all__ = [
    "RegistrarBackend",
    "Result",
    "DS_WRITE_REPLACE",
    "DS_WRITE_ADD",
]
