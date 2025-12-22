"""
Logging filters for OctoDNS.

These filters can be used in logging.yaml:

    filters:
      suppress_soa:
        (): octodns_gitops.logging.SuppressSoaWarningsFilter
"""

from octodns_gitops.logging.filters import SuppressSoaWarningsFilter

__all__ = ["SuppressSoaWarningsFilter"]
