"""
OctoDNS processors for filtering DNS records.

These processors can be used in octodns config.yaml:

    processors:
      acme-filter:
        class: octodns_gitops.processors.AcmeFilter

      external-dns-filter:
        class: octodns_gitops.processors.ExternalDnsFilter
        txt_prefix: 'extdns'
        owner_id: 'my-cluster'
"""

from octodns_gitops.processors.acme_filter import AcmeFilter
from octodns_gitops.processors.external_dns_filter import ExternalDnsFilter

__all__ = ["AcmeFilter", "ExternalDnsFilter"]
