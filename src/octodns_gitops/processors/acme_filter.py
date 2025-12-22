"""
Custom octodns processor to ignore ACME challenge records.

ACME challenge records (_acme-challenge.*) are dynamically managed
by certificate authorities and should not be managed by octodns.

This processor filters out ACME challenge records from both source
and target zones to prevent conflicts.
"""

import logging
from octodns.processor.base import BaseProcessor


log = logging.getLogger(__name__)


class AcmeFilter(BaseProcessor):
    """
    Filter processor that ignores ACME challenge records.

    Removes any records with names starting with '_acme-challenge'
    from both source and target zones.
    """

    def __init__(self, name: str, **kwargs):
        super().__init__(name, **kwargs)
        log.info("AcmeFilter: initialized")

    def _is_acme_record(self, record) -> bool:
        """
        Check if a record is an ACME challenge record.

        Args:
            record: DNS record to check

        Returns:
            bool: True if this is an ACME challenge record
        """
        return record.name.startswith("_acme-challenge")

    def process_source_zone(self, desired, sources):
        """
        Remove ACME challenge records from the source zone.

        Args:
            desired: The desired zone from source provider(s)
            sources: The source providers

        Returns:
            The desired zone with ACME records removed
        """
        records_to_remove = []

        for record in desired.records:
            if self._is_acme_record(record):
                records_to_remove.append(record)
                log.info(
                    f"AcmeFilter: found ACME challenge record in source: "
                    f"{record.name}.{desired.name} (type={record._type})"
                )

        for record in records_to_remove:
            desired.remove_record(record)

        if records_to_remove:
            log.info(
                f"AcmeFilter: removed {len(records_to_remove)} ACME challenge records "
                f"from source zone {desired.name}"
            )

        return desired

    def process_target_zone(self, existing, target):
        """
        Remove ACME challenge records from the target zone.

        Args:
            existing: The existing zone from the target provider
            target: The target provider

        Returns:
            The existing zone with ACME records removed
        """
        records_to_remove = []

        for record in existing.records:
            if self._is_acme_record(record):
                records_to_remove.append(record)
                log.info(
                    f"AcmeFilter: found ACME challenge record in target: "
                    f"{record.name}.{existing.name} (type={record._type})"
                )

        for record in records_to_remove:
            existing.remove_record(record)

        if records_to_remove:
            log.info(
                f"AcmeFilter: removed {len(records_to_remove)} ACME challenge records "
                f"from target zone {existing.name}"
            )

        return existing
