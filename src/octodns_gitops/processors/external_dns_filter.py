"""
Custom octodns processor to ignore records managed by external-dns.

external-dns marks its ownership using TXT records with specific patterns:
- TXT record names: prefixed with record type (e.g., 'a-', 'cname-', 'aaaa-')
- TXT record values: contain "heritage=external-dns"

This processor scans the target zone for external-dns TXT ownership records,
identifies which DNS records are managed by external-dns, and filters them
out from octodns management to prevent conflicts.
"""

import logging
from octodns.processor.base import BaseProcessor
from octodns.record.txt import TxtRecord


log = logging.getLogger(__name__)


class ExternalDnsFilter(BaseProcessor):
    """
    Filter processor that ignores DNS records managed by external-dns.

    Examines TXT records in the target zone to identify external-dns owned
    records and prevents octodns from managing them.

    Configuration:
        txt_prefixes: List of TXT record prefixes used by external-dns
                      (default: ['a-', 'aaaa-', 'cname-'])
        owner_id: Optional specific external-dns owner-id to filter
                  (default: None, matches any owner)
    """

    # Map type prefixes to DNS record types
    TYPE_PREFIX_MAP = {
        "a-": "A",
        "aaaa-": "AAAA",
        "cname-": "CNAME",
        "txt-": "TXT",
    }

    def __init__(
        self,
        name: str,
        txt_prefix: str | None = None,
        type_prefixes: list[str] | None = None,
        owner_id: str | None = None,
        **kwargs,
    ):
        super().__init__(name, **kwargs)

        # TXT prefix used by external-dns (e.g., 'extdns')
        self.txt_prefix = txt_prefix or "extdns"
        # Type prefixes used by external-dns for record types (e.g., 'a-', 'cname-')
        self.type_prefixes = type_prefixes or ["a-", "aaaa-", "cname-", "txt-"]
        self.owner_id = owner_id
        self._external_dns_records: set[tuple[str, str]] = set()

        log.info(
            f"ExternalDnsFilter: initialized with txt_prefix={self.txt_prefix}, "
            f"type_prefixes={self.type_prefixes}, owner_id={self.owner_id}"
        )

    def _parse_txt_name(
        self, txt_name: str, zone_name: str
    ) -> tuple[str | None, str | None]:
        """
        Parse external-dns TXT record name to extract original hostname and record type.

        Args:
            txt_name: TXT record name (e.g., 'extdnsautops.eu', 'extdnsa-chat')
            zone_name: Zone name (e.g., 'autops.eu.')

        Returns:
            tuple: (hostname, record_type) or (None, None) if not parseable
                   hostname is empty string for apex records

        Examples for txt_prefix='extdns', zone='autops.eu.':
        - 'extdnsautops.eu' -> ('', 'A') (apex, default type)
        - 'extdnsa-autops.eu' -> ('', 'A') (apex A record)
        - 'extdnschat' -> ('chat', 'A') (default type)
        - 'extdnsa-chat' -> ('chat', 'A') (A record)
        - 'extdnscname-chat' -> ('chat', 'CNAME') (CNAME record)
        """
        zone_base = zone_name.rstrip(".")  # 'autops.eu'

        if not txt_name.startswith(self.txt_prefix):
            return None, None

        # Strip txt_prefix
        remainder = txt_name[len(self.txt_prefix) :]

        # Check for type prefix (a-, cname-, etc.) and extract record type
        record_type = "A"  # default type if no prefix found
        for type_prefix in self.type_prefixes:
            if remainder.startswith(type_prefix):
                remainder = remainder[len(type_prefix) :]
                record_type = self.TYPE_PREFIX_MAP.get(type_prefix, "A")
                break

        # Map zone name to empty string (apex)
        if remainder == zone_base:
            return "", record_type

        return remainder, record_type

    def _is_external_dns_txt(
        self, record, zone_name: str
    ) -> tuple[bool, str | None, str | None]:
        """
        Check if a TXT record is an external-dns ownership marker.

        Args:
            record: DNS record to check
            zone_name: Zone name for apex domain mapping

        Returns:
            tuple: (is_external_dns, original_record_name, record_type) or (False, None, None)
        """
        if record._type != "TXT":
            return False, None, None

        # Check if record name starts with txt_prefix
        record_name = record.name
        original_name, record_type = self._parse_txt_name(record_name, zone_name)

        if original_name is None:
            return False, None, None

        # Check TXT value for external-dns heritage marker
        # TxtValue is a string subclass, access it directly
        for value in record.values:
            if "heritage=external-dns" in value:
                # If owner_id is specified, check for match
                if self.owner_id:
                    if f"external-dns/owner={self.owner_id}" in value:
                        return True, original_name, record_type
                else:
                    # No specific owner_id, match any external-dns record
                    return True, original_name, record_type

        return False, None, None

    def _filter_txt_values(self, zone) -> int:
        """
        Filter individual TXT values containing heritage=external-dns.

        Args:
            zone: The zone to process

        Returns:
            Number of TXT records modified
        """
        modified_count = 0
        records_to_update: list[tuple] = []

        for record in zone.records:
            if record._type != "TXT":
                continue

            # Check if any values contain heritage=external-dns
            filtered_values = []
            had_external_dns = False
            for value in record.values:
                if "heritage=external-dns" in str(value):
                    had_external_dns = True
                else:
                    filtered_values.append(value)

            # If we filtered values and there are still values left, update the record
            if had_external_dns and filtered_values:
                records_to_update.append((record, filtered_values))
                modified_count += 1
            elif had_external_dns and not filtered_values:
                # All values were filtered - record will be handled elsewhere
                pass

        # Update records with filtered values
        for old_record, new_values in records_to_update:
            zone.remove_record(old_record)
            # Create a new TXT record with filtered values
            data = {
                "name": old_record.name,
                "ttl": old_record.ttl,
                "type": "TXT",
                "values": new_values,
            }
            new_record = TxtRecord(zone, old_record.name, data)
            zone.add_record(new_record)
            log.info(
                f"ExternalDnsFilter: filtered heritage=external-dns from TXT record: "
                f"{old_record.name}.{zone.name}"
            )

        return modified_count

    def process_target_zone(self, existing, target):
        """
        Remove external-dns managed records from the existing target zone.

        Scans for TXT ownership records containing 'heritage=external-dns',
        identifies the corresponding actual records (A, CNAME, etc.),
        and removes BOTH the TXT records and the actual records from the
        existing zone. This prevents octodns from trying to delete them.

        Args:
            existing: The existing zone from the target provider
            target: The target provider

        Returns:
            The existing zone with external-dns records removed
        """
        txt_records_to_remove = []
        actual_records_to_remove = []
        managed_records: set[tuple[str, str]] = set()  # (name, type) tuples

        # First pass: identify external-dns TXT ownership records
        for record in existing.records:
            is_external, original_name, record_type = self._is_external_dns_txt(
                record, existing.name
            )
            if is_external and original_name is not None and record_type is not None:
                txt_records_to_remove.append(record)
                managed_records.add((original_name, record_type))
                log.info(
                    f"ExternalDnsFilter: found external-dns TXT marker: "
                    f"{record.name}.{existing.name} -> manages {original_name} ({record_type})"
                )

        # Second pass: identify actual records managed by external-dns
        for record in existing.records:
            # Skip the TXT ownership records themselves
            if record in txt_records_to_remove:
                continue

            # Check if this record matches any managed (name, type) pair
            if (record.name, record._type) in managed_records:
                actual_records_to_remove.append(record)
                log.info(
                    f"ExternalDnsFilter: found external-dns managed record: "
                    f"{record.name}.{existing.name} (type={record._type})"
                )

        # Remove all identified records from existing zone
        for record in txt_records_to_remove + actual_records_to_remove:
            existing.remove_record(record)

        total_removed = len(txt_records_to_remove) + len(actual_records_to_remove)
        if total_removed > 0:
            log.info(
                f"ExternalDnsFilter: removed {total_removed} external-dns records "
                f"({len(txt_records_to_remove)} TXT markers, {len(actual_records_to_remove)} actual records) "
                f"from zone {existing.name}"
            )

        # Filter individual TXT values containing heritage=external-dns
        txt_modified = self._filter_txt_values(existing)
        if txt_modified > 0:
            log.info(
                f"ExternalDnsFilter: filtered heritage=external-dns values from "
                f"{txt_modified} TXT records in target zone {existing.name}"
            )

        return existing

    def process_source_zone(self, desired, sources):
        """
        Remove external-dns managed records from the source zone.

        This ensures consistency - records managed by external-dns are
        filtered from both source and target views, preventing octodns
        from trying to create records that already exist in live DNS.

        Args:
            desired: The desired zone from source provider(s)
            sources: The source providers

        Returns:
            The desired zone with external-dns records removed
        """
        txt_records_to_remove = []
        actual_records_to_remove = []
        managed_records: set[tuple[str, str]] = set()  # (name, type) tuples

        # First pass: identify external-dns TXT ownership records
        for record in desired.records:
            is_external, original_name, record_type = self._is_external_dns_txt(
                record, desired.name
            )
            if is_external and original_name is not None and record_type is not None:
                txt_records_to_remove.append(record)
                managed_records.add((original_name, record_type))
                log.info(
                    f"ExternalDnsFilter: found external-dns TXT marker in source: "
                    f"{record.name}.{desired.name} -> manages {original_name} ({record_type})"
                )

        # Second pass: identify actual records managed by external-dns
        for record in desired.records:
            # Skip the TXT ownership records themselves
            if record in txt_records_to_remove:
                continue

            # Check if this record matches any managed (name, type) pair
            if (record.name, record._type) in managed_records:
                actual_records_to_remove.append(record)
                log.info(
                    f"ExternalDnsFilter: found external-dns managed record in source: "
                    f"{record.name}.{desired.name} (type={record._type})"
                )

        # Remove all identified records from desired zone
        for record in txt_records_to_remove + actual_records_to_remove:
            desired.remove_record(record)

        total_removed = len(txt_records_to_remove) + len(actual_records_to_remove)
        if total_removed > 0:
            log.info(
                f"ExternalDnsFilter: removed {total_removed} external-dns records "
                f"({len(txt_records_to_remove)} TXT markers, {len(actual_records_to_remove)} actual records) "
                f"from source zone {desired.name}"
            )

        # Filter individual TXT values containing heritage=external-dns
        txt_modified = self._filter_txt_values(desired)
        if txt_modified > 0:
            log.info(
                f"ExternalDnsFilter: filtered heritage=external-dns values from "
                f"{txt_modified} TXT records in source zone {desired.name}"
            )

        return desired
