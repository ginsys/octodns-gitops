"""
Custom octodns processor to ignore specific records by (zone, name, type).

Some DNS records are authoritatively managed outside octodns by a system that
leaves no ownership marker octodns can detect (unlike external-dns, see
ExternalDnsFilter). For example, the `wan-dyn-dns` tool
(opnsense-dyndns-hetzner) writes apex/host A records straight to the provider
with no TXT registry entry. Without a signal, octodns treats them as orphan
records and plans to delete them, fighting the external manager.

This processor removes an explicitly configured set of records from both the
source (desired) and target (existing) zones so octodns never creates, updates
or deletes them. Matching is by (zone, name, type), so it can ignore e.g. the
apex `office A` while still managing `office` MX/TXT.

Configuration:
    records: list of mappings, each:
        name: record name relative to the zone ('' for apex)
        type: record type (e.g. 'A')
        zone: optional zone name; when omitted the entry matches in any zone.
              Trailing dots are ignored.

Example:
    records:
    - {zone: ginsys.net., name: home,   type: A}
    - {zone: ginsys.net., name: office, type: A}
    - {zone: ginsys.net., name: st32,   type: A}
"""

import logging
from octodns.processor.base import BaseProcessor


log = logging.getLogger(__name__)


class IgnoredRecordsFilter(BaseProcessor):
    """
    Filter processor that ignores explicitly configured (zone, name, type)
    records, removing them from both source and target zones.
    """

    def __init__(self, name: str, records=None, **kwargs):
        super().__init__(name, **kwargs)

        # Set of (zone_or_None, name, TYPE). zone is stored without a trailing
        # dot; None means "match in any zone".
        self.ignored: set[tuple[str | None, str, str]] = set()
        for entry in records or []:
            zone = entry.get("zone")
            if zone is not None:
                zone = zone.rstrip(".")
            self.ignored.add(
                (zone, entry["name"], entry["type"].upper())
            )

        log.info(
            f"IgnoredRecordsFilter: initialized with {len(self.ignored)} "
            f"ignored record(s)"
        )

    def _matches(self, zone_name: str, record) -> bool:
        """Return True if `record` in `zone_name` is configured to be ignored."""
        zone = zone_name.rstrip(".")
        key_any = (None, record.name, record._type)
        key_zone = (zone, record.name, record._type)
        return key_any in self.ignored or key_zone in self.ignored

    def _filter(self, zone, where: str):
        """Remove ignored records from `zone` (modified in place)."""
        records_to_remove = [r for r in zone.records if self._matches(zone.name, r)]

        for record in records_to_remove:
            zone.remove_record(record)
            log.info(
                f"IgnoredRecordsFilter: ignoring record in {where}: "
                f"{record.name}.{zone.name} (type={record._type})"
            )

        if records_to_remove:
            log.info(
                f"IgnoredRecordsFilter: removed {len(records_to_remove)} ignored "
                f"record(s) from {where} zone {zone.name}"
            )

        return zone

    def process_source_zone(self, desired, sources, lenient=False):
        """Remove ignored records from the source (desired) zone."""
        return self._filter(desired, "source")

    def process_target_zone(self, existing, target, lenient=False):
        """Remove ignored records from the target (existing) zone."""
        return self._filter(existing, "target")
