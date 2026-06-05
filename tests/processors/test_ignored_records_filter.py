"""Tests for processors/ignored_records_filter.py"""

from octodns_gitops.processors.ignored_records_filter import IgnoredRecordsFilter


# Reuse the same lightweight mocks as the external_dns_filter tests.
class MockRecord:
    def __init__(
        self, name: str, _type: str, values: list[str] | None = None, ttl: int = 3600
    ):
        self.name = name
        self._type = _type
        self.values = values or []
        self.ttl = ttl

    def __hash__(self):
        return hash((self.name, self._type, tuple(self.values)))

    def __eq__(self, other):
        return (
            self.name == other.name
            and self._type == other._type
            and self.values == other.values
        )


class MockZone:
    def __init__(self, name: str, records: list[MockRecord] | None = None):
        self.name = name
        self._records = set(records or [])

    @property
    def records(self):
        return self._records

    def add_record(self, record, replace=False):
        self._records.add(record)

    def remove_record(self, record):
        self._records.discard(record)


# wan-dyn-dns ignore list as configured in dns-zones config.yaml.
WAN_DYN_DNS = [
    {"zone": "ginsys.net.", "name": "home", "type": "A"},
    {"zone": "ginsys.net.", "name": "office", "type": "A"},
    {"zone": "ginsys.net.", "name": "st32", "type": "A"},
]


class TestInit:
    def test_empty(self):
        f = IgnoredRecordsFilter("test")
        assert f.ignored == set()

    def test_builds_set_with_type_upper_and_zone_stripped(self):
        f = IgnoredRecordsFilter("test", records=WAN_DYN_DNS)
        assert ("ginsys.net", "home", "A") in f.ignored
        assert ("ginsys.net", "office", "A") in f.ignored
        assert ("ginsys.net", "st32", "A") in f.ignored

    def test_type_is_uppercased(self):
        f = IgnoredRecordsFilter(
            "test", records=[{"zone": "x.", "name": "a", "type": "cname"}]
        )
        assert ("x", "a", "CNAME") in f.ignored

    def test_zone_omitted_matches_any(self):
        f = IgnoredRecordsFilter("test", records=[{"name": "home", "type": "A"}])
        assert (None, "home", "A") in f.ignored


class TestProcessTargetZone:
    def test_removes_configured_record(self):
        f = IgnoredRecordsFilter("test", records=WAN_DYN_DNS)
        zone = MockZone(
            "ginsys.net.",
            [
                MockRecord("home", "A", ["178.118.54.154"]),
                MockRecord("office", "A", ["178.118.54.153"]),
                MockRecord("st32", "A", ["178.118.54.153", "178.118.54.154"]),
                MockRecord("www", "A", ["5.134.5.11"]),
            ],
        )

        result = f.process_target_zone(zone, None)

        remaining = [(r.name, r._type) for r in result.records]
        assert ("home", "A") not in remaining
        assert ("office", "A") not in remaining
        assert ("st32", "A") not in remaining
        assert ("www", "A") in remaining

    def test_preserves_same_name_different_type(self):
        """office A is ignored, but office MX/TXT must stay managed."""
        f = IgnoredRecordsFilter("test", records=WAN_DYN_DNS)
        zone = MockZone(
            "ginsys.net.",
            [
                MockRecord("office", "A", ["178.118.54.153"]),
                MockRecord("office", "MX", ["10 mx1.forwardemail.net."]),
                MockRecord("office", "TXT", ["forward-email-site-verification=x"]),
            ],
        )

        result = f.process_target_zone(zone, None)

        remaining = [(r.name, r._type) for r in result.records]
        assert ("office", "A") not in remaining
        assert ("office", "MX") in remaining
        assert ("office", "TXT") in remaining

    def test_zone_scoping(self):
        """An entry scoped to ginsys.net. must not match the same name elsewhere."""
        f = IgnoredRecordsFilter("test", records=WAN_DYN_DNS)
        zone = MockZone("example.com.", [MockRecord("home", "A", ["1.2.3.4"])])

        result = f.process_target_zone(zone, None)

        assert ("home", "A") in [(r.name, r._type) for r in result.records]

    def test_zone_omitted_matches_any_zone(self):
        f = IgnoredRecordsFilter("test", records=[{"name": "home", "type": "A"}])
        zone = MockZone("example.com.", [MockRecord("home", "A", ["1.2.3.4"])])

        result = f.process_target_zone(zone, None)

        assert ("home", "A") not in [(r.name, r._type) for r in result.records]

    def test_empty_config_is_noop(self):
        f = IgnoredRecordsFilter("test")
        zone = MockZone("ginsys.net.", [MockRecord("home", "A", ["1.2.3.4"])])

        result = f.process_target_zone(zone, None)

        assert len(result.records) == 1

    def test_returns_zone(self):
        f = IgnoredRecordsFilter("test", records=WAN_DYN_DNS)
        zone = MockZone("ginsys.net.")
        assert f.process_target_zone(zone, None) is zone


class TestProcessSourceZone:
    def test_removes_configured_record_from_source(self):
        f = IgnoredRecordsFilter("test", records=WAN_DYN_DNS)
        zone = MockZone(
            "ginsys.net.",
            [
                MockRecord("home", "A", ["178.118.54.154"]),
                MockRecord("www", "A", ["5.134.5.11"]),
            ],
        )

        result = f.process_source_zone(zone, [])

        remaining = [(r.name, r._type) for r in result.records]
        assert ("home", "A") not in remaining
        assert ("www", "A") in remaining

    def test_returns_zone(self):
        f = IgnoredRecordsFilter("test", records=WAN_DYN_DNS)
        zone = MockZone("ginsys.net.")
        assert f.process_source_zone(zone, []) is zone
