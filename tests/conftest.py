"""
Shared fixtures and mock classes for octodns-gitops tests.

This module sets up mocks for octodns before any test modules are imported.
"""

import sys
from unittest.mock import MagicMock
from pathlib import Path

# ============================================================================
# Mock octodns modules BEFORE any imports from octodns_gitops
# This must happen at conftest load time, before test collection
# ============================================================================


class MockBaseProcessor:
    """Mock BaseProcessor that does nothing in __init__."""

    def __init__(self, name, **kwargs):
        self.name = name


class MockTxtRecord:
    """Mock TxtRecord for testing."""

    def __init__(self, zone, name, data):
        self.zone = zone
        self.name = name
        self._type = "TXT"
        self.values = data.get("values", [])
        self.ttl = data.get("ttl", 3600)


# Set up the mock modules before any octodns_gitops imports
mock_octodns = MagicMock()
mock_processor = MagicMock()
mock_processor_base = MagicMock()
mock_processor_base.BaseProcessor = MockBaseProcessor
mock_record = MagicMock()
mock_record_txt = MagicMock()
mock_record_txt.TxtRecord = MockTxtRecord

sys.modules["octodns"] = mock_octodns
sys.modules["octodns.processor"] = mock_processor
sys.modules["octodns.processor.base"] = mock_processor_base
sys.modules["octodns.record"] = mock_record
sys.modules["octodns.record.txt"] = mock_record_txt

# ============================================================================
# Now we can safely import pytest and set up fixtures
# ============================================================================

import pytest


# Mock record and zone classes for testing
class MockRecord:
    """
    Mock octodns Record for testing processors.

    Simulates the interface of octodns.record.Record.
    """

    def __init__(
        self,
        zone: "MockZone | None" = None,
        name: str = "",
        _type: str = "A",
        values: list[str] | None = None,
        ttl: int = 3600,
    ):
        self.zone = zone
        self.name = name
        self._type = _type
        self.values = values or []
        self.ttl = ttl

    def __repr__(self):
        return f"MockRecord({self.name}, {self._type}, {self.values})"

    def __eq__(self, other):
        if not isinstance(other, MockRecord):
            return False
        return (
            self.name == other.name
            and self._type == other._type
            and self.values == other.values
            and self.ttl == other.ttl
        )

    def __hash__(self):
        return hash((self.name, self._type, tuple(self.values), self.ttl))


class MockZone:
    """
    Mock octodns Zone for testing processors.

    Simulates the interface of octodns.zone.Zone.
    """

    def __init__(self, name: str, records: list[MockRecord] | None = None):
        self.name = name
        self._records: set[MockRecord] = set(records or [])

    @property
    def records(self) -> set[MockRecord]:
        return self._records

    def add_record(self, record: MockRecord, replace: bool = False) -> None:
        if replace:
            # Remove existing record with same name/type
            self._records = {
                r
                for r in self._records
                if not (r.name == record.name and r._type == record._type)
            }
        self._records.add(record)

    def remove_record(self, record: MockRecord) -> None:
        self._records.discard(record)

    def __repr__(self):
        return f"MockZone({self.name}, {len(self._records)} records)"


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_zone():
    """Factory fixture to create mock zones."""

    def _create(name: str = "example.com.", records: list[MockRecord] | None = None):
        return MockZone(name, records)

    return _create


@pytest.fixture
def mock_record():
    """Factory fixture to create mock records."""

    def _create(
        zone: MockZone | None = None,
        name: str = "www",
        _type: str = "A",
        values: list[str] | None = None,
        ttl: int = 3600,
    ):
        if zone is None:
            zone = MockZone("example.com.")
        return MockRecord(zone, name, _type, values or ["1.2.3.4"], ttl)

    return _create


@pytest.fixture
def mock_txt_record():
    """Factory fixture to create mock TXT records."""

    def _create(
        zone: MockZone | None = None,
        name: str = "txt",
        values: list[str] | None = None,
        ttl: int = 3600,
    ):
        if zone is None:
            zone = MockZone("example.com.")
        return MockRecord(
            zone, name, "TXT", values or ["v=spf1 include:example.com ~all"], ttl
        )

    return _create


@pytest.fixture
def sample_zone_with_external_dns(mock_zone):
    """Create a zone with external-dns managed records for testing."""
    zone = mock_zone("example.com.")

    # Regular records (not managed by external-dns)
    zone.add_record(MockRecord(zone, "", "A", ["1.2.3.4"]))
    zone.add_record(MockRecord(zone, "www", "A", ["1.2.3.4"]))
    zone.add_record(MockRecord(zone, "mail", "MX", ["10 mail.example.com."]))

    # External-dns managed A record at 'api'
    zone.add_record(MockRecord(zone, "api", "A", ["5.6.7.8"]))
    # TXT ownership marker for 'api' A record
    zone.add_record(
        MockRecord(
            zone,
            "extdnsa-api",
            "TXT",
            [
                "heritage=external-dns,external-dns/owner=default,external-dns/resource=ingress/default/api"
            ],
        )
    )

    # External-dns managed CNAME at 'blog'
    zone.add_record(MockRecord(zone, "blog", "CNAME", ["blog.external.com."]))
    # TXT ownership marker for 'blog' CNAME record
    zone.add_record(
        MockRecord(
            zone,
            "extdnscname-blog",
            "TXT",
            [
                "heritage=external-dns,external-dns/owner=default,external-dns/resource=ingress/default/blog"
            ],
        )
    )

    return zone


@pytest.fixture
def sample_zone_with_acme(mock_zone):
    """Create a zone with ACME challenge records for testing."""
    zone = mock_zone("example.com.")

    # Regular records
    zone.add_record(MockRecord(zone, "", "A", ["1.2.3.4"]))
    zone.add_record(MockRecord(zone, "www", "A", ["1.2.3.4"]))

    # ACME challenge records
    zone.add_record(MockRecord(zone, "_acme-challenge", "TXT", ["challenge-token-1"]))
    zone.add_record(
        MockRecord(zone, "_acme-challenge.www", "TXT", ["challenge-token-2"])
    )
    zone.add_record(
        MockRecord(zone, "_acme-challenge.api", "TXT", ["challenge-token-3"])
    )

    return zone


@pytest.fixture
def tmp_config_file(tmp_path):
    """Create a temporary config file for testing."""

    def _create(content: str) -> Path:
        config_file = tmp_path / "config.yaml"
        config_file.write_text(content)
        return config_file

    return _create


@pytest.fixture
def sample_config_content():
    """Sample octodns config.yaml content."""
    return """
providers:
  zones:
    class: octodns.provider.yaml.YamlProvider
    directory: zones
  hetzner:
    class: octodns_hetzner.HetznerProvider
    token: env/HETZNER_DNS_TOKEN
  hcloud:
    class: octodns_hetzner.HcloudProvider
    token: env/HCLOUD_TOKEN

zones:
  example.com.:
    sources:
      - zones
    targets:
      - hetzner
    processors:
      - external-dns-filter
      - acme-filter

processors:
  external-dns-filter:
    class: octodns_gitops.processors.ExternalDnsFilter
  acme-filter:
    class: octodns_gitops.processors.AcmeFilter
"""


# Sample octodns output fixtures
@pytest.fixture
def octodns_output_no_changes():
    """octodns-sync output when no changes are needed."""
    return """
********************************************************************************
* example.com.
********************************************************************************
*   No changes were planned
"""


@pytest.fixture
def octodns_output_with_changes():
    """octodns-sync output with creates, updates, and deletes."""
    return """
********************************************************************************
* example.com.
********************************************************************************
*   hetzner (HetznerProvider)
*   Create <ARecord A 3600, www.example.com., ['1.2.3.4']> (zones)
*   Update
*     <ARecord A 1800, mail.example.com., ['5.6.7.8']> ->
*     <ARecord A 3600, mail.example.com., ['5.6.7.8']> (zones)
*   Delete <ARecord A 3600, old.example.com., ['9.10.11.12']>
*   Summary: Creates=1, Updates=1, Deletes=1, Existing=10, Meta=False
"""


@pytest.fixture
def octodns_output_multi_zone():
    """octodns-sync output with multiple zones."""
    return """
********************************************************************************
* example.com.
********************************************************************************
*   hetzner (HetznerProvider)
*   Create <ARecord A 3600, www.example.com., ['1.2.3.4']> (zones)
*   Summary: Creates=1, Updates=0, Deletes=0, Existing=5, Meta=False
********************************************************************************
* example.org.
********************************************************************************
*   hetzner (HetznerProvider)
*   Update
*     <ARecord A 1800, mail.example.org., ['5.6.7.8']> ->
*     <ARecord A 3600, mail.example.org., ['5.6.7.8']> (zones)
*   Summary: Creates=0, Updates=1, Deletes=0, Existing=8, Meta=False
"""
