"""Tests for processors/acme_filter.py"""

import pytest

from octodns_gitops.processors.acme_filter import AcmeFilter


# Mock record and zone classes for testing
class MockRecord:
    def __init__(self, name: str, _type: str, values: list[str] | None = None):
        self.name = name
        self._type = _type
        self.values = values or []


class MockZone:
    def __init__(self, name: str, records: list[MockRecord] | None = None):
        self.name = name
        self._records = set(records or [])

    @property
    def records(self):
        return self._records

    def remove_record(self, record):
        self._records.discard(record)


class TestIsAcmeRecord:
    """Tests for _is_acme_record()."""

    @pytest.fixture
    def filter_instance(self):
        return AcmeFilter("test-filter")

    def test_matches_acme_challenge(self, filter_instance):
        """'_acme-challenge' should return True."""
        record = MockRecord("_acme-challenge", "TXT", ["token"])
        assert filter_instance._is_acme_record(record) is True

    def test_matches_nested_acme(self, filter_instance):
        """'_acme-challenge.www' should return True."""
        record = MockRecord("_acme-challenge.www", "TXT", ["token"])
        assert filter_instance._is_acme_record(record) is True

    def test_matches_deeply_nested_acme(self, filter_instance):
        """'_acme-challenge.api.v1' should return True."""
        record = MockRecord("_acme-challenge.api.v1", "TXT", ["token"])
        assert filter_instance._is_acme_record(record) is True

    def test_rejects_dmarc(self, filter_instance):
        """'_dmarc' should return False."""
        record = MockRecord("_dmarc", "TXT", ["v=DMARC1"])
        assert filter_instance._is_acme_record(record) is False

    def test_rejects_regular_record(self, filter_instance):
        """'www' should return False."""
        record = MockRecord("www", "A", ["1.2.3.4"])
        assert filter_instance._is_acme_record(record) is False

    def test_rejects_similar_prefix(self, filter_instance):
        """'_acme-other' should return False."""
        record = MockRecord("_acme-other", "TXT", ["value"])
        assert filter_instance._is_acme_record(record) is False

    def test_rejects_apex(self, filter_instance):
        """Apex record '' should return False."""
        record = MockRecord("", "A", ["1.2.3.4"])
        assert filter_instance._is_acme_record(record) is False


class TestProcessSourceZone:
    """Tests for process_source_zone()."""

    @pytest.fixture
    def filter_instance(self):
        return AcmeFilter("test-filter")

    def test_removes_acme_records(self, filter_instance):
        """ACME challenge records should be removed from source."""
        zone = MockZone(
            "example.com.",
            [
                MockRecord("www", "A", ["1.2.3.4"]),
                MockRecord("_acme-challenge", "TXT", ["token1"]),
                MockRecord("_acme-challenge.www", "TXT", ["token2"]),
            ],
        )

        result = filter_instance.process_source_zone(zone, [])

        record_names = [r.name for r in result.records]
        assert "_acme-challenge" not in record_names
        assert "_acme-challenge.www" not in record_names
        assert "www" in record_names

    def test_preserves_other_records(self, filter_instance):
        """Non-ACME records should remain."""
        zone = MockZone(
            "example.com.",
            [
                MockRecord("www", "A", ["1.2.3.4"]),
                MockRecord("mail", "MX", ["10 mail.example.com."]),
                MockRecord("_dmarc", "TXT", ["v=DMARC1"]),
            ],
        )

        result = filter_instance.process_source_zone(zone, [])

        record_names = [r.name for r in result.records]
        assert "www" in record_names
        assert "mail" in record_names
        assert "_dmarc" in record_names

    def test_handles_multiple_acme_records(self, filter_instance):
        """Multiple ACME records should all be removed."""
        zone = MockZone(
            "example.com.",
            [
                MockRecord("_acme-challenge", "TXT", ["token1"]),
                MockRecord("_acme-challenge.www", "TXT", ["token2"]),
                MockRecord("_acme-challenge.api", "TXT", ["token3"]),
                MockRecord("_acme-challenge.mail", "TXT", ["token4"]),
            ],
        )

        result = filter_instance.process_source_zone(zone, [])

        assert len(result.records) == 0

    def test_returns_zone(self, filter_instance):
        """Should return the modified zone object."""
        zone = MockZone("example.com.")
        result = filter_instance.process_source_zone(zone, [])
        assert result is zone


class TestProcessTargetZone:
    """Tests for process_target_zone()."""

    @pytest.fixture
    def filter_instance(self):
        return AcmeFilter("test-filter")

    def test_removes_acme_records(self, filter_instance):
        """ACME challenge records should be removed from target."""
        zone = MockZone(
            "example.com.",
            [
                MockRecord("www", "A", ["1.2.3.4"]),
                MockRecord("_acme-challenge", "TXT", ["token1"]),
            ],
        )

        result = filter_instance.process_target_zone(zone, None)

        record_names = [r.name for r in result.records]
        assert "_acme-challenge" not in record_names
        assert "www" in record_names

    def test_preserves_other_records(self, filter_instance):
        """Non-ACME records should remain."""
        zone = MockZone(
            "example.com.",
            [
                MockRecord("www", "A", ["1.2.3.4"]),
                MockRecord("_dmarc", "TXT", ["v=DMARC1"]),
            ],
        )

        result = filter_instance.process_target_zone(zone, None)

        record_names = [r.name for r in result.records]
        assert "www" in record_names
        assert "_dmarc" in record_names

    def test_handles_multiple_acme_records(self, filter_instance):
        """Multiple ACME records should all be removed."""
        zone = MockZone(
            "example.com.",
            [
                MockRecord("_acme-challenge", "TXT", ["token1"]),
                MockRecord("_acme-challenge.api", "TXT", ["token2"]),
            ],
        )

        result = filter_instance.process_target_zone(zone, None)

        assert len(result.records) == 0

    def test_returns_zone(self, filter_instance):
        """Should return the modified zone object."""
        zone = MockZone("example.com.")
        result = filter_instance.process_target_zone(zone, None)
        assert result is zone
