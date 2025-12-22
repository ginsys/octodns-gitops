"""Tests for processors/external_dns_filter.py"""

import pytest

from octodns_gitops.processors.external_dns_filter import ExternalDnsFilter


# Mock record and zone classes for testing
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


class TestInit:
    """Tests for ExternalDnsFilter initialization."""

    def test_default_values(self):
        """Should use default txt_prefix='extdns' and default type_prefixes."""
        f = ExternalDnsFilter("test")
        assert f.txt_prefix == "extdns"
        assert f.type_prefixes == ["a-", "aaaa-", "cname-", "txt-"]
        assert f.owner_id is None

    def test_custom_values(self):
        """Should accept custom txt_prefix, type_prefixes, and owner_id."""
        f = ExternalDnsFilter(
            "test",
            txt_prefix="mydns",
            type_prefixes=["a-", "cname-"],
            owner_id="my-cluster",
        )
        assert f.txt_prefix == "mydns"
        assert f.type_prefixes == ["a-", "cname-"]
        assert f.owner_id == "my-cluster"


class TestParseTxtName:
    """Tests for _parse_txt_name()."""

    @pytest.fixture
    def filter_instance(self):
        return ExternalDnsFilter("test")

    def test_non_matching_prefix(self, filter_instance):
        """'otherprefixwww' should return (None, None)."""
        result = filter_instance._parse_txt_name("otherprefixwww", "example.com.")
        assert result == (None, None)

    def test_subdomain_no_type_prefix(self, filter_instance):
        """'extdnswww' should return ('www', 'A')."""
        result = filter_instance._parse_txt_name("extdnswww", "example.com.")
        assert result == ("www", "A")

    def test_subdomain_a_prefix(self, filter_instance):
        """'extdnsa-www' should return ('www', 'A')."""
        result = filter_instance._parse_txt_name("extdnsa-www", "example.com.")
        assert result == ("www", "A")

    def test_subdomain_aaaa_prefix(self, filter_instance):
        """'extdnsaaaa-www' should return ('www', 'AAAA')."""
        result = filter_instance._parse_txt_name("extdnsaaaa-www", "example.com.")
        assert result == ("www", "AAAA")

    def test_subdomain_cname_prefix(self, filter_instance):
        """'extdnscname-api' should return ('api', 'CNAME')."""
        result = filter_instance._parse_txt_name("extdnscname-api", "example.com.")
        assert result == ("api", "CNAME")

    def test_subdomain_txt_prefix(self, filter_instance):
        """'extdnstxt-spf' should return ('spf', 'TXT')."""
        result = filter_instance._parse_txt_name("extdnstxt-spf", "example.com.")
        assert result == ("spf", "TXT")

    def test_apex_no_type_prefix(self, filter_instance):
        """'extdnsexample.com' for zone 'example.com.' should return ('', 'A')."""
        result = filter_instance._parse_txt_name("extdnsexample.com", "example.com.")
        assert result == ("", "A")

    def test_apex_with_a_prefix(self, filter_instance):
        """'extdnsa-example.com' for zone 'example.com.' should return ('', 'A')."""
        result = filter_instance._parse_txt_name("extdnsa-example.com", "example.com.")
        assert result == ("", "A")

    def test_apex_with_cname_prefix(self, filter_instance):
        """'extdnscname-example.com' should return ('', 'CNAME')."""
        result = filter_instance._parse_txt_name(
            "extdnscname-example.com", "example.com."
        )
        assert result == ("", "CNAME")

    def test_nested_subdomain(self, filter_instance):
        """'extdnsa-api.v1' should return ('api.v1', 'A')."""
        result = filter_instance._parse_txt_name("extdnsa-api.v1", "example.com.")
        assert result == ("api.v1", "A")

    def test_custom_txt_prefix(self):
        """Custom txt_prefix='mydns' should work."""
        f = ExternalDnsFilter("test", txt_prefix="mydns")
        result = f._parse_txt_name("mydnsa-www", "example.com.")
        assert result == ("www", "A")

    def test_unknown_type_prefix_defaults_to_a(self, filter_instance):
        """Unknown type prefix should still parse, defaulting to 'A'."""
        # 'extdnsxxx-www' - 'xxx-' is not a known type prefix
        # So it should return ('xxx-www', 'A')
        result = filter_instance._parse_txt_name("extdnsxxx-www", "example.com.")
        assert result == ("xxx-www", "A")


class TestIsExternalDnsTxt:
    """Tests for _is_external_dns_txt()."""

    @pytest.fixture
    def filter_instance(self):
        return ExternalDnsFilter("test")

    def test_non_txt_record(self, filter_instance):
        """A record should return (False, None, None)."""
        record = MockRecord("www", "A", ["1.2.3.4"])
        result = filter_instance._is_external_dns_txt(record, "example.com.")
        assert result == (False, None, None)

    def test_unrelated_txt(self, filter_instance):
        """TXT without heritage should return (False, None, None)."""
        record = MockRecord("extdnsa-www", "TXT", ["some-other-value"])
        result = filter_instance._is_external_dns_txt(record, "example.com.")
        assert result == (False, None, None)

    def test_with_heritage(self, filter_instance):
        """TXT with heritage=external-dns should return (True, name, type)."""
        record = MockRecord(
            "extdnsa-www", "TXT", ["heritage=external-dns,external-dns/owner=default"]
        )
        result = filter_instance._is_external_dns_txt(record, "example.com.")
        assert result == (True, "www", "A")

    def test_any_owner_when_not_configured(self, filter_instance):
        """Any owner_id should match when owner_id=None."""
        record = MockRecord(
            "extdnsa-www", "TXT", ["heritage=external-dns,external-dns/owner=any-owner"]
        )
        result = filter_instance._is_external_dns_txt(record, "example.com.")
        assert result == (True, "www", "A")

    def test_matching_owner_id(self):
        """Matching owner_id should return True."""
        f = ExternalDnsFilter("test", owner_id="my-cluster")
        record = MockRecord(
            "extdnsa-www",
            "TXT",
            ["heritage=external-dns,external-dns/owner=my-cluster"],
        )
        result = f._is_external_dns_txt(record, "example.com.")
        assert result == (True, "www", "A")

    def test_non_matching_owner_id(self):
        """Non-matching owner_id should return False."""
        f = ExternalDnsFilter("test", owner_id="my-cluster")
        record = MockRecord(
            "extdnsa-www",
            "TXT",
            ["heritage=external-dns,external-dns/owner=other-cluster"],
        )
        result = f._is_external_dns_txt(record, "example.com.")
        assert result == (False, None, None)

    def test_checks_all_values(self, filter_instance):
        """Should check all TXT values, not just first."""
        record = MockRecord(
            "extdnsa-www",
            "TXT",
            ["some-other-value", "heritage=external-dns,external-dns/owner=default"],
        )
        result = filter_instance._is_external_dns_txt(record, "example.com.")
        assert result == (True, "www", "A")

    def test_returns_correct_type(self, filter_instance):
        """Should return correct DNS record type from marker."""
        record_a = MockRecord("extdnsa-www", "TXT", ["heritage=external-dns"])
        record_cname = MockRecord("extdnscname-www", "TXT", ["heritage=external-dns"])
        record_aaaa = MockRecord("extdnsaaaa-www", "TXT", ["heritage=external-dns"])

        assert filter_instance._is_external_dns_txt(record_a, "example.com.") == (
            True,
            "www",
            "A",
        )
        assert filter_instance._is_external_dns_txt(record_cname, "example.com.") == (
            True,
            "www",
            "CNAME",
        )
        assert filter_instance._is_external_dns_txt(record_aaaa, "example.com.") == (
            True,
            "www",
            "AAAA",
        )


class TestFilterTxtValues:
    """Tests for _filter_txt_values()."""

    @pytest.fixture
    def filter_instance(self):
        return ExternalDnsFilter("test")

    def test_removes_heritage_value(self, filter_instance):
        """Single heritage value should trigger modification."""
        zone = MockZone(
            "example.com.",
            [MockRecord("txt", "TXT", ["heritage=external-dns", "other-value"])],
        )

        count = filter_instance._filter_txt_values(zone)
        assert count == 1

    def test_preserves_non_heritage_values(self, filter_instance):
        """Non-heritage values should be preserved."""
        zone = MockZone(
            "example.com.",
            [MockRecord("spf", "TXT", ["v=spf1 include:example.com ~all"])],
        )

        count = filter_instance._filter_txt_values(zone)
        assert count == 0
        assert len(zone.records) == 1

    def test_returns_count(self, filter_instance):
        """Should return modification count."""
        zone = MockZone(
            "example.com.",
            [
                MockRecord("txt1", "TXT", ["heritage=external-dns", "keep"]),
                MockRecord("txt2", "TXT", ["heritage=external-dns", "also-keep"]),
                MockRecord("txt3", "TXT", ["no-heritage"]),
            ],
        )

        count = filter_instance._filter_txt_values(zone)
        assert count == 2

    def test_all_heritage_not_modified(self, filter_instance):
        """Record with only heritage values should not be modified here."""
        zone = MockZone(
            "example.com.", [MockRecord("txt", "TXT", ["heritage=external-dns"])]
        )

        count = filter_instance._filter_txt_values(zone)
        # No modification because no non-heritage values remain
        assert count == 0


class TestProcessTargetZone:
    """Tests for process_target_zone()."""

    @pytest.fixture
    def filter_instance(self):
        return ExternalDnsFilter("test")

    def test_removes_txt_markers(self, filter_instance):
        """External-dns TXT markers should be removed."""
        zone = MockZone(
            "example.com.",
            [
                MockRecord("extdnsa-www", "TXT", ["heritage=external-dns"]),
                MockRecord("www", "A", ["1.2.3.4"]),
            ],
        )

        result = filter_instance.process_target_zone(zone, None)

        record_names = [r.name for r in result.records]
        assert "extdnsa-www" not in record_names

    def test_removes_managed_records(self, filter_instance):
        """Records managed by external-dns should be removed."""
        zone = MockZone(
            "example.com.",
            [
                MockRecord("extdnsa-www", "TXT", ["heritage=external-dns"]),
                MockRecord("www", "A", ["1.2.3.4"]),
                MockRecord("mail", "MX", ["10 mail.example.com."]),
            ],
        )

        result = filter_instance.process_target_zone(zone, None)

        record_names = [r.name for r in result.records]
        assert "www" not in record_names
        assert "mail" in record_names

    def test_matches_name_and_type(self, filter_instance):
        """Only matching (name, type) pairs should be removed."""
        zone = MockZone(
            "example.com.",
            [
                MockRecord(
                    "extdnsa-www", "TXT", ["heritage=external-dns"]
                ),  # Manages www A
                MockRecord("www", "A", ["1.2.3.4"]),  # Should be removed
                MockRecord("www", "MX", ["10 mail.example.com."]),  # Should remain
                MockRecord("www", "TXT", ["some-txt-value"]),  # Should remain
            ],
        )

        result = filter_instance.process_target_zone(zone, None)

        remaining = [(r.name, r._type) for r in result.records]
        assert ("www", "A") not in remaining
        assert ("www", "MX") in remaining
        assert ("www", "TXT") in remaining

    def test_preserves_unmanaged(self, filter_instance):
        """Records not managed by external-dns should remain."""
        zone = MockZone(
            "example.com.",
            [
                MockRecord("other", "A", ["1.2.3.4"]),
                MockRecord("mail", "MX", ["10 mail.example.com."]),
            ],
        )

        result = filter_instance.process_target_zone(zone, None)

        assert len(result.records) == 2

    def test_preserves_same_name_different_type(self, filter_instance):
        """MX at 'www' should remain when only A is managed."""
        zone = MockZone(
            "example.com.",
            [
                MockRecord("extdnsa-www", "TXT", ["heritage=external-dns"]),
                MockRecord("www", "A", ["1.2.3.4"]),
                MockRecord("www", "MX", ["10 mail.example.com."]),
            ],
        )

        result = filter_instance.process_target_zone(zone, None)

        remaining = [(r.name, r._type) for r in result.records]
        assert ("www", "MX") in remaining

    def test_handles_apex(self, filter_instance):
        """Apex records managed by external-dns should be removed."""
        zone = MockZone(
            "example.com.",
            [
                MockRecord("extdnsa-example.com", "TXT", ["heritage=external-dns"]),
                MockRecord("", "A", ["1.2.3.4"]),
                MockRecord("", "MX", ["10 mail.example.com."]),
            ],
        )

        result = filter_instance.process_target_zone(zone, None)

        remaining = [(r.name, r._type) for r in result.records]
        assert ("", "A") not in remaining
        assert ("", "MX") in remaining

    def test_returns_zone(self, filter_instance):
        """Should return the modified zone object."""
        zone = MockZone("example.com.")
        result = filter_instance.process_target_zone(zone, None)
        assert result is zone


class TestProcessSourceZone:
    """Tests for process_source_zone()."""

    @pytest.fixture
    def filter_instance(self):
        return ExternalDnsFilter("test")

    def test_removes_txt_markers(self, filter_instance):
        """External-dns TXT markers should be removed from source."""
        zone = MockZone(
            "example.com.",
            [
                MockRecord("extdnsa-www", "TXT", ["heritage=external-dns"]),
                MockRecord("www", "A", ["1.2.3.4"]),
            ],
        )

        result = filter_instance.process_source_zone(zone, [])

        record_names = [r.name for r in result.records]
        assert "extdnsa-www" not in record_names

    def test_removes_managed_records(self, filter_instance):
        """Records managed by external-dns should be removed from source."""
        zone = MockZone(
            "example.com.",
            [
                MockRecord("extdnsa-api", "TXT", ["heritage=external-dns"]),
                MockRecord("api", "A", ["5.6.7.8"]),
            ],
        )

        result = filter_instance.process_source_zone(zone, [])

        record_names = [r.name for r in result.records]
        assert "api" not in record_names

    def test_matches_name_and_type(self, filter_instance):
        """Only matching (name, type) pairs should be removed from source."""
        zone = MockZone(
            "example.com.",
            [
                MockRecord("extdnscname-blog", "TXT", ["heritage=external-dns"]),
                MockRecord("blog", "CNAME", ["blog.external.com."]),
                MockRecord("blog", "TXT", ["verification-token"]),
            ],
        )

        result = filter_instance.process_source_zone(zone, [])

        remaining = [(r.name, r._type) for r in result.records]
        assert ("blog", "CNAME") not in remaining
        assert ("blog", "TXT") in remaining

    def test_preserves_unmanaged(self, filter_instance):
        """Records not managed by external-dns should remain in source."""
        zone = MockZone(
            "example.com.",
            [
                MockRecord("www", "A", ["1.2.3.4"]),
                MockRecord("mail", "MX", ["10 mail.example.com."]),
            ],
        )

        result = filter_instance.process_source_zone(zone, [])

        assert len(result.records) == 2

    def test_preserves_same_name_different_type(self, filter_instance):
        """TXT at 'api' should remain when only A is managed."""
        zone = MockZone(
            "example.com.",
            [
                MockRecord("extdnsa-api", "TXT", ["heritage=external-dns"]),
                MockRecord("api", "A", ["5.6.7.8"]),
                MockRecord("api", "TXT", ["verification"]),
            ],
        )

        result = filter_instance.process_source_zone(zone, [])

        remaining = [(r.name, r._type) for r in result.records]
        assert ("api", "TXT") in remaining

    def test_handles_apex(self, filter_instance):
        """Apex records managed by external-dns should be removed from source."""
        zone = MockZone(
            "example.com.",
            [
                MockRecord("extdnsexample.com", "TXT", ["heritage=external-dns"]),
                MockRecord("", "A", ["1.2.3.4"]),
            ],
        )

        result = filter_instance.process_source_zone(zone, [])

        remaining = [(r.name, r._type) for r in result.records]
        assert ("", "A") not in remaining

    def test_returns_zone(self, filter_instance):
        """Should return the modified zone object."""
        zone = MockZone("example.com.")
        result = filter_instance.process_source_zone(zone, [])
        assert result is zone
