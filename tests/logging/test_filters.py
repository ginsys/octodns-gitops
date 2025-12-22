"""Tests for logging/filters.py"""

import pytest
import logging

from octodns_gitops.logging.filters import SuppressSoaWarningsFilter


class TestSuppressSoaWarningsFilter:
    """Tests for SuppressSoaWarningsFilter."""

    @pytest.fixture
    def filter_instance(self):
        """Create a filter instance for testing."""
        return SuppressSoaWarningsFilter()

    @pytest.fixture
    def make_log_record(self):
        """Factory to create log records."""

        def _create(msg: str, level: int = logging.WARNING):
            record = logging.LogRecord(
                name="test",
                level=level,
                pathname="test.py",
                lineno=1,
                msg=msg,
                args=(),
                exc_info=None,
            )
            return record

        return _create

    def test_suppresses_soa_warning(self, filter_instance, make_log_record):
        """Should filter 'unsupported SOA record...skipping' messages."""
        record = make_log_record("unsupported SOA record type, skipping")
        assert filter_instance.filter(record) is False

    def test_suppresses_ns_warning(self, filter_instance, make_log_record):
        """Should filter 'root NS record supported...no record is configured' messages."""
        record = make_log_record(
            "root NS record supported, but no record is configured for this zone"
        )
        assert filter_instance.filter(record) is False

    def test_passes_other_warnings(self, filter_instance, make_log_record):
        """Should pass through unrelated warning messages."""
        record = make_log_record("Some other warning message")
        assert filter_instance.filter(record) is True

    def test_passes_errors(self, filter_instance, make_log_record):
        """Should pass through error messages even with SOA content."""
        record = make_log_record("Error processing SOA record", logging.ERROR)
        assert filter_instance.filter(record) is True

    def test_handles_getmessage_exception(self, filter_instance):
        """Should return True if getMessage() raises an exception."""

        class BadRecord:
            def getMessage(self):
                raise ValueError("Bad message")

        record = BadRecord()
        assert filter_instance.filter(record) is True

    def test_case_insensitive(self, filter_instance, make_log_record):
        """Should match regardless of case."""
        record_upper = make_log_record("UNSUPPORTED SOA RECORD TYPE, SKIPPING")
        record_mixed = make_log_record("Unsupported Soa Record Type, Skipping")

        assert filter_instance.filter(record_upper) is False
        assert filter_instance.filter(record_mixed) is False

    def test_partial_match_not_filtered(self, filter_instance, make_log_record):
        """Should not filter partial matches."""
        # Has 'skipping' but not 'unsupported SOA record'
        record1 = make_log_record("skipping invalid record")
        # Has 'unsupported SOA' but not 'skipping'
        record2 = make_log_record("unsupported SOA record found")

        assert filter_instance.filter(record1) is True
        assert filter_instance.filter(record2) is True
