"""Tests for cli/report.py"""

import pytest
from unittest.mock import patch, MagicMock
import os

from octodns_gitops.cli.report import (
    zone_to_filename,
    apex_nameservers,
    iter_zones,
    truncate_value,
    format_report_output,
    main,
)


class TestZoneToFilename:
    """Tests for zone_to_filename()."""

    def test_strips_trailing_dot(self):
        """'example.com.' should become 'zones/example.com.yaml'."""
        result = zone_to_filename("example.com.")
        assert result == "zones/example.com.yaml"

    def test_handles_no_dot(self):
        """'example.com' should become 'zones/example.com.yaml'."""
        result = zone_to_filename("example.com")
        assert result == "zones/example.com.yaml"

    def test_nested_domain(self):
        """'sub.example.com.' should become 'zones/sub.example.com.yaml'."""
        result = zone_to_filename("sub.example.com.")
        assert result == "zones/sub.example.com.yaml"


class TestApexNameservers:
    """Tests for apex_nameservers()."""

    def test_returns_ns_values(self, tmp_path):
        """Should return NS values from apex record."""
        zone_file = tmp_path / "example.com.yaml"
        zone_file.write_text("""
'':
- type: NS
  values:
  - ns1.example.com.
  - ns2.example.com.
""")
        result = apex_nameservers(str(zone_file))

        assert "ns1.example.com" in result
        assert "ns2.example.com" in result

    def test_strips_trailing_dots(self, tmp_path):
        """NS values should have trailing dots stripped."""
        zone_file = tmp_path / "example.com.yaml"
        zone_file.write_text("""
'':
- type: NS
  values:
  - ns1.example.com.
""")
        result = apex_nameservers(str(zone_file))

        assert result == ["ns1.example.com"]

    def test_handles_missing_file(self, tmp_path):
        """Missing file should return empty list."""
        result = apex_nameservers(str(tmp_path / "nonexistent.yaml"))
        assert result == []

    def test_handles_no_ns_record(self, tmp_path):
        """Zone without NS should return empty list."""
        zone_file = tmp_path / "example.com.yaml"
        zone_file.write_text("""
'':
  type: A
  value: 1.2.3.4
""")
        result = apex_nameservers(str(zone_file))
        assert result == []

    def test_handles_dict_apex(self, tmp_path):
        """Dict apex format should work."""
        zone_file = tmp_path / "example.com.yaml"
        zone_file.write_text("""
'':
  type: NS
  values:
  - ns1.example.com.
""")
        result = apex_nameservers(str(zone_file))
        assert result == ["ns1.example.com"]

    def test_handles_list_apex(self, tmp_path):
        """List apex format should work."""
        zone_file = tmp_path / "example.com.yaml"
        zone_file.write_text("""
'':
- type: A
  value: 1.2.3.4
- type: NS
  values:
  - ns1.example.com.
""")
        result = apex_nameservers(str(zone_file))
        assert result == ["ns1.example.com"]


class TestIterZones:
    """Tests for iter_zones()."""

    def test_returns_all_zones(self):
        """Should return all zones from config."""
        cfg = {
            "zones": {
                "example.com.": {},
                "example.org.": {},
            }
        }
        result = iter_zones(cfg, None)

        assert len(result) == 2
        assert "example.com." in result
        assert "example.org." in result

    def test_filters_specific_zone(self):
        """--zone should filter to specific zone."""
        cfg = {
            "zones": {
                "example.com.": {},
                "example.org.": {},
            }
        }
        result = iter_zones(cfg, "example.com.")

        assert result == ["example.com."]

    def test_adds_trailing_dot(self):
        """Zone without dot should have dot added."""
        cfg = {
            "zones": {
                "example.com.": {},
            }
        }
        result = iter_zones(cfg, "example.com")

        assert result == ["example.com."]

    def test_nonexistent_zone_returns_empty(self):
        """Non-existent zone should return empty list."""
        cfg = {
            "zones": {
                "example.com.": {},
            }
        }
        result = iter_zones(cfg, "nonexistent.com.")

        assert result == []


class TestTruncateValue:
    """Tests for truncate_value()."""

    def test_short_string(self):
        """Short strings should not be truncated."""
        result = truncate_value("short", 50)
        assert result == "short"

    def test_long_string(self):
        """Long strings should be truncated with '...'."""
        result = truncate_value("a" * 60, 50)

        assert len(result) == 50
        assert result.endswith("...")

    def test_custom_length(self):
        """Custom max_len should work."""
        result = truncate_value("abcdefghij", 5)

        assert len(result) == 5
        assert result == "ab..."

    def test_exact_length(self):
        """String at exact max_len should not be truncated."""
        result = truncate_value("12345", 5)
        assert result == "12345"


class TestFormatReportOutput:
    """Tests for format_report_output()."""

    def test_empty_output(self, capsys):
        """Empty output should print 'No output'."""
        format_report_output("", "example.com.")

        captured = capsys.readouterr()
        assert "No output" in captured.out

    def test_consistent_records(self, capsys):
        """All consistent should show success message."""
        csv_output = """Name,Type,TTL,ns1,ns2,Consistent
www,A,3600,1.2.3.4,1.2.3.4,True
mail,MX,3600,10 mail,10 mail,True
"""
        format_report_output(csv_output, "example.com.")

        captured = capsys.readouterr()
        assert "consistent" in captured.out.lower()

    def test_inconsistent_records(self, capsys):
        """Inconsistent records should show warning."""
        csv_output = """Name,Type,TTL,ns1,ns2,Consistent
www,A,3600,1.2.3.4,5.6.7.8,False
"""
        format_report_output(csv_output, "example.com.")

        captured = capsys.readouterr()
        assert "INCONSISTENCIES" in captured.out or "Inconsistent" in captured.out

    def test_no_records(self, capsys):
        """No records should print 'No records found'."""
        csv_output = """Name,Type,TTL,Consistent
"""
        format_report_output(csv_output, "example.com.")

        captured = capsys.readouterr()
        assert "No records" in captured.out


class TestMain:
    """Tests for main() function."""

    @pytest.fixture
    def mock_subprocess(self):
        with patch("subprocess.run") as mock_run:
            yield mock_run

    def test_no_zones_returns_error(self, tmp_path, capsys):
        """No zones in config should return error."""
        config = tmp_path / "config.yaml"
        config.write_text("""
providers: {}
zones: {}
""")

        with patch("sys.argv", ["report", "--config", str(config)]):
            result = main()

        assert result == 1
        captured = capsys.readouterr()
        assert "No zones" in captured.err

    def test_success_with_zones(self, mock_subprocess, tmp_path):
        """Should succeed with valid zones."""
        config = tmp_path / "config.yaml"
        config.write_text("""
providers:
  zones:
    class: octodns.provider.yaml.YamlProvider
zones:
  example.com.:
    sources:
      - zones
""")

        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout="Name,Type,TTL,ns1,Consistent\nwww,A,3600,1.2.3.4,True\n",
            stderr="",
        )

        with patch("sys.argv", ["report", "--config", str(config)]):
            # Need to mock zone file existence too
            with patch("octodns_gitops.cli.report.apex_nameservers", return_value=[]):
                result = main()

        assert result == 0

    def test_zone_filter(self, mock_subprocess, tmp_path):
        """--zone flag should filter to specific zone."""
        config = tmp_path / "config.yaml"
        config.write_text("""
providers:
  zones:
    class: octodns.provider.yaml.YamlProvider
zones:
  example.com.:
    sources:
      - zones
  other.com.:
    sources:
      - zones
""")

        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout="Name,Type,TTL,ns1,Consistent\nwww,A,3600,1.2.3.4,True\n",
            stderr="",
        )

        with patch(
            "sys.argv", ["report", "--config", str(config), "--zone", "example.com."]
        ):
            with patch("octodns_gitops.cli.report.apex_nameservers", return_value=[]):
                result = main()

        # Should only call report for one zone
        assert mock_subprocess.call_count == 1
