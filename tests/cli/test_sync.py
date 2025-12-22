"""Tests for cli/sync.py"""

import pytest
from unittest.mock import patch, MagicMock
import subprocess

from octodns_gitops.cli.sync import (
    parse_record_change,
    format_zone_changes,
    detect_threshold_violations,
    parse_octodns_output,
    main,
)


class TestParseRecordChange:
    """Tests for parse_record_change()."""

    def test_parse_a_record(self):
        """Should parse A record from octodns output."""
        line = "*   Create <ARecord A 3600, www.example.com., ['1.2.3.4']> (zones)"
        result = parse_record_change(line)

        assert result is not None
        assert result["type"] == "A"
        assert result["name"] == "www"
        assert result["ttl"] == 3600
        assert "1.2.3.4" in result["values"]

    def test_parse_cname_record(self):
        """Should parse CNAME record from octodns output."""
        line = "*   Create <CnameRecord CNAME 3600, blog.example.com., ['blog.external.com.']> (zones)"
        result = parse_record_change(line)

        assert result is not None
        assert result["type"] == "CNAME"
        assert result["name"] == "blog"

    def test_parse_mx_record(self):
        """Should parse MX record from octodns output."""
        line = "*   Create <MxRecord MX 3600, mail.example.com., ['10 mail.example.com.']> (zones)"
        result = parse_record_change(line)

        assert result is not None
        assert result["type"] == "MX"
        assert result["name"] == "mail"

    def test_parse_txt_record(self):
        """Should parse TXT record from octodns output."""
        line = "*   Create <TxtRecord TXT 3600, spf.example.com., ['v=spf1 include:example.com ~all']> (zones)"
        result = parse_record_change(line)

        assert result is not None
        assert result["type"] == "TXT"
        assert result["name"] == "spf"

    def test_parse_apex_domain(self):
        """Should parse apex domain as '@'."""
        line = "*   Create <ARecord A 3600, example.com., ['1.2.3.4']> (zones)"
        result = parse_record_change(line)

        assert result is not None
        assert result["name"] == "@"

    def test_parse_subdomain(self):
        """Should parse subdomain correctly."""
        line = "*   Create <ARecord A 3600, www.example.com., ['1.2.3.4']> (zones)"
        result = parse_record_change(line)

        assert result is not None
        assert result["name"] == "www"

    def test_parse_nested_subdomain(self):
        """Should parse 'api.v1.example.com' as 'api.v1'."""
        line = "*   Create <ARecord A 3600, api.v1.example.com., ['1.2.3.4']> (zones)"
        result = parse_record_change(line)

        assert result is not None
        assert result["name"] == "api.v1"

    def test_extracts_ttl_as_int(self):
        """TTL should be extracted as integer."""
        line = "*   Create <ARecord A 1800, www.example.com., ['1.2.3.4']> (zones)"
        result = parse_record_change(line)

        assert result is not None
        assert result["ttl"] == 1800
        assert isinstance(result["ttl"], int)

    def test_extracts_values(self):
        """Values should be extracted correctly."""
        line = "*   Create <ARecord A 3600, www.example.com., ['1.2.3.4', '5.6.7.8']> (zones)"
        result = parse_record_change(line)

        assert result is not None
        assert "1.2.3.4" in result["values"]

    def test_invalid_line_returns_none(self):
        """Non-matching line should return None."""
        line = "Some random text"
        result = parse_record_change(line)
        assert result is None

    def test_empty_line_returns_none(self):
        """Empty line should return None."""
        result = parse_record_change("")
        assert result is None


class TestFormatZoneChanges:
    """Tests for format_zone_changes()."""

    def test_shows_create_count(self):
        """Create count should appear in header."""
        zone_data = {
            "name": "example.com.",
            "creates": 2,
            "updates": 0,
            "deletes": 0,
            "changes": ["+ A www ['1.2.3.4']", "+ A api ['5.6.7.8']"],
        }
        result = format_zone_changes(zone_data)

        assert len(result) > 0
        assert "2 creates" in result[0]

    def test_shows_update_count(self):
        """Update count should appear in header."""
        zone_data = {
            "name": "example.com.",
            "creates": 0,
            "updates": 1,
            "deletes": 0,
            "changes": ["~ A www TTL 1800->3600"],
        }
        result = format_zone_changes(zone_data)

        assert len(result) > 0
        assert "1 update" in result[0]

    def test_shows_delete_count(self):
        """Delete count should appear in header."""
        zone_data = {
            "name": "example.com.",
            "creates": 0,
            "updates": 0,
            "deletes": 3,
            "changes": ["- A old1", "- A old2", "- A old3"],
        }
        result = format_zone_changes(zone_data)

        assert len(result) > 0
        assert "3 deletes" in result[0]

    def test_no_changes_returns_empty(self):
        """Zone with no changes should return empty list."""
        zone_data = {
            "name": "example.com.",
            "creates": 0,
            "updates": 0,
            "deletes": 0,
            "changes": [],
        }
        result = format_zone_changes(zone_data)

        assert result == []

    def test_formats_changes_with_indent(self):
        """Individual changes should be formatted with indent."""
        zone_data = {
            "name": "example.com.",
            "creates": 1,
            "updates": 0,
            "deletes": 0,
            "changes": ["+ A www ['1.2.3.4']"],
        }
        result = format_zone_changes(zone_data)

        assert len(result) == 2
        assert result[1].startswith("  ")

    def test_singular_count(self):
        """Singular form should be used for count of 1."""
        zone_data = {
            "name": "example.com.",
            "creates": 1,
            "updates": 0,
            "deletes": 0,
            "changes": ["+ A www"],
        }
        result = format_zone_changes(zone_data)

        assert "1 create" in result[0]
        assert "1 creates" not in result[0]


class TestDetectThresholdViolations:
    """Tests for detect_threshold_violations()."""

    def test_updates_over_30_percent(self):
        """Updates >30% should be flagged."""
        zones = [
            {
                "name": "example.com.",
                "updates": 5,
                "deletes": 0,
                "existing": 10,
            }
        ]
        result = detect_threshold_violations(zones)

        assert len(result) == 1
        assert result[0]["type"] == "updates"
        assert result[0]["pct"] == 50.0

    def test_deletes_over_30_percent(self):
        """Deletes >30% should be flagged."""
        zones = [
            {
                "name": "example.com.",
                "updates": 0,
                "deletes": 4,
                "existing": 10,
            }
        ]
        result = detect_threshold_violations(zones)

        assert len(result) == 1
        assert result[0]["type"] == "deletes"
        assert result[0]["pct"] == 40.0

    def test_under_threshold(self):
        """Changes under 30% should not be flagged."""
        zones = [
            {
                "name": "example.com.",
                "updates": 2,
                "deletes": 1,
                "existing": 10,
            }
        ]
        result = detect_threshold_violations(zones)

        assert len(result) == 0

    def test_ignores_small_zones(self):
        """Zones with <10 records should not be checked."""
        zones = [
            {
                "name": "example.com.",
                "updates": 5,
                "deletes": 0,
                "existing": 5,  # Less than 10
            }
        ]
        result = detect_threshold_violations(zones)

        assert len(result) == 0

    def test_returns_details(self):
        """Violation should include zone, type, count, pct."""
        zones = [
            {
                "name": "example.com.",
                "updates": 5,
                "deletes": 0,
                "existing": 10,
            }
        ]
        result = detect_threshold_violations(zones)

        assert result[0]["zone"] == "example.com."
        assert result[0]["count"] == 5
        assert result[0]["total"] == 10

    def test_multiple_zones(self):
        """Multiple zones can have violations."""
        zones = [
            {"name": "a.com.", "updates": 5, "deletes": 0, "existing": 10},
            {"name": "b.com.", "updates": 0, "deletes": 5, "existing": 10},
        ]
        result = detect_threshold_violations(zones)

        assert len(result) == 2


class TestParseOctodnsOutput:
    """Tests for parse_octodns_output()."""

    def test_extracts_zone_names(self):
        """Zone names should be extracted from '* zone.' lines."""
        output = """
* example.com.
*   Summary: Creates=0, Updates=0, Deletes=0, Existing=5, Meta=False
"""
        result = parse_octodns_output(output)

        assert len(result) == 1
        assert result[0]["name"] == "example.com."

    def test_extracts_summary(self):
        """Summary counts should be extracted."""
        output = """
* example.com.
*   Summary: Creates=1, Updates=2, Deletes=3, Existing=10, Meta=False
"""
        result = parse_octodns_output(output)

        assert result[0]["creates"] == 1
        assert result[0]["updates"] == 2
        assert result[0]["deletes"] == 3
        assert result[0]["existing"] == 10

    def test_extracts_creates(self):
        """Create changes should be extracted."""
        output = """
* example.com.
*   Create <ARecord A 3600, www.example.com., ['1.2.3.4']> (zones)
*   Summary: Creates=1, Updates=0, Deletes=0, Existing=5, Meta=False
"""
        result = parse_octodns_output(output)

        assert len(result[0]["changes"]) == 1
        assert result[0]["changes"][0].startswith("+")

    def test_extracts_updates(self):
        """Update changes should be extracted (with old/new values)."""
        output = """
* example.com.
*   Update
*     <ARecord A 1800, www.example.com., ['1.2.3.4']> ->
*     <ARecord A 3600, www.example.com., ['1.2.3.4']> (zones)
*   Summary: Creates=0, Updates=1, Deletes=0, Existing=5, Meta=False
"""
        result = parse_octodns_output(output)

        assert len(result[0]["changes"]) == 1
        assert result[0]["changes"][0].startswith("~")
        assert "TTL" in result[0]["changes"][0]

    def test_extracts_deletes(self):
        """Delete changes should be extracted."""
        output = """
* example.com.
*   Delete <ARecord A 3600, old.example.com., ['1.2.3.4']>
*   Summary: Creates=0, Updates=0, Deletes=1, Existing=5, Meta=False
"""
        result = parse_octodns_output(output)

        assert len(result[0]["changes"]) == 1
        assert result[0]["changes"][0].startswith("-")

    def test_handles_multiple_zones(self):
        """Multiple zones should be parsed correctly."""
        output = """
* example.com.
*   Summary: Creates=1, Updates=0, Deletes=0, Existing=5, Meta=False
* example.org.
*   Summary: Creates=0, Updates=1, Deletes=0, Existing=8, Meta=False
"""
        result = parse_octodns_output(output)

        assert len(result) == 2
        assert result[0]["name"] == "example.com."
        assert result[1]["name"] == "example.org."

    def test_handles_empty_output(self):
        """Empty output should return empty list."""
        result = parse_octodns_output("")
        assert result == []

    def test_ignores_non_zone_lines(self):
        """Lines not starting with '* ' or zone names should be ignored."""
        output = """
Some header text
* example.com.
*   Summary: Creates=0, Updates=0, Deletes=0, Existing=5, Meta=False
"""
        result = parse_octodns_output(output)

        assert len(result) == 1


class TestMain:
    """Tests for main() function."""

    @pytest.fixture
    def mock_subprocess(self):
        with patch("subprocess.run") as mock_run:
            yield mock_run

    def test_success_no_changes(self, mock_subprocess, capsys):
        """Should print 'No changes' when no changes planned."""
        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="No changes were planned",
        )

        with patch("sys.argv", ["sync", "--config", "config.yaml"]):
            result = main()

        assert result == 0
        captured = capsys.readouterr()
        assert "No changes" in captured.out

    def test_success_with_changes(self, mock_subprocess, capsys):
        """Should parse and display changes."""
        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="""
* example.com.
*   Create <ARecord A 3600, www.example.com., ['1.2.3.4']> (zones)
*   Summary: Creates=1, Updates=0, Deletes=0, Existing=5, Meta=False
""",
        )

        with patch("sys.argv", ["sync", "--config", "config.yaml"]):
            result = main()

        assert result == 0
        captured = capsys.readouterr()
        assert "example.com." in captured.out
        assert "1 create" in captured.out

    def test_failure_credentials_error(self, mock_subprocess, capsys):
        """Should show credentials error message."""
        mock_subprocess.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="missing env var HETZNER_TOKEN",
        )

        with patch("sys.argv", ["sync", "--config", "config.yaml"]):
            with patch(
                "octodns_gitops.cli.sync.is_credentials_error", return_value=True
            ):
                with patch(
                    "octodns_gitops.cli.sync.format_missing_credentials_error",
                    return_value="Missing creds",
                ):
                    result = main()

        assert result == 1

    def test_doit_flag(self, mock_subprocess):
        """--doit flag should be passed to octodns-sync."""
        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="No changes were planned",
        )

        with patch("sys.argv", ["sync", "--config", "config.yaml", "--doit"]):
            main()

        cmd = mock_subprocess.call_args[0][0]
        assert "--doit" in cmd

    def test_force_flag_with_doit(self, mock_subprocess):
        """--force flag should be passed when --doit and --force."""
        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="No changes were planned",
        )

        with patch(
            "sys.argv", ["sync", "--config", "config.yaml", "--doit", "--force"]
        ):
            main()

        cmd = mock_subprocess.call_args[0][0]
        assert "--force" in cmd

    def test_zone_filter(self, mock_subprocess):
        """--zone flag should be passed to octodns-sync."""
        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="No changes were planned",
        )

        with patch(
            "sys.argv", ["sync", "--config", "config.yaml", "--zone", "example.com."]
        ):
            main()

        cmd = mock_subprocess.call_args[0][0]
        assert "example.com." in cmd
