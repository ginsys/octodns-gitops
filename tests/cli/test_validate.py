"""Tests for cli/validate.py"""

import pytest
from unittest.mock import patch, MagicMock
import os

from octodns_gitops.cli.validate import main


class TestMain:
    """Tests for main() function."""

    @pytest.fixture
    def mock_subprocess(self):
        with patch("subprocess.run") as mock_run:
            yield mock_run

    def test_success_returns_zero(self, mock_subprocess):
        """Successful validation should return 0."""
        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout="Validation successful",
            stderr="",
        )

        with patch("sys.argv", ["validate", "--config", "config.yaml"]):
            result = main()

        assert result == 0

    def test_failure_returns_nonzero(self, mock_subprocess):
        """Failed validation should return non-zero."""
        mock_subprocess.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="Validation failed: invalid record",
        )

        with patch("sys.argv", ["validate", "--config", "config.yaml"]):
            result = main()

        assert result == 1

    def test_missing_credentials_shows_message(self, mock_subprocess, capsys):
        """Missing API credentials should show clear message."""
        mock_subprocess.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="missing env var HETZNER_TOKEN",
        )

        with patch("sys.argv", ["validate", "--config", "config.yaml"]):
            with patch(
                "octodns_gitops.cli.validate.is_credentials_error", return_value=True
            ):
                with patch(
                    "octodns_gitops.cli.validate.format_missing_credentials_error",
                    return_value="Missing API credentials",
                ):
                    result = main()

        captured = capsys.readouterr()
        assert "Missing API credentials" in captured.err

    def test_traceback_shows_last_line(self, mock_subprocess, capsys):
        """Python traceback should show only last line."""
        mock_subprocess.return_value = MagicMock(
            returncode=1,
            stdout="",
            stderr="""Traceback (most recent call last):
  File "test.py", line 1, in <module>
    raise ValueError("test error")
ValueError: test error""",
        )

        with patch("sys.argv", ["validate", "--config", "config.yaml"]):
            with patch(
                "octodns_gitops.cli.validate.is_credentials_error", return_value=False
            ):
                result = main()

        captured = capsys.readouterr()
        assert "ValueError: test error" in captured.err
        # Should not include full traceback
        assert "most recent call last" not in captured.err

    def test_passes_logging_config(self, mock_subprocess):
        """--logging-config should be passed to octodns."""
        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="",
        )

        with patch(
            "sys.argv",
            ["validate", "--config", "config.yaml", "--logging-config", "logging.yaml"],
        ):
            main()

        cmd = mock_subprocess.call_args[0][0]
        assert "--logging-config" in cmd
        assert "logging.yaml" in cmd

    def test_uses_debug_env(self, mock_subprocess):
        """DEBUG env var should enable debug mode."""
        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="",
        )

        with patch.dict(os.environ, {"DEBUG": "1", "QUIET": ""}):
            with patch("sys.argv", ["validate", "--config", "config.yaml"]):
                main()

        cmd = mock_subprocess.call_args[0][0]
        assert "--debug" in cmd

    def test_quiet_by_default(self, mock_subprocess):
        """QUIET=1 should be default, enabling quiet mode."""
        mock_subprocess.return_value = MagicMock(
            returncode=0,
            stdout="",
            stderr="",
        )

        with patch.dict(os.environ, {"QUIET": "1"}, clear=False):
            with patch("sys.argv", ["validate", "--config", "config.yaml"]):
                main()

        cmd = mock_subprocess.call_args[0][0]
        assert "--quiet" in cmd
