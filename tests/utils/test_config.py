"""Tests for utils/config.py"""

import pytest
import os
from pathlib import Path
from unittest.mock import patch

from octodns_gitops.utils.config import (
    get_required_env_vars,
    get_missing_env_vars,
    format_missing_credentials_error,
    is_credentials_error,
)


class TestGetRequiredEnvVars:
    """Tests for get_required_env_vars()."""

    def test_extracts_token_field(self, tmp_path):
        """Should extract env var from 'token' field."""
        config = tmp_path / "config.yaml"
        config.write_text("""
providers:
  hetzner:
    class: octodns_hetzner.HetznerProvider
    token: env/HETZNER_DNS_TOKEN
""")
        result = get_required_env_vars(str(config))
        assert result == {"HETZNER_DNS_TOKEN": "hetzner"}

    def test_extracts_api_key_field(self, tmp_path):
        """Should extract env var from 'api_key' field."""
        config = tmp_path / "config.yaml"
        config.write_text("""
providers:
  cloudflare:
    class: octodns_cloudflare.CloudflareProvider
    api_key: env/CLOUDFLARE_API_KEY
""")
        result = get_required_env_vars(str(config))
        assert result == {"CLOUDFLARE_API_KEY": "cloudflare"}

    def test_extracts_multiple_providers(self, tmp_path):
        """Should extract env vars from multiple providers."""
        config = tmp_path / "config.yaml"
        config.write_text("""
providers:
  hetzner:
    class: octodns_hetzner.HetznerProvider
    token: env/HETZNER_DNS_TOKEN
  hcloud:
    class: octodns_hetzner.HcloudProvider
    token: env/HCLOUD_TOKEN
""")
        result = get_required_env_vars(str(config))
        assert result == {
            "HETZNER_DNS_TOKEN": "hetzner",
            "HCLOUD_TOKEN": "hcloud",
        }

    def test_missing_file_returns_empty(self, tmp_path):
        """Should return empty dict for missing file."""
        result = get_required_env_vars(str(tmp_path / "nonexistent.yaml"))
        assert result == {}

    def test_empty_config_returns_empty(self, tmp_path):
        """Should return empty dict for empty config."""
        config = tmp_path / "config.yaml"
        config.write_text("")
        result = get_required_env_vars(str(config))
        assert result == {}

    def test_no_env_prefix_ignored(self, tmp_path):
        """Should ignore tokens without 'env/' prefix."""
        config = tmp_path / "config.yaml"
        config.write_text("""
providers:
  hetzner:
    class: octodns_hetzner.HetznerProvider
    token: direct-token-value
""")
        result = get_required_env_vars(str(config))
        assert result == {}

    def test_non_dict_provider_ignored(self, tmp_path):
        """Should ignore non-dict provider configs."""
        config = tmp_path / "config.yaml"
        config.write_text("""
providers:
  hetzner: some-string-value
""")
        result = get_required_env_vars(str(config))
        assert result == {}


class TestGetMissingEnvVars:
    """Tests for get_missing_env_vars()."""

    def test_all_set_returns_empty(self, tmp_path):
        """Should return empty dict when all env vars are set."""
        config = tmp_path / "config.yaml"
        config.write_text("""
providers:
  hetzner:
    token: env/TEST_TOKEN
""")
        with patch.dict(os.environ, {"TEST_TOKEN": "value"}):
            result = get_missing_env_vars(str(config))
        assert result == {}

    def test_some_missing_returns_missing(self, tmp_path):
        """Should return only missing env vars."""
        config = tmp_path / "config.yaml"
        config.write_text("""
providers:
  hetzner:
    token: env/HETZNER_TOKEN
  hcloud:
    token: env/HCLOUD_TOKEN
""")
        with patch.dict(os.environ, {"HETZNER_TOKEN": "value"}, clear=True):
            result = get_missing_env_vars(str(config))
        assert result == {"HCLOUD_TOKEN": "hcloud"}


class TestFormatMissingCredentialsError:
    """Tests for format_missing_credentials_error()."""

    def test_with_missing_vars(self, tmp_path):
        """Should format error message with missing vars."""
        config = tmp_path / "config.yaml"
        config.write_text("""
providers:
  hetzner:
    token: env/HETZNER_TOKEN
""")
        with patch.dict(os.environ, {}, clear=True):
            result = format_missing_credentials_error(str(config))

        assert "Missing API credentials" in result
        assert "HETZNER_TOKEN" in result
        assert "hetzner" in result

    def test_none_missing_returns_generic(self, tmp_path):
        """Should return generic message when no vars detected as missing."""
        config = tmp_path / "config.yaml"
        config.write_text("""
providers:
  hetzner:
    token: env/TEST_TOKEN
""")
        with patch.dict(os.environ, {"TEST_TOKEN": "value"}):
            result = format_missing_credentials_error(str(config))

        assert "Missing API credentials" in result
        assert "config.yaml" in result


class TestIsCredentialsError:
    """Tests for is_credentials_error()."""

    def test_detects_missing_env_var(self):
        """Should detect 'missing env var' pattern."""
        assert is_credentials_error("Error: missing env var HETZNER_TOKEN")

    def test_detects_authentication(self):
        """Should detect 'authentication' pattern."""
        assert is_credentials_error("Authentication failed")

    def test_detects_unauthorized(self):
        """Should detect 'unauthorized' pattern."""
        assert is_credentials_error("401 Unauthorized")

    def test_detects_invalid_token(self):
        """Should detect 'invalid token' pattern."""
        assert is_credentials_error("Invalid token provided")

    def test_case_insensitive(self):
        """Should be case insensitive."""
        assert is_credentials_error("AUTHENTICATION FAILED")
        assert is_credentials_error("Missing Env Var")

    def test_non_credentials_error(self):
        """Should return False for non-credentials errors."""
        assert not is_credentials_error("Zone not found")
        assert not is_credentials_error("Invalid record type")
        assert not is_credentials_error("")
