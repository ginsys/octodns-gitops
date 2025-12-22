"""
Configuration parsing utilities for octodns-gitops.

Provides functions to extract environment variable requirements from
octodns config.yaml files and format helpful error messages.
"""

import os
import re
from pathlib import Path

import yaml


def get_required_env_vars(config_path: str) -> dict[str, str]:
    """
    Parse config.yaml and extract all required environment variables.

    Scans the providers section for 'env/VAR_NAME' token patterns
    and returns a mapping of env var names to provider names.

    Args:
        config_path: Path to octodns config.yaml file

    Returns:
        dict mapping environment variable names to provider names
        e.g., {'HETZNER_DNS_TOKEN': 'hetzner', 'HCLOUD_TOKEN': 'hcloud-company'}
    """
    config_file = Path(config_path)
    if not config_file.exists():
        return {}

    with open(config_file, "r") as f:
        cfg = yaml.safe_load(f)

    if not cfg:
        return {}

    env_vars: dict[str, str] = {}
    providers = cfg.get("providers", {})

    # Pattern to match env/VAR_NAME references
    env_pattern = re.compile(r"^env/(.+)$")

    for provider_name, provider_cfg in providers.items():
        if not isinstance(provider_cfg, dict):
            continue

        # Check common token fields
        for field in [
            "token",
            "api_key",
            "api_token",
            "secret",
            "password",
            "credentials",
        ]:
            value = provider_cfg.get(field)
            if isinstance(value, str):
                match = env_pattern.match(value)
                if match:
                    env_var = match.group(1)
                    env_vars[env_var] = provider_name

    return env_vars


def get_missing_env_vars(config_path: str) -> dict[str, str]:
    """
    Get environment variables that are required but not set.

    Args:
        config_path: Path to octodns config.yaml file

    Returns:
        dict mapping missing environment variable names to provider names
    """
    required = get_required_env_vars(config_path)
    return {
        var: provider for var, provider in required.items() if not os.environ.get(var)
    }


def format_missing_credentials_error(config_path: str, stderr: str = "") -> str:
    """
    Format a helpful error message for missing credentials.

    Parses config.yaml to determine which environment variables are needed
    and which are missing, then returns a formatted error message.

    Args:
        config_path: Path to octodns config.yaml file
        stderr: Optional stderr output from octodns command (for context)

    Returns:
        Formatted error message string
    """
    missing = get_missing_env_vars(config_path)

    if not missing:
        # Couldn't determine missing vars, return generic message
        return "Missing API credentials. Check provider tokens in config.yaml."

    lines = ["Missing API credentials:"]
    for env_var, provider in sorted(missing.items()):
        lines.append(f"  - {env_var} (provider: {provider})")

    lines.append("")
    lines.append("Set these environment variables or configure them in mise.local.toml")

    return "\n".join(lines)


def is_credentials_error(stderr: str) -> bool:
    """
    Check if stderr output indicates a credentials/authentication error.

    Args:
        stderr: Standard error output from octodns command

    Returns:
        True if the error appears to be credentials-related
    """
    indicators = [
        "missing env var",
        "authentication",
        "unauthorized",
        "forbidden",
        "invalid token",
        "api key",
        "credentials",
    ]
    stderr_lower = stderr.lower()
    return any(indicator in stderr_lower for indicator in indicators)
