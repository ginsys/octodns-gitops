"""
Logging filters for suppressing noisy warnings from DNS providers.
"""

import logging


class SuppressSoaWarningsFilter(logging.Filter):
    """
    Drop noisy warnings from providers (e.g., Hetzner) when populating.

    Suppresses:
    - SOA warnings: 'skipping' and 'unsupported SOA record'
    - NS warnings: 'root NS record supported, but no record is configured'
    """

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            msg = record.getMessage().lower()
        except Exception:
            return True

        # Suppress SOA warnings
        if "unsupported soa record" in msg and "skipping" in msg:
            return False

        # Suppress NS record warnings
        if "root ns record supported" in msg and "no record is configured" in msg:
            return False

        return True
