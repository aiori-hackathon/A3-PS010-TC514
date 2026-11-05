"""Application settings, read from environment variables / a local .env file.

Secrets (API keys, tokens) are excluded from repr() so they do not leak into
logs or tracebacks. Nothing here performs network access.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from datetime import timedelta
from pathlib import Path
from typing import Mapping, Optional

from .audit.retention import DEFAULT_RETENTION_DAYS, parse_enabled, parse_retention_days
from .sources import SOURCES


@dataclass(frozen=True)
class Settings:
    db_path: Path = Path("data/audit.sqlite3")
    cache_dir: Path = Path("data/cache")
    tor_exit_list_url: str = "https://check.torproject.org/torbulkexitlist"
    ripestat_base_url: str = "https://stat.ripe.net/data"
    # Optional identifier RIPEstat asks regular API users to send (documented
    # characters only: letters, digits, '-' and '_'). Not a secret.
    ripestat_sourceapp: Optional[str] = None
    # How long a successful RIPEstat response may be reused (in memory only).
    ripestat_cache_ttl_seconds: int = 3600
    # Optional IPinfo Lite API. Disabled unless IPINFO_TOKEN is set.
    ipinfo_base_url: str = "https://api.ipinfo.io"
    ipinfo_cache_ttl_seconds: int = 3600
    http_timeout_seconds: float = 10.0
    # Retries after the first attempt, for the three evidence sources only, and only for
    # timeouts, connection errors, HTTP 429 and HTTP 5xx. 0 disables; 2 is the maximum.
    http_max_retries: int = 2
    cache_ttl_seconds: int = 1800
    current_evidence_tolerance_seconds: int = 3600
    max_source_age_seconds: int = 86400
    max_download_bytes: int = 20_000_000
    enabled_sources: tuple[str, ...] = tuple(SOURCES)
    vpn_provider_name: Optional[str] = None
    # repr=False keeps secrets out of logs
    vpn_provider_api_key: Optional[str] = field(default=None, repr=False)
    ipinfo_token: Optional[str] = field(default=None, repr=False)
    # SQLite audit history. OFF unless NETCLASS_AUDIT_ENABLED is set (or --audit is
    # passed). Retention is applied only by the explicit purge command, never automatically;
    # 0 means keep records indefinitely.
    audit_enabled: bool = False
    audit_retention_days: int = DEFAULT_RETENTION_DAYS

    @property
    def audit_keeps_forever(self) -> bool:
        return self.audit_retention_days == 0

    @property
    def current_evidence_tolerance(self) -> timedelta:
        return timedelta(seconds=self.current_evidence_tolerance_seconds)

    @property
    def vpn_provider_configured(self) -> bool:
        return bool(self.vpn_provider_name)

    @property
    def ipinfo_enabled(self) -> bool:
        """True when a token is configured (the service may still reject its format)."""
        return bool(self.ipinfo_token)


def _optional_str(env: Mapping[str, str], key: str) -> Optional[str]:
    """Return a stripped string, or None when missing/blank."""
    raw = env.get(key)
    if raw is None or raw.strip() == "":
        return None
    return raw.strip()


def _positive_number(env: Mapping[str, str], key: str, default: float) -> float:
    raw = _optional_str(env, key)
    if raw is None:
        return default
    try:
        value = float(raw)
    except ValueError as exc:
        raise ValueError(f"{key} must be a number, got {raw!r}") from exc
    if value <= 0:
        raise ValueError(f"{key} must be greater than zero, got {raw!r}")
    return value


def _retry_count(env: Mapping[str, str], key: str, default: int) -> int:
    raw = _optional_str(env, key)
    if raw is None:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{key} must be a whole number between 0 and 2, got {raw!r}") from exc
    if not 0 <= value <= 2:
        raise ValueError(f"{key} must be between 0 and 2, got {raw!r}")
    return value


def _source_list(env: Mapping[str, str], key: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = _optional_str(env, key)
    if raw is None:
        return default
    names = tuple(part.strip() for part in raw.split(",") if part.strip())
    unknown = [name for name in names if name not in SOURCES]
    if unknown or not names:
        raise ValueError(
            f"{key} must be a comma-separated list of: {', '.join(SOURCES)} "
            f"(got {raw!r})"
        )
    # Keep registry order and drop duplicates so behaviour never depends on typing order.
    return tuple(name for name in SOURCES if name in names)


def load_settings(env: Optional[Mapping[str, str]] = None) -> Settings:
    """Build Settings from `env`, or from os.environ (after loading .env).

    Passing `env` explicitly skips .env loading, which keeps tests hermetic.
    """
    if env is None:
        from dotenv import load_dotenv  # lazy import: only needed in real runs

        load_dotenv()
        env = os.environ

    defaults = Settings()
    settings = Settings(
        db_path=Path(_optional_str(env, "NETCLASS_DB_PATH") or defaults.db_path),
        cache_dir=Path(_optional_str(env, "NETCLASS_CACHE_DIR") or defaults.cache_dir),
        tor_exit_list_url=_optional_str(env, "NETCLASS_TOR_EXIT_LIST_URL")
        or defaults.tor_exit_list_url,
        ripestat_base_url=_optional_str(env, "NETCLASS_RIPESTAT_BASE_URL")
        or defaults.ripestat_base_url,
        ripestat_sourceapp=_optional_str(env, "NETCLASS_RIPESTAT_SOURCEAPP"),
        ripestat_cache_ttl_seconds=int(
            _positive_number(
                env, "NETCLASS_RIPESTAT_CACHE_TTL_SECONDS", defaults.ripestat_cache_ttl_seconds
            )
        ),
        ipinfo_base_url=_optional_str(env, "NETCLASS_IPINFO_BASE_URL")
        or defaults.ipinfo_base_url,
        ipinfo_cache_ttl_seconds=int(
            _positive_number(
                env, "NETCLASS_IPINFO_CACHE_TTL_SECONDS", defaults.ipinfo_cache_ttl_seconds
            )
        ),
        http_timeout_seconds=_positive_number(
            env, "NETCLASS_HTTP_TIMEOUT_SECONDS", defaults.http_timeout_seconds
        ),
        http_max_retries=_retry_count(env, "NETCLASS_HTTP_MAX_RETRIES", defaults.http_max_retries),
        cache_ttl_seconds=int(
            _positive_number(env, "NETCLASS_CACHE_TTL_SECONDS", defaults.cache_ttl_seconds)
        ),
        current_evidence_tolerance_seconds=int(
            _positive_number(
                env,
                "NETCLASS_CURRENT_EVIDENCE_TOLERANCE_SECONDS",
                defaults.current_evidence_tolerance_seconds,
            )
        ),
        max_source_age_seconds=int(
            _positive_number(
                env, "NETCLASS_MAX_SOURCE_AGE_SECONDS", defaults.max_source_age_seconds
            )
        ),
        max_download_bytes=int(
            _positive_number(env, "NETCLASS_MAX_DOWNLOAD_BYTES", defaults.max_download_bytes)
        ),
        enabled_sources=_source_list(env, "NETCLASS_ENABLED_SOURCES", defaults.enabled_sources),
        vpn_provider_name=_optional_str(env, "NETCLASS_VPN_PROVIDER"),
        vpn_provider_api_key=_optional_str(env, "NETCLASS_VPN_API_KEY"),
        ipinfo_token=_optional_str(env, "IPINFO_TOKEN"),
        audit_enabled=parse_enabled(env.get("NETCLASS_AUDIT_ENABLED"), "NETCLASS_AUDIT_ENABLED"),
        audit_retention_days=parse_retention_days(
            env.get("NETCLASS_AUDIT_RETENTION_DAYS"), "NETCLASS_AUDIT_RETENTION_DAYS"
        ),
    )

    if not settings.ripestat_base_url.lower().startswith("https://"):
        raise ValueError("NETCLASS_RIPESTAT_BASE_URL must use https")
    if not settings.ipinfo_base_url.lower().startswith("https://"):
        raise ValueError("NETCLASS_IPINFO_BASE_URL must use https")
    if settings.ripestat_sourceapp is not None and not re.match(
        r"^[A-Za-z0-9_-]{1,64}$", settings.ripestat_sourceapp
    ):
        raise ValueError(
            "NETCLASS_RIPESTAT_SOURCEAPP may only contain letters, digits, '-' and '_' (max 64)"
        )

    # A cached snapshot older than the tolerance would be rejected as stale by
    # the classifier, so the cache TTL must not exceed the tolerance.
    if settings.cache_ttl_seconds > settings.current_evidence_tolerance_seconds:
        raise ValueError(
            "NETCLASS_CACHE_TTL_SECONDS must not exceed "
            "NETCLASS_CURRENT_EVIDENCE_TOLERANCE_SECONDS"
        )
    return settings
