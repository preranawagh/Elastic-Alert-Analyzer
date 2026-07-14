"""
Central configuration loaded from environment / .env.

All values are validated at import time with friendly error messages.
"""

from __future__ import annotations

import os
from datetime import date, datetime

from dotenv import load_dotenv

load_dotenv()


class ConfigError(ValueError):
    """Raised when an environment variable has an invalid value."""


def _env_raw(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip()
    if value == "" and default is not None:
        return default
    return value


def _env_str(name: str, default: str | None = None, *, required: bool = False) -> str | None:
    value = _env_raw(name, default)
    if required and (value is None or value == ""):
        raise ConfigError(
            f"{name} is required. Set it in your .env file or environment."
        )
    return value


def _env_bool(name: str, default: bool = False) -> bool:
    raw = _env_raw(name)
    if raw is None or raw == "":
        return default
    lowered = raw.lower()
    if lowered in ("1", "true", "yes", "on"):
        return True
    if lowered in ("0", "false", "no", "off"):
        return False
    raise ConfigError(
        f"{name} must be a boolean "
        f"(true/false/1/0/yes/no), got {raw!r}."
    )


def _env_int(
    name: str,
    default: int | None = None,
    *,
    minimum: int | None = None,
    maximum: int | None = None,
    allow_none: bool = False,
) -> int | None:
    raw = _env_raw(name)
    if raw is None or raw == "":
        if allow_none and default is None:
            return None
        if default is None and not allow_none:
            raise ConfigError(f"{name} is required.")
        value = default
    else:
        if allow_none and raw.lower() in ("none", "null", "unlimited"):
            return None
        try:
            value = int(raw)
        except ValueError as exc:
            raise ConfigError(
                f"{name} must be an integer"
                + (" or None" if allow_none else "")
                + f", got {raw!r}."
            ) from exc

    if value is None:
        return None

    if minimum is not None and value < minimum:
        raise ConfigError(
            f"{name} must be >= {minimum}, got {value}."
        )
    if maximum is not None and value > maximum:
        raise ConfigError(
            f"{name} must be <= {maximum}, got {value}."
        )
    return value


def _env_float(
    name: str,
    default: float,
    *,
    minimum: float | None = None,
    maximum: float | None = None,
) -> float:
    raw = _env_raw(name)
    if raw is None or raw == "":
        value = default
    else:
        try:
            value = float(raw)
        except ValueError as exc:
            raise ConfigError(
                f"{name} must be a number, got {raw!r}."
            ) from exc

    if minimum is not None and value < minimum:
        raise ConfigError(
            f"{name} must be >= {minimum}, got {value}."
        )
    if maximum is not None and value > maximum:
        raise ConfigError(
            f"{name} must be <= {maximum}, got {value}."
        )
    return value


def build_retry_delays(base_delay: float, max_retries: int) -> tuple[float, ...]:
    """
    Build sleep schedule for retry attempts.

    With base_delay=1 and max_retries=3 → (1, 2, 5) matching the
    original backoff. Extra retries (if configured) double the last delay.
    """
    if max_retries <= 0:
        return ()
    multipliers = (1.0, 2.0, 5.0)
    delays: list[float] = []
    for index in range(max_retries):
        if index < len(multipliers):
            delays.append(base_delay * multipliers[index])
        else:
            delays.append(delays[-1] * 2.0)
    return tuple(delays)


# ---------------------------------------------------------------------------
# Elasticsearch
# ---------------------------------------------------------------------------
ELASTIC_URL = _env_str("ELASTIC_URL")
ELASTIC_API_KEY = _env_str("ELASTIC_API_KEY")
ALERTS_INDEX = _env_str(
    "ALERTS_INDEX",
    ".internal.alerts-security.alerts-default-000001",
)
LOGS_INDEX = _env_str("LOGS_INDEX", "logs-*")

# ---------------------------------------------------------------------------
# Investigation
# ---------------------------------------------------------------------------
INVESTIGATION_WINDOW_MINUTES = _env_int(
    "INVESTIGATION_WINDOW_MINUTES", 5, minimum=1, maximum=1440
)
INVESTIGATION_SIZE = _env_int(
    "INVESTIGATION_SIZE", 50, minimum=1, maximum=10000
)

# ---------------------------------------------------------------------------
# LLM
# ---------------------------------------------------------------------------
OPENAI_API_KEY = _env_str("OPENAI_API_KEY")
OPENAI_MODEL = _env_str("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_API_URL = _env_str(
    "OPENAI_API_URL",
    "https://api.openai.com/v1/chat/completions",
)

# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
REPORTS_DIR = _env_str("REPORTS_DIR", "reports")
SAVE_REPORTS = _env_bool("SAVE_REPORTS", True)

# ---------------------------------------------------------------------------
# Cache / history
# ---------------------------------------------------------------------------
CACHE_DB_PATH = _env_str("CACHE_DB_PATH", "cache.db")
CACHE_TTL_HOURS = _env_int(
    "CACHE_TTL_HOURS", 24, minimum=1, maximum=8760
)
HISTORY_LOOKBACK_DAYS = _env_int(
    "HISTORY_LOOKBACK_DAYS", 30, minimum=1, maximum=3650
)

# ---------------------------------------------------------------------------
# Pipeline logging
# ---------------------------------------------------------------------------
PIPELINE_LOGS_DIR = _env_str("PIPELINE_LOGS_DIR", "logs")
# Optional fixed name override; default rotates daily as pipeline_YYYY-MM-DD.log
_PIPELINE_LOG_FILE_RAW = _env_str("PIPELINE_LOG_FILE")
PIPELINE_LOG_FILE = _PIPELINE_LOG_FILE_RAW or None

# ---------------------------------------------------------------------------
# Pipeline fetch / state
# ---------------------------------------------------------------------------
PIPELINE_INTERVAL_MINUTES = _env_int(
    "PIPELINE_INTERVAL_MINUTES", 30, minimum=1, maximum=10080
)
PIPELINE_STATE_FILE = _env_str("PIPELINE_STATE_FILE", "state.json")
ALERTS_PAGE_SIZE = _env_int(
    "ALERTS_PAGE_SIZE", 500, minimum=1, maximum=10000
)

# In-memory batch size for alert processing / report staging
PIPELINE_BATCH_SIZE = _env_int(
    "PIPELINE_BATCH_SIZE", 100, minimum=1, maximum=10000
)

# Retry policy for Elasticsearch and threat-intel HTTP calls
PIPELINE_MAX_RETRIES = _env_int(
    "PIPELINE_MAX_RETRIES", 3, minimum=0, maximum=20
)
PIPELINE_RETRY_DELAY = _env_float(
    "PIPELINE_RETRY_DELAY", 1.0, minimum=0.0, maximum=300.0
)

# Optional hard cap on alerts processed in a single run (None = unlimited)
PIPELINE_MAX_ALERTS_PER_RUN = _env_int(
    "PIPELINE_MAX_ALERTS_PER_RUN",
    None,
    minimum=1,
    maximum=1_000_000,
    allow_none=True,
)

PIPELINE_RETRY_DELAYS = build_retry_delays(
    PIPELINE_RETRY_DELAY, PIPELINE_MAX_RETRIES
)


def pipeline_log_filename(for_date=None):
    """Return daily log basename, e.g. pipeline_2026-07-14.log."""
    if PIPELINE_LOG_FILE:
        return PIPELINE_LOG_FILE
    if for_date is None:
        log_date = os.getenv("PIPELINE_LOG_DATE")
        if log_date:
            return f"pipeline_{log_date}.log"
        for_date = date.today()
    elif isinstance(for_date, datetime):
        for_date = for_date.date()
    return f"pipeline_{for_date.isoformat()}.log"


def pipeline_log_path(for_date=None, logs_dir=None):
    """Absolute path is resolved by callers; returns logs/pipeline_YYYY-MM-DD.log."""
    return os.path.join(
        logs_dir or PIPELINE_LOGS_DIR,
        pipeline_log_filename(for_date),
    )
