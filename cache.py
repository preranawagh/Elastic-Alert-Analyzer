import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

load_dotenv()

CACHE_DB_PATH = os.getenv("CACHE_DB_PATH", "cache.db")
CACHE_TTL_HOURS = int(os.getenv("CACHE_TTL_HOURS", "24"))


def _connect(db_path=None):
    path = db_path or CACHE_DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def init_cache(db_path=None):
    """Create the IOC cache table if it does not exist."""
    conn = _connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS ioc_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                provider TEXT NOT NULL,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                response_json TEXT,
                cached_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                UNIQUE(provider, ioc_type, ioc_value)
            )
            """
        )
        conn.commit()
    finally:
        conn.close()


def _utcnow():
    return datetime.now(timezone.utc)


def get_cached(provider, ioc_type, ioc_value, db_path=None):
    """
    Return cached JSON payload if present and not expired.
    Returns None on miss / expiry.
    """
    if not ioc_value:
        return None

    init_cache(db_path)
    conn = _connect(db_path)

    try:
        row = conn.execute(
            """
            SELECT response_json, expires_at
            FROM ioc_cache
            WHERE provider = ?
              AND ioc_type = ?
              AND ioc_value = ?
            """,
            (provider, ioc_type, str(ioc_value).lower()),
        ).fetchone()

        if not row:
            return None

        expires_at = datetime.fromisoformat(row["expires_at"])
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if _utcnow() >= expires_at:
            conn.execute(
                """
                DELETE FROM ioc_cache
                WHERE provider = ?
                  AND ioc_type = ?
                  AND ioc_value = ?
                """,
                (provider, ioc_type, str(ioc_value).lower()),
            )
            conn.commit()
            return None

        if row["response_json"] is None:
            return None

        return json.loads(row["response_json"])
    finally:
        conn.close()


def set_cached(
    provider,
    ioc_type,
    ioc_value,
    response,
    ttl_hours=None,
    db_path=None,
):
    """Store an IOC lookup result in cache.db."""
    if not ioc_value:
        return

    if ttl_hours is None:
        ttl_hours = CACHE_TTL_HOURS

    init_cache(db_path)
    now = _utcnow()
    expires = now + timedelta(hours=ttl_hours)

    payload = (
        json.dumps(response, default=str)
        if response is not None
        else None
    )

    conn = _connect(db_path)
    try:
        conn.execute(
            """
            INSERT INTO ioc_cache (
                provider, ioc_type, ioc_value,
                response_json, cached_at, expires_at
            )
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(provider, ioc_type, ioc_value)
            DO UPDATE SET
                response_json = excluded.response_json,
                cached_at = excluded.cached_at,
                expires_at = excluded.expires_at
            """,
            (
                provider,
                ioc_type,
                str(ioc_value).lower(),
                payload,
                now.isoformat(),
                expires.isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def cached_lookup(
    provider,
    ioc_type,
    ioc_value,
    fetch_fn,
    ttl_hours=None,
    db_path=None,
):
    """
    Cache-aside helper:
      hit  -> return cached result + cache_hit=True
      miss -> call fetch_fn(), store, return + cache_hit=False
    """
    if not ioc_value:
        return None, False

    cached = get_cached(
        provider, ioc_type, ioc_value, db_path=db_path
    )
    if cached is not None:
        return cached, True

    result = fetch_fn()

    # Cache successful lookups and explicit empty results
    # so we do not hammer APIs for known-empty IOCs.
    if result is not None:
        set_cached(
            provider,
            ioc_type,
            ioc_value,
            result,
            ttl_hours=ttl_hours,
            db_path=db_path,
        )

    return result, False
