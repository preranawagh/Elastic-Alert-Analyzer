"""
Time-window alert fetching for the scheduled SOC pipeline.

Uses pipeline state (state.json) to track last_run and a composite
alert cursor (timestamp + _id), queries Elasticsearch for the open
window, paginates with search_after, and deduplicates by alert _id.

Composite cursor prevents skipping / double-processing alerts that
share the same @timestamp.
"""

from __future__ import annotations

import json
import logging
import os
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import NamedTuple

import portalocker

from config import (
    ALERTS_INDEX,
    ALERTS_PAGE_SIZE,
    PIPELINE_INTERVAL_MINUTES,
    PIPELINE_STATE_FILE,
)
from elastic_client import es

logger = logging.getLogger("soc_pipeline")

STATE_LOCK_SUFFIX = ".lock"
STATE_LOCK_TIMEOUT_SEC = 600


class FetchWindow(NamedTuple):
    """Upper-bounded window ending at `end` (UTC)."""

    start: datetime
    end: datetime


class PipelineCursor(NamedTuple):
    """
    Resume position for alert fetching.

    last_run: last successful pipeline completion (UTC).
    last_processed_alert_id / last_processed_timestamp: composite
        cursor on the last successfully processed alert (optional;
        absent on legacy state.json files).
    """

    last_run: datetime | None
    last_processed_alert_id: str | None
    last_processed_timestamp: datetime | None


class FetchResult(NamedTuple):
    hits: list
    window: FetchWindow
    retrieved: int
    duplicates_skipped: int


class StreamStats:
    """Mutable counters updated while streaming alerts."""

    def __init__(self):
        self.retrieved = 0
        self.duplicates_skipped = 0


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def format_iso_z(dt: datetime) -> str:
    """Format datetime as UTC ISO-8601 with second precision (...Z)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def format_iso_z_precise(dt: datetime) -> str:
    """
    Format datetime as UTC ISO-8601 preserving milliseconds.

    Used for last_processed_timestamp so same-second alerts remain
    distinguishable from the composite _id cursor.
    """
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt = dt.astimezone(timezone.utc)
    micros = dt.microsecond
    if micros:
        # Trim to milliseconds (Elastic typically uses ms)
        ms = micros // 1000
        return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms:03d}Z"
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso_z(value: str) -> datetime:
    text = (value or "").strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def state_path(path: str | None = None) -> str:
    return path or PIPELINE_STATE_FILE


def _state_lock_path(file_path: str) -> str:
    return file_path + STATE_LOCK_SUFFIX


@contextmanager
def _with_state_lock(file_path: str):
    """Acquire an exclusive cross-process lock for state.json I/O."""
    lock_path = _state_lock_path(file_path)
    parent = os.path.dirname(os.path.abspath(file_path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    logger.info("State file locked...")
    try:
        with portalocker.Lock(
            lock_path,
            timeout=STATE_LOCK_TIMEOUT_SEC,
        ):
            yield
    finally:
        logger.info("State file released...")


def load_state(path: str | None = None) -> dict | None:
    file_path = state_path(path)
    if not os.path.isfile(file_path):
        return None
    with _with_state_lock(file_path):
        with open(file_path, encoding="utf-8") as fh:
            return json.load(fh)


def parse_cursor(state: dict | None) -> PipelineCursor:
    """
    Build a PipelineCursor from state.json.

    Backward compatible with legacy files that only contain last_run.
    """
    if not state:
        return PipelineCursor(None, None, None)

    last_run = None
    if state.get("last_run"):
        last_run = parse_iso_z(state["last_run"])

    alert_id = state.get("last_processed_alert_id") or None
    if alert_id is not None:
        alert_id = str(alert_id)

    last_ts = None
    if state.get("last_processed_timestamp"):
        last_ts = parse_iso_z(state["last_processed_timestamp"])

    # Require both composite fields; otherwise fall back to last_run only
    if not alert_id or not last_ts:
        alert_id = None
        last_ts = None

    return PipelineCursor(
        last_run=last_run,
        last_processed_alert_id=alert_id,
        last_processed_timestamp=last_ts,
    )


def save_state(
    last_run: datetime,
    path: str | None = None,
    *,
    last_processed_alert_id: str | None = None,
    last_processed_timestamp: datetime | str | None = None,
) -> None:
    """
    Persist pipeline cursor.

    Always writes last_run. Writes composite alert cursor fields when
    both id and timestamp are provided (or preserves them from an
    explicitly passed pair).
    """
    file_path = state_path(path)
    payload = {"last_run": format_iso_z(last_run)}

    ts_value = last_processed_timestamp
    if isinstance(ts_value, datetime):
        ts_value = format_iso_z_precise(ts_value)

    if last_processed_alert_id and ts_value:
        payload["last_processed_alert_id"] = str(
            last_processed_alert_id
        )
        payload["last_processed_timestamp"] = str(ts_value)
    else:
        # Keep nulls explicit for clarity / ops tooling
        payload["last_processed_alert_id"] = None
        payload["last_processed_timestamp"] = None

    with _with_state_lock(file_path):
        with open(file_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=4)
            fh.write("\n")


def compute_window(
    interval_minutes: int | None = None,
    state_file: str | None = None,
    now: datetime | None = None,
) -> tuple[FetchWindow, PipelineCursor]:
    """
    Determine the fetch window and resume cursor for this run.

    Returns (window, cursor).
    """
    end = now or utc_now()
    interval = timedelta(
        minutes=interval_minutes or PIPELINE_INTERVAL_MINUTES
    )
    state = load_state(state_file)
    cursor = parse_cursor(state)

    if cursor.last_processed_timestamp:
        start = cursor.last_processed_timestamp
    elif cursor.last_run:
        start = cursor.last_run
    else:
        start = end - interval

    return FetchWindow(start=start, end=end), cursor


def format_window_log(window: FetchWindow) -> str:
    start = window.start.astimezone(timezone.utc)
    end = window.end.astimezone(timezone.utc)
    if start.date() == end.date():
        return f"{start.strftime('%H:%M:%S')} -> {end.strftime('%H:%M:%S')} UTC"
    fmt = "%Y-%m-%d %H:%M:%S"
    return f"{start.strftime(fmt)} -> {end.strftime(fmt)} UTC"


def hit_timestamp(hit: dict) -> datetime | None:
    """Extract @timestamp from an ES hit as UTC datetime."""
    src = hit.get("_source") or {}
    raw = src.get("@timestamp")
    if not raw:
        return None
    if isinstance(raw, datetime):
        if raw.tzinfo is None:
            return raw.replace(tzinfo=timezone.utc)
        return raw.astimezone(timezone.utc)
    try:
        return parse_iso_z(str(raw))
    except ValueError:
        return None


def _build_alert_query(window: FetchWindow, cursor: PipelineCursor) -> dict:
    """
    Build the ES bool filter for the open time window.

    Composite cursor present:
      @timestamp >= last_processed_timestamp AND @timestamp <= end
      (client then skips ids already processed at that timestamp)

    Legacy last_run only:
      @timestamp > last_run AND @timestamp <= end

    No state:
      @timestamp > window.start AND @timestamp <= end
      (window.start already = now - interval)
    """
    end_iso = format_iso_z(window.end)

    if (
        cursor.last_processed_timestamp
        and cursor.last_processed_alert_id
    ):
        return {
            "bool": {
                "filter": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": format_iso_z_precise(
                                    cursor.last_processed_timestamp
                                ),
                                "lte": end_iso,
                            }
                        }
                    }
                ]
            }
        }

    # Legacy / first-run style exclusive lower bound
    start_iso = format_iso_z(window.start)
    return {
        "bool": {
            "filter": [
                {
                    "range": {
                        "@timestamp": {
                            "gt": start_iso,
                            "lte": end_iso,
                        }
                    }
                }
            ]
        }
    }


def _past_composite_cursor(
    hit: dict,
    cursor: PipelineCursor,
) -> bool:
    """
    Return True once hit is strictly after (timestamp, _id).

    Sort order: @timestamp asc, then _id asc.
    """
    if not (
        cursor.last_processed_timestamp
        and cursor.last_processed_alert_id
    ):
        return True

    hit_ts = hit_timestamp(hit)
    hit_id = hit.get("_id")
    if hit_ts is None or hit_id is None:
        return True

    cursor_ts = cursor.last_processed_timestamp
    cursor_id = cursor.last_processed_alert_id

    if hit_ts > cursor_ts:
        return True
    if hit_ts < cursor_ts:
        return False
    # Same timestamp: only process ids greater than the cursor id
    return str(hit_id) > str(cursor_id)


def iter_alerts_in_window(
    window: FetchWindow,
    cursor: PipelineCursor | None = None,
    stats: StreamStats | None = None,
    page_size: int | None = None,
):
    """
    Yield deduplicated alert hits one at a time (low memory).

    When a composite cursor is present, alerts at the same @timestamp
    as last_processed_timestamp are skipped until _id >
    last_processed_alert_id, then included.
    """
    page_size = page_size or ALERTS_PAGE_SIZE
    stats = stats if stats is not None else StreamStats()
    cursor = cursor or PipelineCursor(None, None, None)
    seen_ids: set[str] = set()
    search_after = None
    query = _build_alert_query(window, cursor)
    sort = [
        {"@timestamp": {"order": "asc"}},
        {"_id": {"order": "asc"}},
    ]

    if (
        cursor.last_processed_timestamp
        and cursor.last_processed_alert_id
    ):
        logger.info(
            "Resume cursor: ts=%s id=%s",
            format_iso_z_precise(cursor.last_processed_timestamp),
            cursor.last_processed_alert_id,
        )
    elif cursor.last_run:
        logger.info(
            "Resume cursor (legacy last_run): %s",
            format_iso_z(cursor.last_run),
        )

    while True:
        kwargs = {
            "index": ALERTS_INDEX,
            "query": query,
            "sort": sort,
            "size": page_size,
        }
        if search_after is not None:
            kwargs["search_after"] = search_after

        response = es.search(**kwargs)
        hits = response.get("hits", {}).get("hits", []) or []
        if not hits:
            break

        for hit in hits:
            alert_id = hit.get("_id")
            if alert_id in seen_ids:
                stats.duplicates_skipped += 1
                continue
            seen_ids.add(alert_id)

            if not _past_composite_cursor(hit, cursor):
                continue

            stats.retrieved += 1
            yield hit

        if len(hits) < page_size:
            break

        search_after = hits[-1].get("sort")
        if not search_after:
            break


def fetch_alerts_in_window(
    window: FetchWindow,
    cursor: PipelineCursor | None = None,
    page_size: int | None = None,
) -> FetchResult:
    """
    Fetch every alert in the window using search_after pagination.
    Deduplicates by Elastic document _id.

    Prefer iter_alerts_in_window() for large volumes to avoid loading
    all hits into memory at once.
    """
    stats = StreamStats()
    hits = list(
        iter_alerts_in_window(
            window,
            cursor=cursor,
            stats=stats,
            page_size=page_size,
        )
    )
    return FetchResult(
        hits=hits,
        window=window,
        retrieved=stats.retrieved,
        duplicates_skipped=stats.duplicates_skipped,
    )
