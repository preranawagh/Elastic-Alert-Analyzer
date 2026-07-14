"""
Reusable retry helpers for transient Elasticsearch and HTTP failures.
"""

from __future__ import annotations

import logging
import time
from typing import Callable, Optional, TypeVar

import requests
from elasticsearch import ApiError
from elasticsearch.exceptions import (
    ConnectionError as ESConnectionError,
    ConnectionTimeout as ESConnectionTimeout,
)

from config import PIPELINE_MAX_RETRIES, PIPELINE_RETRY_DELAYS

logger = logging.getLogger("soc_pipeline")

RETRY_DELAYS = PIPELINE_RETRY_DELAYS
MAX_RETRIES = PIPELINE_MAX_RETRIES

RETRYABLE_HTTP_STATUS = frozenset({429, 500, 502, 503, 504})
AUTH_HTTP_STATUS = frozenset({401, 403})

T = TypeVar("T")


class TransientHTTPError(Exception):
    """Signals a recoverable HTTP response that should be retried."""

    def __init__(self, status_code: int, service: str):
        self.status_code = status_code
        self.service = service
        super().__init__(f"{service} HTTP {status_code}")


def _http_status_from_es_error(exc: ApiError) -> Optional[int]:
    status = getattr(exc, "status_code", None)
    if status is not None:
        return int(status)
    meta = getattr(exc, "meta", None)
    if meta is not None:
        status = getattr(meta, "status", None)
        if status is not None:
            return int(status)
    return None


def is_retryable_es_error(exc: BaseException) -> bool:
    if isinstance(exc, (ESConnectionError, ESConnectionTimeout)):
        return True
    if isinstance(exc, ApiError):
        status = _http_status_from_es_error(exc)
        return status in RETRYABLE_HTTP_STATUS
    return False


def is_retryable_http_exception(exc: BaseException) -> bool:
    if isinstance(exc, TransientHTTPError):
        return True
    if isinstance(exc, (requests.Timeout, requests.ConnectionError)):
        return True
    if isinstance(exc, requests.HTTPError):
        response = getattr(exc, "response", None)
        if response is not None:
            return response.status_code in RETRYABLE_HTTP_STATUS
    return False


def call_with_retry(
    fn: Callable[[], T],
    service_label: str,
    *,
    is_retryable: Callable[[BaseException], bool],
    show_attempt_counter: bool = False,
) -> T:
    """
    Execute fn with configured backoff retries.

    Delay schedule comes from PIPELINE_RETRY_DELAY / PIPELINE_MAX_RETRIES
    (default base 1s → 1s, 2s, 5s). Re-raises when retries are exhausted.
    """
    last_exc: Optional[BaseException] = None
    max_retries = MAX_RETRIES
    delays = RETRY_DELAYS

    for attempt in range(max_retries + 1):
        try:
            return fn()
        except Exception as exc:
            if not is_retryable(exc):
                raise
            last_exc = exc
            if attempt >= max_retries:
                break

            retry_num = attempt + 1
            if show_attempt_counter:
                logger.warning(
                    "Retrying %s request (Attempt %s/%s)",
                    service_label,
                    retry_num,
                    max_retries,
                )
            else:
                logger.warning(
                    "Retrying %s request...",
                    service_label,
                )
            delay = (
                delays[attempt]
                if attempt < len(delays)
                else (delays[-1] if delays else 0)
            )
            time.sleep(delay)

    assert last_exc is not None
    raise last_exc


def elasticsearch_search(client, **kwargs):
    """Run es.search with retries for transient Elasticsearch failures."""
    return call_with_retry(
        lambda: client.search(**kwargs),
        "Elasticsearch",
        is_retryable=is_retryable_es_error,
        show_attempt_counter=True,
    )


def http_request_with_retry(
    method: str,
    url: str,
    service_name: str,
    **kwargs,
) -> Optional[requests.Response]:
    """
    HTTP request with retries for transient failures.

    Returns the Response on HTTP 200, None for auth errors and other
    non-retryable failures (preserves existing TI lookup behaviour).
    Returns None after retry exhaustion.
    """
    def once() -> Optional[requests.Response]:
        response = requests.request(method, url, timeout=30, **kwargs)
        status = response.status_code

        if status in AUTH_HTTP_STATUS:
            logger.error(
                "%s: unauthorized — not retrying (HTTP %s)",
                service_name,
                status,
            )
            return None

        if status in RETRYABLE_HTTP_STATUS:
            raise TransientHTTPError(status, service_name)

        if status != 200:
            return None

        return response

    try:
        return call_with_retry(
            once,
            service_name,
            is_retryable=is_retryable_http_exception,
            show_attempt_counter=False,
        )
    except Exception as exc:
        logger.error(
            "%s request failed after %s retries: %s",
            service_name,
            MAX_RETRIES,
            exc,
        )
        return None
