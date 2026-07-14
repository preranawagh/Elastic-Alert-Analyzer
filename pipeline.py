"""
Production SOC incident reporting pipeline.

Single entry point for scheduled / automated execution.
Analysis steps are unchanged from the original fetch_alerts flow;
this module adds structured logging and a clean exit code.
"""

from __future__ import annotations

import logging
import os
import sys
import time
import traceback
from datetime import datetime, timezone

from alert_fetch import (
    StreamStats,
    compute_window,
    format_iso_z,
    format_iso_z_precise,
    format_window_log,
    hit_timestamp,
    iter_alerts_in_window,
    save_state,
)
from config import (
    ALERTS_INDEX,
    HISTORY_LOOKBACK_DAYS,
    PIPELINE_BATCH_SIZE,
    PIPELINE_LOGS_DIR,
    PIPELINE_MAX_ALERTS_PER_RUN,
    REPORTS_DIR,
    SAVE_REPORTS,
    pipeline_log_path,
)
from enrichment import enrich_alert
from history import (
    extract_history_fields,
    find_related_alerts,
    record_alert_history,
)
from investigation import investigate_alert
from llm_summary import summarize_alert
from mitre import map_mitre
from report import generate_soc_report
from report_writer import IncrementalReportWriter
from scoring import calculate_risk_score
from timeline import build_timeline
from yara_suggest import suggest_yara_rules

logger = logging.getLogger("soc_pipeline")

# Provider-level TI cache keys (exclude aggregate "virustotal" to avoid double-count)
_TI_CACHE_KEYS = (
    "virustotal_ip",
    "virustotal_hash",
    "virustotal_domain",
    "virustotal_url",
    "abuseipdb",
    "shodan",
    "hybrid_analysis",
)


def setup_logging(logs_dir=None, log_path=None):
    """
    Configure pipeline logging.

    Logs rotate daily as logs/pipeline_YYYY-MM-DD.log.

    - Always log to stdout (captured by run_pipeline.bat into today's log).
    - Also append to the file when not launched with PIPELINE_LOG_CAPTURED=1
      so interactive `python pipeline.py` still persists a log.
    """
    logs_dir = logs_dir or PIPELINE_LOGS_DIR
    os.makedirs(logs_dir, exist_ok=True)
    log_path = os.path.abspath(
        log_path or pipeline_log_path(logs_dir=logs_dir)
    )

    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.propagate = False

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.setLevel(logging.INFO)
    logger.addHandler(console_handler)

    # Avoid double-writing when bat already redirects stdout into the log file
    if os.environ.get("PIPELINE_LOG_CAPTURED") != "1":
        file_handler = logging.FileHandler(log_path, encoding="utf-8")
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)
        logger.addHandler(file_handler)

    return log_path


def format_duration(seconds):
    """Human-readable duration, e.g. 450ms, 12.3s, 2m 05s."""
    if seconds is None:
        return "n/a"
    seconds = float(seconds)
    if seconds < 0:
        seconds = 0.0
    if seconds < 1:
        return f"{int(round(seconds * 1000))}ms"
    if seconds < 60:
        if seconds == int(seconds):
            return f"{int(seconds)}s"
        return f"{seconds:.1f}s"
    minutes = int(seconds // 60)
    secs = int(round(seconds % 60))
    return f"{minutes}m {secs:02d}s"


def ti_cache_counts(enrichment):
    """Count TI provider cache hits / misses from an enrichment payload."""
    cache = (enrichment or {}).get("cache") or {}
    hits = 0
    misses = 0
    for key in _TI_CACHE_KEYS:
        status = cache.get(key)
        if status == "hit":
            hits += 1
        elif status == "miss":
            misses += 1
    return hits, misses


def log_pipeline_summary(
    window,
    retrieved,
    processed,
    failed,
    duration_sec,
    duplicates_skipped=0,
    avg_alert_sec=None,
    ti_cache_hits=0,
    ti_cache_misses=0,
    report_gen_sec=None,
    status_message="Pipeline finished successfully.",
):
    """Emit the human-readable SOC pipeline summary block."""
    logger.info("=" * 28)
    logger.info("SOC PIPELINE")
    logger.info("=" * 28)
    logger.info("Window                         : %s", format_window_log(window))
    logger.info("Retrieved                      : %s", retrieved)
    logger.info("Processed                      : %s", processed)
    logger.info("Failed                         : %s", failed)
    logger.info("Duplicates                     : %s", duplicates_skipped)
    logger.info("Duration                       : %s", format_duration(duration_sec))
    logger.info(
        "Average alert processing time  : %s",
        format_duration(avg_alert_sec),
    )
    logger.info("Threat Intel cache hits        : %s", ti_cache_hits)
    logger.info("Threat Intel cache misses      : %s", ti_cache_misses)
    logger.info(
        "Report generation time         : %s",
        format_duration(report_gen_sec),
    )
    logger.info("")
    logger.info("%s", status_message)


def process_alert(src, index, total=None):
    """
    Run the full analysis chain for one alert.

    Returns (report, metrics) where metrics includes duration and TI
    cache hit/miss counts. Raises on failure so the caller can continue.
    """
    rule = src.get("kibana.alert.rule.name") or "Unknown Rule"
    label = (
        f"[{index}/{total}]"
        if total is not None
        else f"[{index}]"
    )
    alert_started = time.monotonic()
    logger.info("%s Analyzing: %s", label, rule)

    enrichment = enrich_alert(src)
    ti_hits, ti_misses = ti_cache_counts(enrichment)
    logger.info("%s Threat Intelligence completed", label)

    investigation = investigate_alert(src)
    yara = suggest_yara_rules(src, enrichment, investigation)
    history = find_related_alerts(
        src,
        enrichment=enrichment,
        lookback_days=HISTORY_LOOKBACK_DAYS,
    )
    timeline = build_timeline(src, investigation)
    mitre = map_mitre(src, enrichment, investigation)

    risk = calculate_risk_score(
        src,
        enrichment,
        investigation,
        history=history,
        mitre=mitre,
    )
    logger.info(
        "%s Risk scoring completed: %s (%s, conf=%s)",
        label,
        risk.get("risk_score_label"),
        risk.get("overall_risk"),
        risk.get("evidence_confidence"),
    )

    summary = summarize_alert(
        src,
        enrichment,
        investigation,
        risk=risk,
        mitre=mitre,
        timeline=timeline,
        history=history,
        yara=yara,
    )
    report = generate_soc_report(
        src,
        enrichment,
        investigation,
        summary,
        timeline=timeline,
        risk=risk,
        mitre=mitre,
        yara=yara,
        history=history,
    )
    record_alert_history(
        extract_history_fields(
            src, enrichment=enrichment, report=report
        )
    )
    alert_duration = time.monotonic() - alert_started
    logger.info(
        "%s OK — %s (%s)",
        label,
        rule,
        format_duration(alert_duration),
    )
    return report, {
        "duration": alert_duration,
        "ti_hits": ti_hits,
        "ti_misses": ti_misses,
    }


def run_pipeline():
    """
    Execute the end-to-end SOC reporting pipeline.

    Returns an exit code:
      0 = success (reports written or no alerts in window)
      1 = hard failure (fetch/report fatal / all alerts failed)
    """
    started_at = time.monotonic()
    started_iso = datetime.now(timezone.utc).isoformat()
    window, cursor = compute_window()

    logger.info("=" * 72)
    logger.info("Pipeline started — %s", started_iso)
    logger.info(
        "Fetch window: %s (index=%s)",
        format_window_log(window),
        ALERTS_INDEX,
    )

    def emit_summary(
        *,
        retrieved,
        processed,
        failed,
        duplicates=0,
        avg_alert_sec=None,
        ti_hits=0,
        ti_misses=0,
        report_gen_sec=None,
        status_message,
    ):
        log_pipeline_summary(
            window,
            retrieved=retrieved,
            processed=processed,
            failed=failed,
            duration_sec=time.monotonic() - started_at,
            duplicates_skipped=duplicates,
            avg_alert_sec=avg_alert_sec,
            ti_cache_hits=ti_hits,
            ti_cache_misses=ti_misses,
            report_gen_sec=report_gen_sec,
            status_message=status_message,
        )

    try:
        stream_stats = StreamStats()
        alert_iter = iter_alerts_in_window(
            window, cursor=cursor, stats=stream_stats
        )
    except Exception as exc:
        logger.error("Failed to fetch alerts: %s", exc)
        logger.debug(traceback.format_exc())
        emit_summary(
            retrieved=0,
            processed=0,
            failed=0,
            status_message="Pipeline finished — FAILED (fetch).",
        )
        return 1

    logger.info(
        "Processing alerts in batches of %s",
        PIPELINE_BATCH_SIZE,
    )
    if PIPELINE_MAX_ALERTS_PER_RUN is not None:
        logger.info(
            "Per-run alert cap: %s",
            PIPELINE_MAX_ALERTS_PER_RUN,
        )

    writer = IncrementalReportWriter(output_dir=REPORTS_DIR) if SAVE_REPORTS else None
    batch_reports: list = []
    failures = 0
    processed = 0
    index = 0
    last_ok_alert_id = cursor.last_processed_alert_id
    last_ok_alert_ts = cursor.last_processed_timestamp
    cap_hit = False
    alert_time_total = 0.0
    ti_cache_hits = 0
    ti_cache_misses = 0
    report_gen_sec = None

    for alert in alert_iter:
        if (
            PIPELINE_MAX_ALERTS_PER_RUN is not None
            and index >= PIPELINE_MAX_ALERTS_PER_RUN
        ):
            cap_hit = True
            logger.warning(
                "Reached PIPELINE_MAX_ALERTS_PER_RUN=%s — "
                "remaining alerts deferred to the next run "
                "(cursor advanced only for processed alerts).",
                PIPELINE_MAX_ALERTS_PER_RUN,
            )
            break

        index += 1
        src = alert.get("_source") or {}
        rule = src.get("kibana.alert.rule.name") or "Unknown Rule"
        try:
            report, metrics = process_alert(src, index)
            processed += 1
            alert_time_total += metrics["duration"]
            ti_cache_hits += metrics["ti_hits"]
            ti_cache_misses += metrics["ti_misses"]
            last_ok_alert_id = alert.get("_id")
            last_ok_alert_ts = hit_timestamp(alert)
            if writer is not None:
                batch_reports.append(report)
                if len(batch_reports) >= PIPELINE_BATCH_SIZE:
                    writer.add_batch(batch_reports)
                    batch_reports = []
        except Exception as exc:
            failures += 1
            logger.error(
                "[%s] FAIL — %s | Error: %s",
                index,
                rule,
                exc,
            )
            logger.debug(traceback.format_exc())
            continue

    total = stream_stats.retrieved
    if cap_hit:
        total = index
    duplicates_skipped = stream_stats.duplicates_skipped

    logger.info("Alerts fetched: %s", total)
    if duplicates_skipped:
        logger.info(
            "Duplicate alert _id skipped during fetch: %s",
            duplicates_skipped,
        )

    avg_alert_sec = (
        (alert_time_total / processed) if processed else None
    )

    def _persist_cursor():
        save_state(
            window.end,
            last_processed_alert_id=last_ok_alert_id,
            last_processed_timestamp=last_ok_alert_ts,
        )
        if last_ok_alert_id and last_ok_alert_ts:
            logger.info(
                "Cursor saved: last_run=%s last_processed=%s id=%s",
                format_iso_z(window.end),
                format_iso_z_precise(last_ok_alert_ts)
                if isinstance(last_ok_alert_ts, datetime)
                else last_ok_alert_ts,
                last_ok_alert_id,
            )
        else:
            logger.info(
                "Cursor saved: last_run=%s (no alert cursor)",
                format_iso_z(window.end),
            )

    if total == 0:
        _persist_cursor()
        emit_summary(
            retrieved=0,
            processed=0,
            failed=0,
            duplicates=duplicates_skipped,
            status_message="Pipeline finished successfully.",
        )
        return 0

    if batch_reports and writer is not None:
        writer.add_batch(batch_reports)
        batch_reports = []

    if processed == 0:
        emit_summary(
            retrieved=total,
            processed=0,
            failed=failures,
            duplicates=duplicates_skipped,
            ti_hits=ti_cache_hits,
            ti_misses=ti_cache_misses,
            status_message="Pipeline finished — FAILED (no reports).",
        )
        logger.error(
            "No reports generated. All %s alert(s) failed.",
            failures,
        )
        return 1

    if SAVE_REPORTS and writer is not None:
        try:
            logger.info("Report generation starting...")
            report_started = time.monotonic()
            saved_paths = writer.finalize()
            report_gen_sec = time.monotonic() - report_started
            logger.info(
                "Report generation completed (%s)",
                format_duration(report_gen_sec),
            )
            logger.info(
                "Markdown : %s", saved_paths.get("markdown")
            )
            logger.info("JSON     : %s", saved_paths.get("json"))
            logger.info("HTML     : %s", saved_paths.get("html"))
            if saved_paths.get("pdf"):
                logger.info(
                    "PDF      : %s", saved_paths.get("pdf")
                )
            elif saved_paths.get("pdf_error"):
                logger.warning(
                    "PDF      : skipped (%s)",
                    saved_paths.get("pdf_error"),
                )
        except Exception as exc:
            logger.error("Report generation failed: %s", exc)
            logger.debug(traceback.format_exc())
            emit_summary(
                retrieved=total,
                processed=processed,
                failed=failures,
                duplicates=duplicates_skipped,
                avg_alert_sec=avg_alert_sec,
                ti_hits=ti_cache_hits,
                ti_misses=ti_cache_misses,
                report_gen_sec=report_gen_sec,
                status_message="Pipeline finished — FAILED (report).",
            )
            return 1
    else:
        logger.info(
            "Processed %s alerts (SAVE_REPORTS=false, nothing written).",
            processed,
        )

    _persist_cursor()

    emit_summary(
        retrieved=total,
        processed=processed,
        failed=failures,
        duplicates=duplicates_skipped,
        avg_alert_sec=avg_alert_sec,
        ti_hits=ti_cache_hits,
        ti_misses=ti_cache_misses,
        report_gen_sec=report_gen_sec,
        status_message="Pipeline finished successfully.",
    )
    return 0


def main():
    """CLI entry point used by run_pipeline.bat and python -m / pipeline.py."""
    log_path = setup_logging()
    try:
        exit_code = run_pipeline()
    except Exception as exc:
        logger.error("Unhandled pipeline exception: %s", exc)
        logger.error(traceback.format_exc())
        logger.info("Pipeline finished — FAILED (unhandled)")
        exit_code = 1
    logger.info("Log file: %s", os.path.abspath(log_path))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
