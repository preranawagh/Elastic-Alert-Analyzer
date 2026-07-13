"""
Historical correlation across previous SOC analyzer runs.

Stores compact alert indicators in SQLite (same DB as IOC cache)
and matches current hash / IP / user against prior alerts.
"""

import os
from datetime import datetime, timedelta, timezone

from dotenv import load_dotenv

load_dotenv()

CACHE_DB_PATH = os.getenv("CACHE_DB_PATH", "cache.db")
HISTORY_LOOKBACK_DAYS = int(os.getenv("HISTORY_LOOKBACK_DAYS", "30"))


def _connect(db_path=None):
    import sqlite3

    path = db_path or CACHE_DB_PATH
    conn = sqlite3.connect(path)
    conn.row_factory = sqlite3.Row
    return conn


def _utcnow():
    return datetime.now(timezone.utc)


def init_history(db_path=None):
    """Create alert_history table if missing."""
    conn = _connect(db_path)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_uuid TEXT,
                rule_name TEXT,
                timestamp TEXT,
                host TEXT,
                user_name TEXT,
                process_name TEXT,
                file_name TEXT,
                file_path TEXT,
                sha256 TEXT,
                sha1 TEXT,
                md5 TEXT,
                lookup_ip TEXT,
                source_ip TEXT,
                destination_ip TEXT,
                risk_score INTEGER,
                overall_risk TEXT,
                disposition TEXT,
                recorded_at TEXT NOT NULL
            )
            """
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hist_sha256 "
            "ON alert_history(sha256)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hist_sha1 "
            "ON alert_history(sha1)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hist_md5 "
            "ON alert_history(md5)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hist_user "
            "ON alert_history(user_name)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hist_ip_lookup "
            "ON alert_history(lookup_ip)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hist_ip_src "
            "ON alert_history(source_ip)"
        )
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_hist_ip_dst "
            "ON alert_history(destination_ip)"
        )
        conn.commit()
    finally:
        conn.close()


def _norm(value):
    if value is None:
        return None
    text = str(value).strip()
    return text.lower() if text else None


def _alert_uuid(alert):
    from ecs_utils import get_field

    return (
        get_field(alert, "kibana.alert.uuid")
        or get_field(alert, "kibana.alert.original_event.id")
        or get_field(alert, "event.id")
    )


def extract_history_fields(alert, enrichment=None, report=None):
    """Build a flat dict suitable for insert / correlation."""
    from ecs_utils import get_field

    enrichment = enrichment or {}
    iocs = enrichment.get("iocs") or {}
    report = report or {}
    alert_block = report.get("alert") or {}
    risk = report.get("risk") or {}
    summary = report.get("summary") or {}

    return {
        "alert_uuid": _alert_uuid(alert) or alert_block.get(
            "alert_uuid"
        ),
        "rule_name": (
            alert_block.get("rule")
            or get_field(alert, "kibana.alert.rule.name")
        ),
        "timestamp": (
            alert_block.get("timestamp")
            or get_field(alert, "@timestamp")
        ),
        "host": (
            alert_block.get("host")
            or get_field(alert, "host.name")
        ),
        "user_name": (
            alert_block.get("user")
            or get_field(alert, "user.name")
        ),
        "process_name": (
            alert_block.get("process")
            or get_field(alert, "process.name")
        ),
        "file_name": (
            alert_block.get("file_name") or iocs.get("file_name")
        ),
        "file_path": (
            alert_block.get("file_path") or iocs.get("file_path")
        ),
        "sha256": _norm(alert_block.get("sha256") or iocs.get("sha256")),
        "sha1": _norm(alert_block.get("sha1") or iocs.get("sha1")),
        "md5": _norm(alert_block.get("md5") or iocs.get("md5")),
        "lookup_ip": _norm(
            alert_block.get("lookup_ip") or iocs.get("lookup_ip")
        ),
        "source_ip": _norm(
            alert_block.get("source_ip") or iocs.get("source_ip")
        ),
        "destination_ip": _norm(
            alert_block.get("destination_ip")
            or iocs.get("destination_ip")
        ),
        "risk_score": risk.get("risk_score"),
        "overall_risk": risk.get("overall_risk"),
        "disposition": summary.get("disposition"),
    }


def record_alert_history(fields, db_path=None):
    """Persist one analyzed alert for future correlation."""
    if not fields:
        return

    init_history(db_path)
    conn = _connect(db_path)
    try:
        uuid = fields.get("alert_uuid")
        if uuid:
            conn.execute(
                "DELETE FROM alert_history WHERE alert_uuid = ?",
                (uuid,),
            )
        conn.execute(
            """
            INSERT INTO alert_history (
                alert_uuid, rule_name, timestamp, host, user_name,
                process_name, file_name, file_path,
                sha256, sha1, md5,
                lookup_ip, source_ip, destination_ip,
                risk_score, overall_risk, disposition, recorded_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                fields.get("alert_uuid"),
                fields.get("rule_name"),
                fields.get("timestamp"),
                fields.get("host"),
                fields.get("user_name"),
                fields.get("process_name"),
                fields.get("file_name"),
                fields.get("file_path"),
                fields.get("sha256"),
                fields.get("sha1"),
                fields.get("md5"),
                fields.get("lookup_ip"),
                fields.get("source_ip"),
                fields.get("destination_ip"),
                fields.get("risk_score"),
                fields.get("overall_risk"),
                fields.get("disposition"),
                _utcnow().isoformat(),
            ),
        )
        conn.commit()
    finally:
        conn.close()


def _row_to_match(row, matched_on):
    return {
        "matched_on": matched_on,
        "alert_uuid": row["alert_uuid"],
        "rule": row["rule_name"],
        "timestamp": row["timestamp"],
        "host": row["host"],
        "user": row["user_name"],
        "process": row["process_name"],
        "file_name": row["file_name"],
        "sha256": row["sha256"],
        "lookup_ip": row["lookup_ip"],
        "source_ip": row["source_ip"],
        "destination_ip": row["destination_ip"],
        "risk_score": row["risk_score"],
        "overall_risk": row["overall_risk"],
        "disposition": row["disposition"],
        "recorded_at": row["recorded_at"],
    }


def find_related_alerts(
    alert,
    enrichment=None,
    exclude_uuid=None,
    lookback_days=None,
    limit=25,
    db_path=None,
):
    """
    Find prior alerts sharing hash, IP, or user.

    Returns a structured correlation summary.
    """
    init_history(db_path)
    fields = extract_history_fields(alert, enrichment)
    exclude_uuid = exclude_uuid or fields.get("alert_uuid")
    lookback_days = (
        HISTORY_LOOKBACK_DAYS
        if lookback_days is None
        else int(lookback_days)
    )
    cutoff = (
        _utcnow() - timedelta(days=lookback_days)
    ).isoformat()

    matches = []
    seen_ids = set()

    queries = []
    if fields.get("sha256"):
        queries.append(
            ("hash:sha256", "sha256 = ?", fields["sha256"])
        )
    if fields.get("sha1"):
        queries.append(("hash:sha1", "sha1 = ?", fields["sha1"]))
    if fields.get("md5"):
        queries.append(("hash:md5", "md5 = ?", fields["md5"]))

    for ip_key, label in (
        ("lookup_ip", "ip:lookup"),
        ("source_ip", "ip:source"),
        ("destination_ip", "ip:destination"),
    ):
        value = fields.get(ip_key)
        if value:
            queries.append(
                (
                    label,
                    "(lookup_ip = ? OR source_ip = ? "
                    "OR destination_ip = ?)",
                    (value, value, value),
                )
            )

    if fields.get("user_name"):
        queries.append(
            (
                "user",
                "LOWER(user_name) = LOWER(?)",
                fields["user_name"],
            )
        )

    conn = _connect(db_path)
    try:
        for matched_on, where_sql, params in queries:
            if not isinstance(params, (list, tuple)):
                params = (params,)

            sql = f"""
                SELECT *
                FROM alert_history
                WHERE {where_sql}
                  AND recorded_at >= ?
            """
            sql_params = list(params) + [cutoff]

            if exclude_uuid:
                sql += (
                    " AND (alert_uuid IS NULL OR alert_uuid != ?)"
                )
                sql_params.append(exclude_uuid)

            sql += " ORDER BY recorded_at DESC LIMIT ?"
            sql_params.append(limit)

            rows = conn.execute(sql, sql_params).fetchall()

            for row in rows:
                key = (row["id"], matched_on.split(":")[0])
                if key in seen_ids:
                    continue
                seen_ids.add(key)
                matches.append(_row_to_match(row, matched_on))
    finally:
        conn.close()

    by_type = {"hash": [], "ip": [], "user": []}
    for match in matches:
        kind = match["matched_on"].split(":")[0]
        if kind in by_type:
            by_type[kind].append(match)

    unique_alerts = {}
    for match in matches:
        uid = match.get("alert_uuid") or (
            f"{match.get('timestamp')}|{match.get('rule')}"
        )
        unique_alerts.setdefault(uid, match)

    summary_bits = []
    if by_type["hash"]:
        summary_bits.append(
            f"{len(by_type['hash'])} prior alert(s) with same hash"
        )
    if by_type["ip"]:
        summary_bits.append(
            f"{len(by_type['ip'])} prior alert(s) with same IP"
        )
    if by_type["user"]:
        summary_bits.append(
            f"{len(by_type['user'])} prior alert(s) for same user"
        )

    return {
        "lookback_days": lookback_days,
        "match_count": len(unique_alerts),
        "match_total_rows": len(matches),
        "summary": (
            "; ".join(summary_bits)
            if summary_bits
            else "No historical matches in lookback window"
        ),
        "by_type": {
            "hash": by_type["hash"][:10],
            "ip": by_type["ip"][:10],
            "user": by_type["user"][:10],
        },
        "matches": list(unique_alerts.values())[:limit],
        "indicators_checked": {
            "sha256": fields.get("sha256"),
            "sha1": fields.get("sha1"),
            "md5": fields.get("md5"),
            "lookup_ip": fields.get("lookup_ip"),
            "source_ip": fields.get("source_ip"),
            "destination_ip": fields.get("destination_ip"),
            "user": fields.get("user_name"),
        },
    }


def correlate_and_record(
    alert,
    enrichment=None,
    report=None,
    lookback_days=None,
    db_path=None,
):
    """
    Correlate against history, then record the current alert.
    Call after the report is built so risk/disposition are stored.
    """
    history = find_related_alerts(
        alert,
        enrichment=enrichment,
        lookback_days=lookback_days,
        db_path=db_path,
    )
    fields = extract_history_fields(
        alert, enrichment=enrichment, report=report
    )
    record_alert_history(fields, db_path=db_path)
    return history
