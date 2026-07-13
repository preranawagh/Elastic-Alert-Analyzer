import html
import json
import os
from datetime import datetime, timezone

from dotenv import load_dotenv
from ecs_utils import get_field, as_text

load_dotenv()

REPORTS_DIR = os.getenv("REPORTS_DIR", "reports")


def _safe_len(items):
    if not items:
        return 0
    if isinstance(items, list) and items and isinstance(
        items[0], dict
    ) and "_error" in items[0]:
        return 0
    return len(items)


def _ti_brief(enrichment):
    enrichment = enrichment or {}
    brief = {
        "iocs": enrichment.get("iocs") or {},
        "virustotal": "No data",
        "virustotal_ip": "No data",
        "virustotal_hash": "No data",
        "virustotal_domain": "No data",
        "virustotal_url": "No data",
        "abuseipdb": "No data",
        "shodan": "No data",
        "hybrid_analysis": "No data",
    }

    def vt_text(payload):
        if not payload:
            return "No data"
        try:
            stats = payload["data"]["attributes"][
                "last_analysis_stats"
            ]
            return (
                f"{stats.get('malicious', 0)} malicious / "
                f"{stats.get('suspicious', 0)} suspicious"
            )
        except Exception:
            return "Data available"

    brief["virustotal"] = vt_text(enrichment.get("virustotal"))
    brief["virustotal_ip"] = vt_text(enrichment.get("virustotal_ip"))
    brief["virustotal_hash"] = vt_text(
        enrichment.get("virustotal_hash")
    )
    brief["virustotal_domain"] = vt_text(
        enrichment.get("virustotal_domain")
    )
    brief["virustotal_url"] = vt_text(
        enrichment.get("virustotal_url")
    )

    abuse = enrichment.get("abuseipdb")
    if abuse:
        try:
            score = abuse["data"]["abuseConfidenceScore"]
            brief["abuseipdb"] = f"{score}% abuse confidence"
        except Exception:
            brief["abuseipdb"] = "Data available"

    shodan = enrichment.get("shodan")
    if shodan:
        brief["shodan"] = {
            "org": shodan.get("org"),
            "os": shodan.get("os"),
            "country": shodan.get("country_name"),
        }

    if enrichment.get("hybrid_analysis"):
        brief["hybrid_analysis"] = "Sample found"

    return brief


def _attack_chain(investigation, timeline):
    """Build a simple ordered attack-chain narrative from tree + timeline."""
    tree = (investigation or {}).get("process_tree") or {}
    display = tree.get("display")
    steps = []

    if display:
        steps.append({
            "stage": "Process Tree",
            "detail": display,
        })

    for event in ((timeline or {}).get("events") or [])[:12]:
        steps.append({
            "stage": f"{event.get('category')}/{event.get('action')}",
            "timestamp": event.get("timestamp"),
            "detail": event.get("detail"),
        })

    return steps


def build_report(
    alert,
    enrichment,
    investigation,
    summary,
    timeline=None,
    risk=None,
    mitre=None,
    yara=None,
    history=None,
):
    """Assemble a structured SOC investigation report."""
    inv = investigation or {}
    persistence = inv.get("persistence") or {}
    iocs = (enrichment or {}).get("iocs") or {}

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "alert": {
            "rule": get_field(alert, "kibana.alert.rule.name"),
            "severity": (
                get_field(alert, "kibana.alert.severity")
                or get_field(alert, "kibana.alert.rule.severity")
            ),
            "reason": get_field(alert, "kibana.alert.reason"),
            "timestamp": get_field(alert, "@timestamp"),
            "host": get_field(alert, "host.name"),
            "user": get_field(alert, "user.name"),
            "process": get_field(alert, "process.name"),
            "process_pid": get_field(alert, "process.pid"),
            "process_entity_id": get_field(
                alert, "process.entity_id"
            ),
            "command_line": get_field(
                alert, "process.command_line"
            ),
            "parent_process": get_field(
                alert, "process.parent.name"
            ),
            "source_ip": iocs.get("source_ip"),
            "destination_ip": iocs.get("destination_ip"),
            "lookup_ip": iocs.get("lookup_ip"),
            "related_ips": iocs.get("related_ips"),
            "domain": iocs.get("domain"),
            "url": iocs.get("url"),
            "file_name": iocs.get("file_name"),
            "file_path": iocs.get("file_path"),
            "sha256": iocs.get("sha256"),
            "sha1": iocs.get("sha1"),
            "md5": iocs.get("md5"),
        },
        "threat_intelligence": _ti_brief(enrichment),
        "cache": (enrichment or {}).get("cache") or {},
        "investigation": {
            "window": inv.get("window"),
            "parent_process": inv.get("parent_process"),
            "child_processes": inv.get("child_processes") or [],
            "process_tree": inv.get("process_tree") or {},
            "file_creations": inv.get("file_creations") or [],
            "file_modifications": (
                inv.get("file_modifications") or []
            ),
            "registry_changes": inv.get("registry_changes") or [],
            "network_connections": (
                inv.get("network_connections") or []
            ),
            "dns_events": inv.get("dns_events") or [],
            "authentication_events": (
                inv.get("authentication_events") or []
            ),
            "user_logons": inv.get("user_logons") or [],
            "services": inv.get("services") or [],
            "scheduled_tasks": inv.get("scheduled_tasks") or [],
            "persistence": persistence,
            "related_events": inv.get("related_events") or [],
            "counts": {
                "child_processes": _safe_len(
                    inv.get("child_processes")
                ),
                "file_creations": _safe_len(
                    inv.get("file_creations")
                ),
                "file_modifications": _safe_len(
                    inv.get("file_modifications")
                ),
                "registry_changes": _safe_len(
                    inv.get("registry_changes")
                ),
                "network_connections": _safe_len(
                    inv.get("network_connections")
                ),
                "dns_events": _safe_len(inv.get("dns_events")),
                "authentication_events": _safe_len(
                    inv.get("authentication_events")
                ),
                "services": _safe_len(inv.get("services")),
                "scheduled_tasks": _safe_len(
                    inv.get("scheduled_tasks")
                ),
                "related_events": _safe_len(
                    inv.get("related_events")
                ),
            },
        },
        "timeline": timeline or {"event_count": 0, "events": []},
        "attack_chain": _attack_chain(inv, timeline),
        "risk": risk or {},
        "mitre": mitre or {},
        "yara_suggestions": yara if yara is not None else {
            "applicable": False,
            "strength": "none",
            "recommendations": [],
            "draft_rules": [],
            "rule_count": 0,
            "suggestions": [],
            "note": "YARA not evaluated",
        },
        "historical_correlation": history or {
            "match_count": 0,
            "summary": "No historical correlation run",
            "matches": [],
        },
        "summary": {
            "provider": (summary or {}).get("provider"),
            "model": (summary or {}).get("model"),
            "risk_level": (summary or {}).get("risk_level"),
            "disposition": (summary or {}).get("disposition"),
            "executive_summary": (summary or {}).get(
                "executive_summary"
            ),
            "key_findings": (summary or {}).get(
                "key_findings"
            ) or [],
            "recommended_actions": (summary or {}).get(
                "recommended_actions"
            ) or [],
        },
    }


def render_alert_section(report, alert_number):
    """Render one alert using the full SOC report template."""
    alert = report.get("alert") or {}
    ti = report.get("threat_intelligence") or {}
    inv = report.get("investigation") or {}
    summary = report.get("summary") or {}
    risk = report.get("risk") or {}
    mitre = report.get("mitre") or {}
    timeline = report.get("timeline") or {}
    attack_chain = report.get("attack_chain") or []
    counts = inv.get("counts") or {}
    window = inv.get("window") or {}
    cache = report.get("cache") or {}
    persistence = inv.get("persistence") or {}
    tree = inv.get("process_tree") or {}

    rule = alert.get("rule") or "Unknown Rule"
    iocs = ti.get("iocs") or {}

    lines = [
        f"# {alert_number}. Alert {alert_number} — {rule}",
        "",
        "## Executive Summary",
        "",
        summary.get("executive_summary") or "No summary available.",
        "",
        f"- **Disposition:** {summary.get('disposition')}",
        f"- **Overall Risk:** {risk.get('overall_risk')} "
        f"({risk.get('risk_score_label')})",
        f"- **Recommendation:** {risk.get('recommendation')}",
        "",
        "## Alert Overview",
        "",
        f"- **Rule:** {rule}",
        f"- **Elastic Severity:** {alert.get('severity')}",
        f"- **Timestamp:** {alert.get('timestamp')}",
        f"- **Host:** {alert.get('host')}",
        f"- **User:** {alert.get('user')}",
        f"- **Process:** {alert.get('process')} "
        f"(pid={alert.get('process_pid')})",
        f"- **Parent:** {alert.get('parent_process')}",
        f"- **Command Line:** `{alert.get('command_line')}`",
        f"- **Elastic Reason:** {alert.get('reason')}",
        "",
        "## Risk Score",
        "",
        f"- **Elastic Severity:** {risk.get('elastic_severity')}",
        f"- **Computed Risk Score:** {risk.get('risk_score_label')}",
        f"- **Overall Risk:** {risk.get('overall_risk')}",
        f"- **Recommendation:** {risk.get('recommendation')}",
        "",
        "### Score Reasons",
        "",
    ]

    for reason in risk.get("reasons") or []:
        lines.append(f"- ✔ {reason}")
    if not risk.get("reasons"):
        lines.append("- (none)")

    lines.extend(["", "## MITRE ATT&CK", ""])
    techniques = mitre.get("techniques") or []
    if techniques:
        for item in techniques:
            lines.append(
                f"- **{item.get('id')}** | {item.get('tactic')} | "
                f"{item.get('name')} — {item.get('evidence')}"
            )
    else:
        lines.append("- No mapped techniques")

    lines.extend(["", "## Attack Chain", ""])
    if tree.get("display"):
        lines.extend([
            "### Process Tree",
            "",
            "```",
            tree.get("display"),
            "```",
            "",
        ])
    if attack_chain:
        for step in attack_chain[:15]:
            ts = step.get("timestamp") or ""
            lines.append(
                f"- {ts} **{step.get('stage')}** — {step.get('detail')}"
            )
    else:
        lines.append("- No attack-chain steps")

    lines.extend([
        "",
        "## Threat Intelligence",
        "",
        f"- **Lookup IP:** {iocs.get('lookup_ip')}",
        f"- **Source IP:** {iocs.get('source_ip')}",
        f"- **Destination IP:** {iocs.get('destination_ip')}",
        f"- **Related IPs:** {iocs.get('related_ips')}",
        f"- **Domain:** {iocs.get('domain')}",
        f"- **URL:** {iocs.get('url')}",
        f"- **VirusTotal (best):** {ti.get('virustotal')} "
        f"[{cache.get('virustotal')}]",
        f"- **VirusTotal IP:** {ti.get('virustotal_ip')} "
        f"[{cache.get('virustotal_ip')}]",
        f"- **VirusTotal Hash:** {ti.get('virustotal_hash')} "
        f"[{cache.get('virustotal_hash')}]",
        f"- **VirusTotal Domain:** {ti.get('virustotal_domain')} "
        f"[{cache.get('virustotal_domain')}]",
        f"- **VirusTotal URL:** {ti.get('virustotal_url')} "
        f"[{cache.get('virustotal_url')}]",
        f"- **AbuseIPDB:** {ti.get('abuseipdb')} "
        f"[{cache.get('abuseipdb')}]",
        f"- **Shodan:** {ti.get('shodan')} [{cache.get('shodan')}]",
        f"- **Hybrid Analysis:** {ti.get('hybrid_analysis')} "
        f"[{cache.get('hybrid_analysis')}]",
        "",
        "## IOC Summary",
        "",
        f"- **File Name:** {alert.get('file_name')}",
        f"- **File Path:** {alert.get('file_path')}",
        f"- **SHA256:** {alert.get('sha256')}",
        f"- **SHA1:** {alert.get('sha1')}",
        f"- **MD5:** {alert.get('md5')}",
        f"- **Public IPs:** {iocs.get('public_ips')}",
        f"- **Private IPs:** {iocs.get('private_ips')}",
        "",
        "## Historical Correlation",
        "",
    ])

    history = report.get("historical_correlation") or {}
    lines.append(f"- **Summary:** {history.get('summary')}")
    lines.append(
        f"- **Lookback:** {history.get('lookback_days')} day(s)"
    )
    lines.append(f"- **Matches:** {history.get('match_count', 0)}")
    for match in (history.get("matches") or [])[:8]:
        lines.append(
            f"- [{match.get('matched_on')}] "
            f"{match.get('timestamp')} | {match.get('rule')} | "
            f"host={match.get('host')} user={match.get('user')} "
            f"risk={match.get('overall_risk')}"
        )
    if not history.get("matches"):
        lines.append("- No prior alerts with same hash/IP/user")

    yara = report.get("yara_suggestions") or {}
    if yara.get("applicable"):
        lines.extend([
            "",
            "## YARA Recommendation",
            "",
            f"- **Why:** {yara.get('note')}",
        ])
        for reason in yara.get("reasons") or []:
            lines.append(f"- **Evidence:** {reason}")
        lines.append("")
        lines.append("### Recommended actions")
        lines.append("")
        for item in yara.get("recommendations") or []:
            lines.append(f"- {item}")
        draft_rules = (
            yara.get("draft_rules") or yara.get("suggestions") or []
        )
        if draft_rules:
            lines.extend([
                "",
                "### Optional draft rule "
                "(validate in lab before use)",
                "",
            ])
            for item in draft_rules:
                lines.append(f"#### {item.get('name')}")
                lines.append("")
                lines.append(f"- {item.get('rationale')}")
                lines.append("")
                lines.append("```yara")
                lines.append((item.get("rule") or "").rstrip())
                lines.append("```")
                lines.append("")

    lines.extend([
        "",
        "## Investigation Findings",
        "",
        f"- **Window:** ±{window.get('minutes')} min "
        f"({window.get('start')} → {window.get('end')})",
        f"- **Index:** {window.get('index')}",
        f"- **Child Processes:** {counts.get('child_processes')}",
        f"- **File Creations:** {counts.get('file_creations')}",
        f"- **File Modifications:** {counts.get('file_modifications')}",
        f"- **Registry Changes:** {counts.get('registry_changes')}",
        f"- **Network Connections:** {counts.get('network_connections')}",
        f"- **DNS Events:** {counts.get('dns_events')}",
        f"- **Auth Events:** {counts.get('authentication_events')}",
        f"- **Services:** {counts.get('services')}",
        f"- **Scheduled Tasks:** {counts.get('scheduled_tasks')}",
        f"- **Persistence Registry:** "
        f"{_safe_len(persistence.get('registry_persistence'))}",
        f"- **Startup Folder:** "
        f"{_safe_len(persistence.get('startup_folder'))}",
        f"- **WMI Persistence:** "
        f"{_safe_len(persistence.get('wmi_persistence'))}",
        "",
        "### Parent / Children",
        "",
        f"```json\n{json.dumps({'parent': inv.get('parent_process'), 'children': (inv.get('child_processes') or [])[:10]}, indent=2, default=str)}\n```",
        "",
        "## Timeline",
        "",
        f"- **Event Count:** {timeline.get('event_count', 0)}",
        "",
    ])

    # Group timeline by category for readability
    events = timeline.get("events") or []
    by_category = {}
    for event in events:
        cat = as_text(event.get("category")) or "other"
        # Use first token for grouping when multi-valued
        cat_key = cat.split()[0] if cat else "other"
        by_category.setdefault(cat_key, []).append(event)

    category_order = [
        "alert", "process", "file", "registry", "network",
        "dns", "authentication", "service", "scheduled_task",
        "persistence", "related",
    ]
    ordered_cats = [
        c for c in category_order if c in by_category
    ] + [
        c for c in by_category if c not in category_order
    ]

    if not events:
        lines.append("- No timeline events")
    else:
        for cat in ordered_cats:
            lines.append(f"### {cat.title()}")
            lines.append("")
            for event in by_category[cat][:10]:
                lines.append(
                    f"- [{event.get('timestamp')}] "
                    f"**{event.get('action')}** — "
                    f"{event.get('detail')}"
                )
            lines.append("")

    lines.extend([
        "## Evidence",
        "",
        f"```json\n{json.dumps({'persistence': persistence, 'network_sample': (inv.get('network_connections') or [])[:5], 'file_sample': (inv.get('file_creations') or [])[:5]}, indent=2, default=str)}\n```",
        "",
        "## Analyst Assessment",
        "",
        f"- **Provider:** {summary.get('provider')}"
        + (f" ({summary.get('model')})" if summary.get("model") else ""),
        f"- **Risk Level:** {summary.get('risk_level')}",
        f"- **Disposition:** {summary.get('disposition')}",
        "",
        "### Key Findings",
        "",
    ])

    findings = summary.get("key_findings") or []
    if findings:
        lines.extend([f"- {item}" for item in findings])
    else:
        lines.append("- No data")

    lines.extend(["", "## Recommended Actions", ""])
    actions = summary.get("recommended_actions") or []
    if actions:
        lines.extend([f"- {item}" for item in actions])
    else:
        lines.append("- No data")

    lines.extend([
        "",
        "## Appendix",
        "",
        f"- Generated at: {report.get('generated_at')}",
        f"- Cache status: `{json.dumps(cache)}`",
        f"- Related event count: {counts.get('related_events')}",
        "",
        "---",
        "",
    ])
    return "\n".join(lines)


def render_combined_markdown(reports, generated_at=None):
    generated_at = generated_at or datetime.now(
        timezone.utc
    ).isoformat()

    lines = [
        "# SOC Investigation Report",
        "",
        f"**Generated:** {generated_at}",
        f"**Alert Count:** {len(reports)}",
        "",
        "---",
        "",
    ]

    for index, report in enumerate(reports, start=1):
        lines.append(render_alert_section(report, index))

    return "\n".join(lines)


# ======================================================
# HTML / PDF export
# ======================================================

def _html_esc(value):
    if value is None:
        return "-"
    if isinstance(value, (list, dict)):
        return html.escape(str(value))
    text = str(value).strip()
    return html.escape(text) if text else "-"


def _severity_class(value):
    text = as_text(value).lower()
    if text in ("critical", "crit"):
        return "sev-critical"
    if text in ("high",):
        return "sev-high"
    if text in ("medium", "med", "moderate"):
        return "sev-medium"
    if text in ("low", "informational", "info"):
        return "sev-low"
    if text in ("suspicious", "malicious"):
        return "sev-high"
    if text in ("likely_benign", "benign"):
        return "sev-low"
    return "sev-unknown"


def _badge(value, kind=None):
    css = kind or _severity_class(value)
    return (
        f'<span class="badge {css}">'
        f"{_html_esc(value)}</span>"
    )


def _kv_table(rows):
    lines = [
        '<table class="kv">',
        "<thead><tr><th>Field</th><th>Value</th></tr></thead>",
        "<tbody>",
    ]
    for key, value in rows:
        lines.append(
            f"<tr><td class='k'>{_html_esc(key)}</td>"
            f"<td class='v'>{value}</td></tr>"
        )
    lines.extend(["</tbody></table>"])
    return "\n".join(lines)


def _data_table(headers, rows):
    head = "".join(f"<th>{_html_esc(h)}</th>" for h in headers)
    body = []
    for row in rows:
        cells = "".join(f"<td>{c}</td>" for c in row)
        body.append(f"<tr>{cells}</tr>")
    if not body:
        body.append(
            f"<tr><td colspan='{len(headers)}'>No data</td></tr>"
        )
    return (
        '<table class="data">'
        f"<thead><tr>{head}</tr></thead>"
        f"<tbody>{''.join(body)}</tbody>"
        "</table>"
    )


def _section(title, body_html, level=2):
    tag = f"h{level}"
    return (
        f'<section class="section">'
        f"<{tag}>{_html_esc(title)}</{tag}>"
        f"{body_html}"
        f"</section>"
    )


def _report_css(for_pdf=False):
    """Browser HTML stylesheet. PDF uses ReportLab (not HTML/CSS)."""
    _ = for_pdf
    return """
:root {
  --bg: #f5f7fb;
  --card: #ffffff;
  --text: #1f2937;
  --muted: #6b7280;
  --border: #e5e7eb;
  --accent: #0f766e;
  --critical: #b91c1c;
  --high: #c2410c;
  --medium: #a16207;
  --low: #15803d;
  --unknown: #4b5563;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  font-family: "Segoe UI", Tahoma, Geneva, Verdana, sans-serif;
  color: var(--text);
  background: var(--bg);
  line-height: 1.45;
  font-size: 13px;
}
.page {
  max-width: 1100px;
  margin: 0 auto;
  padding: 24px 20px 48px;
}
.cover {
  background: linear-gradient(135deg, #0f766e, #115e59 55%, #134e4a);
  color: #fff;
  border-radius: 14px;
  padding: 28px 30px;
  margin-bottom: 22px;
}
.cover h1 {
  margin: 0 0 8px;
  font-size: 28px;
  letter-spacing: 0.2px;
}
.cover .meta { opacity: 0.92; font-size: 13px; }
.alert-card {
  background: var(--card);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 18px 20px 10px;
  margin: 0 0 28px;
  box-shadow: 0 1px 2px rgba(0,0,0,0.04);
  page-break-inside: avoid;
}
.alert-card h1 {
  margin: 0 0 12px;
  font-size: 20px;
  border-bottom: 2px solid var(--accent);
  padding-bottom: 8px;
}
.section {
  margin: 16px 0 18px;
  padding-top: 4px;
  border-top: 1px solid var(--border);
}
.section:first-of-type { border-top: none; }
.section h2 {
  margin: 12px 0 8px;
  font-size: 15px;
  color: #0f172a;
  letter-spacing: 0.3px;
  text-transform: uppercase;
}
.section h3 {
  margin: 10px 0 6px;
  font-size: 13px;
  color: #334155;
}
.badge {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 999px;
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.3px;
  color: #fff;
  vertical-align: middle;
}
.sev-critical { background: var(--critical); }
.sev-high { background: var(--high); }
.sev-medium { background: var(--medium); }
.sev-low { background: var(--low); }
.sev-unknown { background: var(--unknown); }
table {
  width: 100%;
  border-collapse: collapse;
  margin: 6px 0 10px;
  background: #fff;
}
table.kv td, table.kv th,
table.data td, table.data th {
  border: 1px solid var(--border);
  padding: 7px 9px;
  text-align: left;
  vertical-align: top;
}
table th {
  background: #f1f5f9;
  font-size: 12px;
  color: #334155;
}
table.kv td.k {
  width: 28%;
  font-weight: 600;
  background: #f8fafc;
  color: #334155;
}
.pre {
  white-space: pre-wrap;
  font-family: Consolas, "Courier New", monospace;
  background: #0b1220;
  color: #e2e8f0;
  border-radius: 8px;
  padding: 10px 12px;
  font-size: 11px;
  overflow-wrap: anywhere;
}
.summary-box {
  background: #ecfeff;
  border-left: 4px solid var(--accent);
  padding: 10px 12px;
  border-radius: 0 8px 8px 0;
  margin: 6px 0 10px;
}
.muted { color: var(--muted); }
ul.clean { margin: 6px 0 8px 18px; padding: 0; }
ul.clean li { margin: 3px 0; }
@media print {
  body { background: #fff; }
  .page { max-width: none; padding: 0; }
  .alert-card {
    box-shadow: none;
    page-break-after: always;
  }
  .cover { border-radius: 0; }
}
"""


def _render_alert_html(report, alert_number):
    alert = report.get("alert") or {}
    risk = report.get("risk") or {}
    summary = report.get("summary") or {}
    ti = report.get("threat_intelligence") or {}
    iocs = ti.get("iocs") or {}
    inv = report.get("investigation") or {}
    counts = inv.get("counts") or {}
    persistence = inv.get("persistence") or {}
    mitre = report.get("mitre") or {}
    timeline = report.get("timeline") or {}
    tree = (inv.get("process_tree") or {}).get("display")
    yara = report.get("yara_suggestions") or {}
    history = report.get("historical_correlation") or {}

    elastic_sev = risk.get("elastic_severity") or alert.get("severity")
    overall = risk.get("overall_risk") or "UNKNOWN"
    disposition = summary.get("disposition") or "-"

    overview = _kv_table([
        ("Rule", _html_esc(alert.get("rule"))),
        ("Elastic Severity", _badge(elastic_sev)),
        ("Overall Risk", _badge(overall)),
        ("Risk Score", _html_esc(risk.get("risk_score_label"))),
        ("Recommendation", _html_esc(risk.get("recommendation"))),
        ("Disposition", _badge(disposition)),
        ("Timestamp", _html_esc(alert.get("timestamp"))),
        ("Host", _html_esc(alert.get("host"))),
        ("User", _html_esc(alert.get("user"))),
        (
            "Process",
            _html_esc(
                f"{alert.get('process')} "
                f"(pid={alert.get('process_pid')})"
            ),
        ),
        ("Parent", _html_esc(alert.get("parent_process"))),
        (
            "Command Line",
            f"<code>{_html_esc(alert.get('command_line'))}</code>",
        ),
        ("Elastic Reason", _html_esc(alert.get("reason"))),
    ])

    score_reasons = "".join(
        f"<li>{_html_esc(r)}</li>" for r in (risk.get("reasons") or [])
    ) or "<li class='muted'>No reasons</li>"

    mitre_rows = []
    for item in mitre.get("techniques") or []:
        mitre_rows.append([
            _html_esc(item.get("id")),
            _html_esc(item.get("tactic")),
            _html_esc(item.get("name")),
            _html_esc(item.get("evidence")),
        ])
    mitre_table = _data_table(
        ["ID", "Tactic", "Technique", "Evidence"],
        mitre_rows,
    )

    ioc_table = _kv_table([
        (
            "Lookup IP",
            _html_esc(iocs.get("lookup_ip") or alert.get("lookup_ip")),
        ),
        (
            "Source IP",
            _html_esc(iocs.get("source_ip") or alert.get("source_ip")),
        ),
        (
            "Destination IP",
            _html_esc(
                iocs.get("destination_ip") or alert.get("destination_ip")
            ),
        ),
        ("Related IPs", _html_esc(iocs.get("related_ips"))),
        (
            "Domain",
            _html_esc(iocs.get("domain") or alert.get("domain")),
        ),
        ("URL", _html_esc(iocs.get("url") or alert.get("url"))),
        ("File Name", _html_esc(alert.get("file_name"))),
        ("File Path", _html_esc(alert.get("file_path"))),
        ("SHA256", f"<code>{_html_esc(alert.get('sha256'))}</code>"),
        ("SHA1", f"<code>{_html_esc(alert.get('sha1'))}</code>"),
        ("MD5", f"<code>{_html_esc(alert.get('md5'))}</code>"),
        ("Public IPs", _html_esc(iocs.get("public_ips"))),
        ("Private IPs", _html_esc(iocs.get("private_ips"))),
    ])

    ti_table = _kv_table([
        ("VirusTotal (best)", _html_esc(ti.get("virustotal"))),
        ("VirusTotal IP", _html_esc(ti.get("virustotal_ip"))),
        ("VirusTotal Hash", _html_esc(ti.get("virustotal_hash"))),
        ("VirusTotal Domain", _html_esc(ti.get("virustotal_domain"))),
        ("VirusTotal URL", _html_esc(ti.get("virustotal_url"))),
        ("AbuseIPDB", _html_esc(ti.get("abuseipdb"))),
        ("Shodan", _html_esc(ti.get("shodan"))),
        ("Hybrid Analysis", _html_esc(ti.get("hybrid_analysis"))),
    ])

    inv_table = _data_table(
        ["Signal", "Count"],
        [
            ["Child Processes", _html_esc(counts.get("child_processes"))],
            ["File Creations", _html_esc(counts.get("file_creations"))],
            [
                "File Modifications",
                _html_esc(counts.get("file_modifications")),
            ],
            ["Registry Changes", _html_esc(counts.get("registry_changes"))],
            [
                "Network Connections",
                _html_esc(counts.get("network_connections")),
            ],
            ["DNS Events", _html_esc(counts.get("dns_events"))],
            [
                "Auth Events",
                _html_esc(counts.get("authentication_events")),
            ],
            ["Services", _html_esc(counts.get("services"))],
            ["Scheduled Tasks", _html_esc(counts.get("scheduled_tasks"))],
            [
                "Persistence Registry",
                _html_esc(
                    _safe_len(persistence.get("registry_persistence"))
                ),
            ],
            [
                "Startup Folder",
                _html_esc(_safe_len(persistence.get("startup_folder"))),
            ],
            [
                "WMI Persistence",
                _html_esc(_safe_len(persistence.get("wmi_persistence"))),
            ],
        ],
    )

    tree_html = (
        f'<div class="pre">{_html_esc(tree)}</div>'
        if tree else "<p class='muted'>No process tree</p>"
    )

    timeline_rows = []
    for event in (timeline.get("events") or [])[:25]:
        timeline_rows.append([
            _html_esc(event.get("timestamp")),
            _html_esc(event.get("category")),
            _html_esc(event.get("action")),
            _html_esc(event.get("detail")),
        ])
    timeline_table = _data_table(
        ["Timestamp", "Category", "Action", "Detail"],
        timeline_rows,
    )

    history_rows = []
    for match in (history.get("matches") or [])[:12]:
        history_rows.append([
            _html_esc(match.get("matched_on")),
            _html_esc(match.get("timestamp")),
            _html_esc(match.get("rule")),
            _html_esc(match.get("host")),
            _html_esc(match.get("user")),
            _badge(match.get("overall_risk") or "-"),
        ])
    history_html = (
        f"<p>{_html_esc(history.get('summary'))}</p>"
        f"<p class='muted'>Lookback: "
        f"{_html_esc(history.get('lookback_days'))} day(s) · "
        f"Matches: {_html_esc(history.get('match_count', 0))}</p>"
        + _data_table(
            ["Matched On", "Timestamp", "Rule", "Host", "User", "Risk"],
            history_rows,
        )
    )

    yara_parts = []
    if yara.get("applicable"):
        yara_parts.append(f"<p>{_html_esc(yara.get('note'))}</p>")
        reason_items = "".join(
            f"<li>{_html_esc(r)}</li>"
            for r in (yara.get("reasons") or [])
        )
        if reason_items:
            yara_parts.append(
                f"<h3>Evidence</h3><ul class='clean'>{reason_items}</ul>"
            )
        action_items = "".join(
            f"<li>{_html_esc(r)}</li>"
            for r in (yara.get("recommendations") or [])
        )
        yara_parts.append(
            "<h3>Recommended actions</h3>"
            f"<ul class='clean'>{action_items or '<li class=\"muted\">None</li>'}</ul>"
        )
        draft_rules = (
            yara.get("draft_rules") or yara.get("suggestions") or []
        )
        if draft_rules:
            yara_parts.append(
                "<h3>Optional draft rule "
                "(validate in lab before use)</h3>"
            )
            for item in draft_rules:
                yara_parts.append(
                    f"<h4>{_html_esc(item.get('name'))}</h4>"
                )
                yara_parts.append(
                    f"<p class='muted'>"
                    f"{_html_esc(item.get('rationale'))}</p>"
                )
                yara_parts.append(
                    f'<div class="pre">'
                    f'{_html_esc(item.get("rule"))}</div>'
                )
    yara_html = "\n".join(yara_parts)

    findings = "".join(
        f"<li>{_html_esc(item)}</li>"
        for item in (summary.get("key_findings") or [])
    ) or "<li class='muted'>No findings</li>"

    actions = "".join(
        f"<li>{_html_esc(item)}</li>"
        for item in (summary.get("recommended_actions") or [])
    ) or "<li class='muted'>No actions</li>"

    parts = [
        f'<article class="alert-card" id="alert-{alert_number}">',
        f"<h1>{alert_number}. {_html_esc(alert.get('rule') or 'Alert')}</h1>",
        _section(
            "Executive Summary",
            f"<div class='summary-box'>"
            f"{_html_esc(summary.get('executive_summary'))}"
            f"</div>"
            f"<p>Disposition: {_badge(disposition)} &nbsp; "
            f"Risk: {_badge(overall)} "
            f"({_html_esc(risk.get('risk_score_label'))})</p>",
        ),
        _section("Alert Overview", overview),
        _section(
            "Risk Score",
            _kv_table([
                ("Elastic Severity", _badge(elastic_sev)),
                (
                    "Computed Score",
                    _html_esc(risk.get("risk_score_label")),
                ),
                ("Overall Risk", _badge(overall)),
                (
                    "Recommendation",
                    _html_esc(risk.get("recommendation")),
                ),
            ])
            + "<h3>Score Reasons</h3>"
            + f"<ul class='clean'>{score_reasons}</ul>",
        ),
        _section("MITRE ATT&CK", mitre_table),
        _section("Attack Chain / Process Tree", tree_html),
        _section("Threat Intelligence", ti_table),
        _section("IOC Summary", ioc_table),
        _section("Historical Correlation", history_html),
        *(
            [_section("YARA Recommendation", yara_html)]
            if yara.get("applicable") and yara_html
            else []
        ),
        _section("Investigation Findings", inv_table),
        _section(
            "Timeline",
            f"<p class='muted'>Showing up to 25 of "
            f"{_html_esc(timeline.get('event_count', 0))} events</p>"
            + timeline_table,
        ),
        _section(
            "Analyst Assessment",
            f"<p>Provider: <strong>"
            f"{_html_esc(summary.get('provider'))}</strong>"
            + (
                f" ({_html_esc(summary.get('model'))})"
                if summary.get("model")
                else ""
            )
            + "</p>"
            + "<h3>Key Findings</h3>"
            + f"<ul class='clean'>{findings}</ul>",
        ),
        _section(
            "Recommended Actions",
            f"<ul class='clean'>{actions}</ul>",
        ),
        "</article>",
    ]
    return "\n".join(parts)


def render_combined_html(reports, generated_at=None, for_pdf=False):
    generated_at = generated_at or datetime.now(
        timezone.utc
    ).isoformat()

    toc_rows = []
    for index, report in enumerate(reports, start=1):
        alert = report.get("alert") or {}
        risk = report.get("risk") or {}
        toc_rows.append([
            f"<a href='#alert-{index}'>{index}</a>",
            _html_esc(alert.get("rule")),
            _badge(
                risk.get("elastic_severity") or alert.get("severity")
            ),
            _badge(risk.get("overall_risk")),
            _html_esc(risk.get("risk_score_label")),
            _html_esc(alert.get("host")),
        ])

    toc = _data_table(
        ["#", "Rule", "Elastic Sev", "Risk", "Score", "Host"],
        toc_rows,
    )

    alerts_html = "\n".join(
        _render_alert_html(report, index)
        for index, report in enumerate(reports, start=1)
    )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>SOC Investigation Report</title>
  <style>{_report_css(for_pdf=for_pdf)}</style>
</head>
<body>
  <div class="page">
    <header class="cover">
      <h1>SOC Investigation Report</h1>
      <div class="meta">
        Generated: {_html_esc(generated_at)}<br/>
        Alert Count: {len(reports)}
      </div>
    </header>

    <section class="alert-card">
      <h1>Report Index</h1>
      {toc}
    </section>

    {alerts_html}
  </div>
</body>
</html>
"""


def save_html_report(
    reports, output_path, generated_at=None, for_pdf=False
):
    html_content = render_combined_html(
        reports,
        generated_at=generated_at,
        for_pdf=for_pdf,
    )
    with open(output_path, "w", encoding="utf-8") as handle:
        handle.write(html_content)
    return html_content


def save_pdf_report(reports, output_path, generated_at=None):
    """Write PDF via ReportLab. Returns (ok, error)."""
    from pdf_export import build_pdf_report

    return build_pdf_report(
        reports, output_path, generated_at=generated_at
    )


def save_combined_report(reports, output_dir=None):
    """
    Save combined report as Markdown, JSON, HTML, and PDF.
    PDF is built with ReportLab (wrapping, colors, ASCII trees).
    """
    output_dir = output_dir or REPORTS_DIR
    os.makedirs(output_dir, exist_ok=True)

    generated_at = datetime.now(timezone.utc).isoformat()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = f"soc_report_{stamp}"

    md_path = os.path.join(output_dir, f"{base}.md")
    json_path = os.path.join(output_dir, f"{base}.json")
    html_path = os.path.join(output_dir, f"{base}.html")
    pdf_path = os.path.join(output_dir, f"{base}.pdf")

    combined = {
        "generated_at": generated_at,
        "alert_count": len(reports),
        "alerts": [
            {
                "alert_number": index,
                "alert_label": f"Alert {index}",
                **report,
            }
            for index, report in enumerate(reports, start=1)
        ],
    }

    with open(md_path, "w", encoding="utf-8") as handle:
        handle.write(
            render_combined_markdown(
                reports, generated_at=generated_at
            )
        )

    with open(json_path, "w", encoding="utf-8") as handle:
        json.dump(combined, handle, indent=2, default=str)

    save_html_report(
        reports,
        html_path,
        generated_at=generated_at,
        for_pdf=False,
    )

    pdf_ok, pdf_error = save_pdf_report(
        reports, pdf_path, generated_at=generated_at
    )

    result = {
        "markdown": md_path,
        "json": json_path,
        "html": html_path,
    }

    if pdf_ok:
        result["pdf"] = pdf_path
    else:
        result["pdf"] = None
        result["pdf_error"] = pdf_error

    return result


def print_report(report, alert_number=None):
    print("\nSOC Report")
    print("-" * 60)

    if alert_number is not None:
        print(f"Alert         : {alert_number}")

    alert = report.get("alert") or {}
    summary = report.get("summary") or {}
    risk = report.get("risk") or {}
    mitre = report.get("mitre") or {}
    timeline = report.get("timeline") or {}

    print(f"Rule          : {alert.get('rule')}")
    print(f"Host / User   : {alert.get('host')} / {alert.get('user')}")
    print(
        f"Process       : {alert.get('process')} "
        f"(pid={alert.get('process_pid')})"
    )
    print(
        f"Risk Score    : {risk.get('risk_score_label')} "
        f"→ {risk.get('overall_risk')} "
        f"({risk.get('recommendation')})"
    )
    print(
        f"MITRE         : {mitre.get('technique_count', 0)} technique(s)"
    )
    print(
        f"Timeline      : {timeline.get('event_count', 0)} events"
    )
    print(f"Disposition   : {summary.get('disposition')}")
    print(f"Summary       : {summary.get('executive_summary')}")


def generate_soc_report(
    alert,
    enrichment,
    investigation,
    summary,
    timeline=None,
    risk=None,
    mitre=None,
    yara=None,
    history=None,
):
    return build_report(
        alert,
        enrichment,
        investigation,
        summary,
        timeline=timeline,
        risk=risk,
        mitre=mitre,
        yara=yara,
        history=history,
    )
