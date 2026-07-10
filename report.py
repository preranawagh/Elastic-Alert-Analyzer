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


def save_combined_report(reports, output_dir=None):
    output_dir = output_dir or REPORTS_DIR
    os.makedirs(output_dir, exist_ok=True)

    generated_at = datetime.now(timezone.utc).isoformat()
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    base = f"soc_report_{stamp}"

    md_path = os.path.join(output_dir, f"{base}.md")
    json_path = os.path.join(output_dir, f"{base}.json")

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

    return {
        "markdown": md_path,
        "json": json_path,
    }


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
):
    return build_report(
        alert,
        enrichment,
        investigation,
        summary,
        timeline=timeline,
        risk=risk,
        mitre=mitre,
    )
