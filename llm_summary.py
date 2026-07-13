import json
import os

import requests
from dotenv import load_dotenv

load_dotenv()

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
OPENAI_API_URL = os.getenv(
    "OPENAI_API_URL",
    "https://api.openai.com/v1/chat/completions",
)


def _safe_len(items):
    if not items:
        return 0
    if isinstance(items, list) and items and isinstance(
        items[0], dict
    ) and "_error" in items[0]:
        return 0
    return len(items)


def _trim_list(items, limit=5):
    if not items:
        return []
    if isinstance(items, list) and items and isinstance(
        items[0], dict
    ) and "_error" in items[0]:
        return [{"error": items[0].get("_error")}]
    return items[:limit]


def build_summary_context(
    alert,
    enrichment,
    investigation,
    risk=None,
    mitre=None,
    timeline=None,
    history=None,
    yara=None,
):
    """Compact JSON-friendly context for the LLM / rule engine."""
    iocs = (enrichment or {}).get("iocs") or {}
    vt = (enrichment or {}).get("virustotal")
    abuse = (enrichment or {}).get("abuseipdb")
    shodan = (enrichment or {}).get("shodan")
    hybrid = (enrichment or {}).get("hybrid_analysis")

    ti = {
        "iocs": iocs,
        "virustotal": None,
        "abuseipdb": None,
        "shodan": None,
        "hybrid_analysis": bool(hybrid),
    }

    if vt:
        try:
            ti["virustotal"] = vt["data"]["attributes"][
                "last_analysis_stats"
            ]
        except Exception:
            ti["virustotal"] = "available"

    if abuse:
        try:
            ti["abuseipdb"] = {
                "abuseConfidenceScore": abuse["data"][
                    "abuseConfidenceScore"
                ],
                "countryCode": abuse["data"].get("countryCode"),
                "isp": abuse["data"].get("isp"),
            }
        except Exception:
            ti["abuseipdb"] = "available"

    if shodan:
        ti["shodan"] = {
            "org": shodan.get("org"),
            "os": shodan.get("os"),
            "country_name": shodan.get("country_name"),
            "ports": shodan.get("ports"),
        }

    inv = investigation or {}
    persistence = inv.get("persistence") or {}
    tree = inv.get("process_tree") or {}

    return {
        "alert": {
            "rule": alert.get("kibana.alert.rule.name"),
            "severity": (
                alert.get("kibana.alert.severity")
                or alert.get("kibana.alert.rule.severity")
            ),
            "reason": alert.get("kibana.alert.reason"),
            "timestamp": alert.get("@timestamp"),
            "host": (
                alert.get("host.name")
                or (alert.get("host") or {}).get("name")
            ),
            "user": (
                alert.get("user.name")
                or (alert.get("user") or {}).get("name")
            ),
            "process": (
                alert.get("process.name")
                or (alert.get("process") or {}).get("name")
            ),
            "process_pid": (
                alert.get("process.pid")
                or (alert.get("process") or {}).get("pid")
            ),
            "command_line": (
                alert.get("process.command_line")
                or (alert.get("process") or {}).get("command_line")
            ),
            "file_name": iocs.get("file_name"),
            "file_path": iocs.get("file_path"),
            "sha256": iocs.get("sha256"),
            "sha1": iocs.get("sha1"),
            "md5": iocs.get("md5"),
            "lookup_ip": iocs.get("lookup_ip"),
            "domain": iocs.get("domain"),
            "url": iocs.get("url"),
        },
        "threat_intelligence": ti,
        "risk": {
            **(risk or {}),
            "elastic_severity": (risk or {}).get("elastic_severity"),
            "elastic_detection_severity": (risk or {}).get(
                "elastic_detection_severity"
            ),
            "overall_risk": (risk or {}).get("overall_risk"),
            "analyst_risk_assessment": (risk or {}).get(
                "analyst_risk_assessment"
            ),
            "risk_score_label": (risk or {}).get("risk_score_label"),
            "risk_delta_label": (risk or {}).get("risk_delta_label"),
            "evidence_confidence": (risk or {}).get(
                "evidence_confidence"
            ),
            "alert_context": (risk or {}).get("alert_context"),
            "reason_for_difference": (risk or {}).get(
                "reason_for_difference"
            ),
            "analyst_rationale": (risk or {}).get("analyst_rationale"),
            "divergence_reasons": (risk or {}).get(
                "divergence_reasons"
            ) or [],
            "clean_developer_workflow": (risk or {}).get(
                "clean_developer_workflow"
            ),
            "process_chain": (risk or {}).get("process_chain"),
            "strong_malicious_override": (risk or {}).get(
                "strong_malicious_override"
            ),
        },
        "mitre": mitre or {},
        "timeline_preview": _trim_list(
            (timeline or {}).get("events"), 12
        ),
        "investigation": {
            "window": inv.get("window"),
            "process_tree_display": tree.get("display"),
            "parent_process": inv.get("parent_process"),
            "child_processes": _trim_list(
                inv.get("child_processes")
            ),
            "child_process_count": _safe_len(
                inv.get("child_processes")
            ),
            "file_creations": _trim_list(
                inv.get("file_creations")
            ),
            "file_modifications": _trim_list(
                inv.get("file_modifications")
            ),
            "registry_changes": _trim_list(
                inv.get("registry_changes")
            ),
            "network_connections": _trim_list(
                inv.get("network_connections")
            ),
            "dns_events": _trim_list(inv.get("dns_events")),
            "authentication_events": _trim_list(
                inv.get("authentication_events")
            ),
            "services": _trim_list(inv.get("services")),
            "scheduled_tasks": _trim_list(
                inv.get("scheduled_tasks")
            ),
            "persistence": {
                "registry_count": _safe_len(
                    persistence.get("registry_persistence")
                ),
                "services_count": _safe_len(
                    persistence.get("services")
                ),
                "scheduled_tasks_count": _safe_len(
                    persistence.get("scheduled_tasks")
                ),
                "startup_folder_count": _safe_len(
                    persistence.get("startup_folder")
                ),
                "wmi_count": _safe_len(
                    persistence.get("wmi_persistence")
                ),
            },
            "related_event_count": _safe_len(
                inv.get("related_events")
            ),
        },
        "historical_correlation": {
            "summary": (history or {}).get("summary"),
            "match_count": (history or {}).get("match_count", 0),
            "by_type_counts": {
                "hash": len(
                    ((history or {}).get("by_type") or {}).get(
                        "hash"
                    )
                    or []
                ),
                "ip": len(
                    ((history or {}).get("by_type") or {}).get("ip")
                    or []
                ),
                "user": len(
                    ((history or {}).get("by_type") or {}).get(
                        "user"
                    )
                    or []
                ),
            },
        },
        "yara_suggestions": {
            "applicable": bool((yara or {}).get("applicable")),
            "strength": (yara or {}).get("strength") or "none",
            "reasons": ((yara or {}).get("reasons") or [])[:5],
            "recommendation_count": len(
                (yara or {}).get("recommendations") or []
            ),
            "draft_rule_count": len(
                (yara or {}).get("draft_rules")
                or (yara or {}).get("suggestions")
                or []
            ),
        },
    }


def _dynamic_recommendations(context, disposition):
    inv = context.get("investigation") or {}
    persistence = inv.get("persistence") or {}
    ti = context.get("threat_intelligence") or {}
    alert = context.get("alert") or {}
    actions = []

    parent = (inv.get("parent_process") or {}).get("name")
    process = alert.get("process")

    actions.append(
        f"Validate whether {process} launched by "
        f"{parent or 'unknown parent'} is expected for user "
        f"{alert.get('user')} on host {alert.get('host')}."
    )

    if alert.get("command_line"):
        actions.append(
            "Review the full command line for encoded commands, "
            "download cradles, or unexpected script paths."
        )

    if persistence.get("registry_count"):
        actions.extend([
            "Inspect Registry Run / RunOnce keys for unauthorized entries.",
            "Collect Autoruns output and remove confirmed malicious Run keys.",
        ])
    if persistence.get("scheduled_tasks_count"):
        actions.append(
            "Enumerate scheduled tasks created in the alert window "
            "and remove unauthorized tasks."
        )
    if persistence.get("services_count"):
        actions.append(
            "Review newly created/modified services and disable "
            "unauthorized service binaries."
        )
    if persistence.get("startup_folder_count"):
        actions.append(
            "Check Startup folder drops and remove unauthorized shortcuts/files."
        )
    if persistence.get("wmi_count"):
        actions.append(
            "Inspect WMI permanent event subscriptions "
            "(__EventFilter / CommandLineEventConsumer)."
        )

    if _safe_len(inv.get("network_connections")) or (
        ti.get("iocs") or {}
    ).get("lookup_ip"):
        actions.append(
            "Block confirmed malicious external IPs/domains at the "
            "edge and hunt for additional hosts contacting them."
        )

    if (ti.get("iocs") or {}).get("sha256") or (
        ti.get("iocs") or {}
    ).get("md5"):
        actions.append(
            "Quarantine the hashed file, submit for malware analysis, "
            "and hunt the hash across the environment."
        )

    history = context.get("historical_correlation") or {}
    if history.get("match_count"):
        actions.append(
            "Correlate with prior alerts sharing the same hash, IP, "
            "or user and expand the investigation scope accordingly."
        )

    yara = context.get("yara_suggestions") or {}
    if yara.get("applicable"):
        actions.append(
            "Scan the sample using organization YARA rules, submit "
            "for malware analysis, and hunt the file hash across "
            "the environment."
        )
        if yara.get("draft_rule_count"):
            actions.append(
                "If a draft YARA rule was provided, validate it in a "
                "lab against known-good binaries before deploying."
            )

    if (context.get("risk") or {}).get("clean_developer_workflow"):
        actions = [
            "No escalation required for allowlisted developer workflow "
            "unless new malicious IOC or persistence appears.",
            "If this detection is noisy, tune the Elastic rule or add "
            "an exception for the trusted IDE/toolchain parent with "
            "change control.",
            "Spot-check command lines for encoded PowerShell, download "
            "cradles, or unexpected persistence as a sanity check.",
        ]

    if disposition in ("suspicious", "malicious"):
        actions.extend([
            "Consider host isolation if active compromise is confirmed.",
            "Preserve memory/disk evidence before remediation.",
            "Reset credentials for the involved user if credential "
            "access or persistence is confirmed.",
        ])
    else:
        actions.append(
            "If this matches known developer/admin tooling, tune the "
            "detection rule or add an exception with change control."
        )

    # Deduplicate
    deduped = []
    seen = set()
    for item in actions:
        if item not in seen:
            deduped.append(item)
            seen.add(item)
    return deduped


def rule_based_summary(context):
    """
    Narrative fallback when no LLM key is configured.
    Explicitly explains why our risk differs from Elastic.
    """
    alert = context.get("alert") or {}
    ti = context.get("threat_intelligence") or {}
    inv = context.get("investigation") or {}
    persistence = inv.get("persistence") or {}
    risk = context.get("risk") or {}

    process = alert.get("process") or "unknown process"
    parent = (inv.get("parent_process") or {}).get("name")
    host = alert.get("host") or "unknown host"
    user = alert.get("user") or "unknown user"
    chain = (
        risk.get("process_chain")
        or " → ".join(
            [p for p in [parent, process] if p]
        )
        or process
    )

    findings = []
    risk_level = (risk.get("overall_risk") or "low").lower()
    if risk_level == "informational":
        risk_level = "low"
    disposition = "likely_benign"

    elastic = (
        risk.get("elastic_detection_severity")
        or risk.get("elastic_severity")
        or alert.get("severity")
        or "unknown"
    )
    score_label = risk.get("risk_score_label") or "?"
    confidence = risk.get("evidence_confidence") or "Low"
    rationale = (
        risk.get("reason_for_difference")
        or risk.get("analyst_rationale")
        or ""
    )
    context_name = (risk.get("alert_context") or "unknown").replace(
        "_", " "
    )

    # Lead with Elastic vs our score explanation (required)
    if risk.get("clean_developer_workflow"):
        findings.append(
            f"Developer workflow detected ({chain}). "
            "This activity is consistent with normal software "
            "development and is unlikely to represent malicious behavior."
        )
        disposition = "likely_benign"
        risk_level = "low"
    elif rationale:
        findings.append(rationale)
    else:
        findings.append(
            f"Alert '{alert.get('rule')}' on host {host} under "
            f"user {user} (process chain: {chain})."
        )

    # Only treat persistence / TI as escalation drivers
    if persistence.get("registry_count"):
        findings.append("Registry persistence indicators were observed.")
        disposition = "suspicious"
    if persistence.get("scheduled_tasks_count"):
        findings.append("Scheduled task persistence activity was observed.")
        disposition = "suspicious"
    if persistence.get("wmi_count"):
        findings.append("WMI persistence indicators were observed.")
        disposition = "suspicious"

    vt = ti.get("virustotal")
    if isinstance(vt, dict) and (
        vt.get("malicious", 0) or vt.get("suspicious", 0)
    ):
        findings.append(
            f"VirusTotal flagged an IOC "
            f"({vt.get('malicious')} malicious / "
            f"{vt.get('suspicious')} suspicious)."
        )
        disposition = "suspicious"
        if (vt.get("malicious") or 0) >= 5:
            disposition = "malicious"
            risk_level = "high"

    abuse = ti.get("abuseipdb")
    if isinstance(abuse, dict) and abuse.get(
        "abuseConfidenceScore", 0
    ) >= 75:
        findings.append(
            f"AbuseIPDB confidence "
            f"{abuse.get('abuseConfidenceScore')}%."
        )
        disposition = "suspicious"
        risk_level = "high"

    # Prefer scorer's overall risk when available
    if risk.get("overall_risk"):
        mapped = str(risk.get("overall_risk")).lower()
        if mapped == "informational":
            mapped = "low"
        risk_level = mapped

    if risk.get("strong_malicious_override"):
        if disposition == "likely_benign":
            disposition = "suspicious"

    if risk.get("clean_developer_workflow"):
        disposition = "likely_benign"

    # Build explicit Elastic-vs-ours paragraph
    if rationale:
        narrative = rationale + f" Disposition: {disposition}."
    elif risk.get("clean_developer_workflow"):
        narrative = (
            f"Elastic Detection Severity: {elastic}. "
            f"Analyst Risk Assessment: LOW ({score_label}, "
            f"confidence {confidence}). Developer workflow "
            f"({chain}) with clean TI and no persistence. "
            f"Disposition: likely_benign."
        )
    else:
        narrative = (
            f"Elastic Detection Severity: {elastic}. "
            f"Analyst Risk Assessment: {risk_level.upper()} "
            f"({score_label}, confidence {confidence}, "
            f"context={context_name}). "
            f"Process chain: {chain}. Disposition: {disposition}."
        )

    # Key findings should include divergence bullets
    key_findings = _dedupe_findings(
        findings
        + list((risk.get("divergence_reasons") or [])[:5])
    )

    return {
        "provider": "rule_based",
        "model": None,
        "executive_summary": " ".join(narrative.split()),
        "risk_level": risk_level,
        "disposition": disposition,
        "key_findings": key_findings,
        "recommended_actions": _dynamic_recommendations(
            context, disposition
        ),
        "raw_response": None,
    }


def _dedupe_findings(items):
    out, seen = [], set()
    for item in items:
        if not item:
            continue
        key = str(item).strip()
        if key and key not in seen:
            out.append(key)
            seen.add(key)
    return out


def _call_openai(context):
    if not OPENAI_API_KEY:
        return None

    system_prompt = (
        "You are a senior Tier-2 SOC analyst writing an incident assessment. "
        "Use only the provided alert, threat intelligence, process tree, "
        "timeline, MITRE mapping, risk scoring rationale, and investigation "
        "evidence. "
        "The executive_summary MUST explicitly explain why our risk score "
        "differs from (or aligns with) Elastic severity — never only state "
        "the score. "
        "If risk.clean_developer_workflow is true, say the activity is "
        "consistent with normal software development and unlikely malicious. "
        "If risk.strong_malicious_override is true, cite the independent "
        "evidence (VT, persistence, encoded PowerShell, etc.). "
        "Do NOT treat child processes, file creation counts, or IDE tooling "
        "alone as malicious. "
        "Write 3-6 sentences. Be specific about process lineage. "
        "Recommended actions must be dynamic and tied to the evidence. "
        "Respond ONLY with valid JSON keys: "
        "executive_summary (string), "
        "risk_level (low|medium|high|critical), "
        "disposition (likely_benign|suspicious|malicious|insufficient_data), "
        "key_findings (array of short strings), "
        "recommended_actions (array of specific strings)."
    )

    payload = {
        "model": OPENAI_MODEL,
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": (
                    "Analyze this SOC investigation package:\n"
                    + json.dumps(context, default=str)
                ),
            },
        ],
    }

    headers = {
        "Authorization": f"Bearer {OPENAI_API_KEY}",
        "Content-Type": "application/json",
    }

    response = requests.post(
        OPENAI_API_URL,
        headers=headers,
        json=payload,
        timeout=60,
    )

    if response.status_code != 200:
        return {
            "error": (
                f"LLM API error {response.status_code}: "
                f"{response.text[:300]}"
            )
        }

    body = response.json()
    content = (
        body.get("choices", [{}])[0]
        .get("message", {})
        .get("content", "")
    )

    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        return {
            "error": "LLM returned non-JSON content",
            "raw_response": content,
        }

    return {
        "provider": "openai",
        "model": OPENAI_MODEL,
        "executive_summary": parsed.get("executive_summary"),
        "risk_level": parsed.get("risk_level"),
        "disposition": parsed.get("disposition"),
        "key_findings": parsed.get("key_findings") or [],
        "recommended_actions": (
            parsed.get("recommended_actions") or []
        ),
        "raw_response": content,
    }


def summarize_alert(
    alert,
    enrichment,
    investigation,
    risk=None,
    mitre=None,
    timeline=None,
    history=None,
    yara=None,
):
    """
    Build an analyst summary from alert + TI + investigation.
    Uses OpenAI when OPENAI_API_KEY is set; otherwise narrative
    rule-based fallback with dynamic recommendations.
    """
    context = build_summary_context(
        alert,
        enrichment,
        investigation,
        risk=risk,
        mitre=mitre,
        timeline=timeline,
        history=history,
        yara=yara,
    )

    if OPENAI_API_KEY:
        result = _call_openai(context)
        if result and not result.get("error"):
            result["context"] = context
            return result

        fallback = rule_based_summary(context)
        fallback["llm_error"] = (
            (result or {}).get("error") or "LLM call failed"
        )
        fallback["context"] = context
        return fallback

    result = rule_based_summary(context)
    result["context"] = context
    return result


def print_summary(summary):
    print("\nAnalyst Summary")
    print("-" * 60)

    provider = summary.get("provider")
    model = summary.get("model")
    print(f"Provider      : {provider}" + (
        f" ({model})" if model else ""
    ))

    if summary.get("llm_error"):
        print(f"LLM Note      : {summary['llm_error']}")
        print("               Fell back to rule-based summary.")

    print(f"Risk Level    : {summary.get('risk_level')}")
    print(f"Disposition   : {summary.get('disposition')}")
    print(
        f"Executive     : {summary.get('executive_summary')}"
    )

    findings = summary.get("key_findings") or []
    print("\nKey Findings")
    if not findings:
        print("  No data")
    else:
        for item in findings:
            print(f"  - {item}")

    actions = summary.get("recommended_actions") or []
    print("\nRecommended Actions")
    if not actions:
        print("  No data")
    else:
        for item in actions:
            print(f"  - {item}")
