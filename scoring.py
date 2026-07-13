def _safe_len(items):
    if not items:
        return 0
    if isinstance(items, list) and items and isinstance(
        items[0], dict
    ) and "_error" in items[0]:
        return 0
    return len(items)


def _elastic_severity_points(severity):
    mapping = {
        "low": 10,
        "medium": 25,
        "high": 45,
        "critical": 60,
    }
    if not severity:
        return 5, None
    key = str(severity).lower()
    return mapping.get(key, 10), f"Elastic severity: {severity}"


def _child_is_powershell(children):
    for child in children or []:
        if not isinstance(child, dict):
            continue
        name = (child.get("name") or "").lower()
        cmd = (child.get("command_line") or "").lower()
        if "powershell" in name or "powershell" in cmd:
            return True
    return False


def _has_run_key(registry_events, persistence_registry):
    keywords = [
        "\\run",
        "\\runonce",
        "currentversion\\run",
        "startupapproved",
    ]
    candidates = list(registry_events or []) + list(
        persistence_registry or []
    )
    for item in candidates:
        if not isinstance(item, dict) or item.get("_error"):
            continue
        path = (
            str(item.get("path") or "")
            + str(item.get("key") or "")
        ).lower()
        if any(k in path for k in keywords):
            return True
    return False


def _vt_stats(payload):
    if not isinstance(payload, dict):
        return None
    try:
        return payload["data"]["attributes"]["last_analysis_stats"]
    except Exception:
        return None


def _ti_signals(enrichment):
    reasons = []
    points = 0
    breakdown = {}

    enrichment = enrichment or {}
    vt_hash = enrichment.get("virustotal_hash")
    vt_url = enrichment.get("virustotal_url")
    vt_domain = enrichment.get("virustotal_domain")
    vt_ip = enrichment.get("virustotal_ip")
    vt = enrichment.get("virustotal")

    for label, payload in (
        ("hash", vt_hash),
        ("url", vt_url),
        ("domain", vt_domain),
        ("ip", vt_ip),
        ("combined", vt if not any([vt_hash, vt_url, vt_domain, vt_ip]) else None),
    ):
        stats = _vt_stats(payload)
        if not stats:
            continue
        malicious = stats.get("malicious", 0) or 0
        suspicious = stats.get("suspicious", 0) or 0
        if malicious or suspicious:
            add = min(40, 20 + malicious * 2 + suspicious)
            points += add
            breakdown[f"virustotal_{label}"] = (
                f"{malicious} malicious / {suspicious} suspicious"
            )
            reasons.append(
                f"VirusTotal {label}: {malicious} malicious / "
                f"{suspicious} suspicious"
            )
            break

    abuse = enrichment.get("abuseipdb")
    if isinstance(abuse, dict):
        try:
            score = abuse["data"].get("abuseConfidenceScore", 0) or 0
            if score >= 25:
                points += min(30, int(score / 3))
                breakdown["abuseipdb"] = f"{score}% confidence"
                reasons.append(
                    f"Bad IP on AbuseIPDB ({score}% confidence)"
                )
        except Exception:
            pass

    hybrid = enrichment.get("hybrid_analysis")
    if hybrid:
        points += 20
        breakdown["hybrid_analysis"] = "sample found"
        reasons.append("Hash found on Hybrid Analysis")

    iocs = enrichment.get("iocs") or {}
    if iocs.get("sha256") or iocs.get("sha1") or iocs.get("md5"):
        if not any("VirusTotal" in r or "Hybrid" in r for r in reasons):
            points += 10
            reasons.append("File hash present on alert")

    if iocs.get("lookup_ip"):
        breakdown["lookup_ip"] = iocs.get("lookup_ip")
    elif iocs.get("private_ips"):
        breakdown["private_ips_only"] = True
        reasons.append("Only private/internal IPs present (TI skipped)")

    return points, reasons, breakdown


def _recommendation(score):
    if score >= 80:
        return "High Priority Investigation"
    if score >= 60:
        return "Priority Investigation"
    if score >= 40:
        return "Standard Investigation"
    if score >= 20:
        return "Monitor / Tune Detection"
    return "Informational / Likely Benign"


def _overall_label(score):
    if score >= 80:
        return "CRITICAL"
    if score >= 60:
        return "HIGH"
    if score >= 40:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFORMATIONAL"


def calculate_risk_score(
    alert, enrichment, investigation, history=None
):
    """
    Produce a 0-100 risk score with checklist reasons and
    a priority recommendation.
    """
    inv = investigation or {}
    persistence = inv.get("persistence") or {}
    reasons = []
    score = 0
    breakdown = {}

    severity = (
        alert.get("kibana.alert.severity")
        or alert.get("kibana.alert.rule.severity")
    )
    sev_points, sev_reason = _elastic_severity_points(severity)
    score += sev_points
    breakdown["elastic_severity"] = severity
    if sev_reason:
        reasons.append(sev_reason)

    rule_name = (
        alert.get("kibana.alert.rule.name") or ""
    ).lower()
    if "malware" in rule_name:
        score += 25
        reasons.append("Malware-related detection rule")

    ti_points, ti_reasons, ti_breakdown = _ti_signals(enrichment)
    score += ti_points
    reasons.extend(ti_reasons)
    breakdown.update(ti_breakdown)

    children = inv.get("child_processes") or []
    if _safe_len(children) > 0:
        score += min(15, 5 + _safe_len(children))
        reasons.append(
            f"Child process activity ({_safe_len(children)})"
        )

    if _child_is_powershell(children):
        score += 15
        reasons.append("Child PowerShell")

    process_name = (
        alert.get("process.name")
        or (alert.get("process") or {}).get("name")
        or ""
    ).lower()
    command = (
        alert.get("process.command_line")
        or (alert.get("process") or {}).get("command_line")
        or ""
    ).lower()
    if "powershell" in process_name or "powershell" in command:
        if "Child PowerShell" not in reasons:
            score += 8
            reasons.append("PowerShell execution")

    file_creates = _safe_len(inv.get("file_creations"))
    if file_creates > 0:
        score += min(20, 10 + file_creates)
        reasons.append(f"File dropped ({file_creates})")

    file_mods = _safe_len(inv.get("file_modifications"))
    if file_mods > 0:
        score += min(10, 4 + file_mods)
        reasons.append(f"File modified ({file_mods})")

    registry_events = inv.get("registry_changes") or []
    persistence_registry = persistence.get(
        "registry_persistence"
    ) or []

    if _has_run_key(registry_events, persistence_registry):
        score += 20
        reasons.append("Registry Run Key")
    elif _safe_len(registry_events) > 0:
        score += 10
        reasons.append(
            f"Registry changes ({_safe_len(registry_events)})"
        )

    services = _safe_len(
        inv.get("services") or persistence.get("services")
    )
    tasks = _safe_len(
        inv.get("scheduled_tasks")
        or persistence.get("scheduled_tasks")
    )
    startup = _safe_len(persistence.get("startup_folder"))
    wmi = _safe_len(persistence.get("wmi_persistence"))

    if services or tasks or persistence_registry or startup or wmi:
        score += 15 if "Registry Run Key" not in reasons else 8
        reasons.append("Persistence")
        if startup:
            reasons.append("Startup Folder")
        if wmi:
            reasons.append("WMI Persistence")

    network = _safe_len(inv.get("network_connections"))
    dns = _safe_len(inv.get("dns_events"))
    if network:
        score += min(12, 4 + network)
        reasons.append(f"Network connections ({network})")
        reasons.append("External Connection")
    if dns:
        score += min(8, 3 + dns)
        reasons.append(f"DNS activity ({dns})")

    auth = _safe_len(inv.get("authentication_events"))
    if auth:
        score += min(8, 2 + auth)
        reasons.append(f"Authentication events ({auth})")

    history = history or {}
    by_type = history.get("by_type") or {}
    if by_type.get("hash"):
        score += 15
        reasons.append(
            f"Historical hash match "
            f"({len(by_type['hash'])} prior)"
        )
        breakdown["history_hash_matches"] = len(by_type["hash"])
    if by_type.get("ip"):
        score += 8
        reasons.append(
            f"Historical IP match ({len(by_type['ip'])} prior)"
        )
        breakdown["history_ip_matches"] = len(by_type["ip"])
    if len(by_type.get("user") or []) >= 2:
        score += 5
        reasons.append(
            f"Repeat user in history "
            f"({len(by_type['user'])} prior)"
        )
        breakdown["history_user_matches"] = len(by_type["user"])

    deduped = []
    seen = set()
    for reason in reasons:
        if reason not in seen:
            deduped.append(reason)
            seen.add(reason)

    score = max(0, min(100, int(score)))
    recommendation = _recommendation(score)
    overall = _overall_label(score)

    return {
        "risk_score": score,
        "risk_score_label": f"{score}/100",
        "overall_risk": overall,
        "elastic_severity": severity,
        "breakdown": breakdown,
        "reasons": deduped,
        "recommendation": recommendation,
    }


def print_risk_score(result):
    print("\nSeverity Scoring")
    print("-" * 60)

    print(
        f"Elastic Sev   : {result.get('elastic_severity')}"
    )
    print(
        f"Risk Score    : {result.get('risk_score_label')} "
        f"→ {result.get('overall_risk')}"
    )
    print(f"Recommendation: {result.get('recommendation')}")

    breakdown = result.get("breakdown") or {}
    if breakdown:
        print("\nScore Inputs")
        for key, value in breakdown.items():
            print(f"  - {key}: {value}")

    reasons = result.get("reasons") or []
    print("\nReasons")
    if not reasons:
        print("  (none)")
    else:
        for reason in reasons:
            print(f"  ✔ {reason}")
