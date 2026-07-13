"""
SOC-analyst style risk scoring (context engine).

Answers: "Would a Tier-2 analyst escalate this?"
NOT: "How many suspicious-looking events occurred?"

Elastic severity is detection-rule confidence only — one input signal.
Final severity is driven by alert context (developer / admin / attack)
and correlated evidence (TI, persistence, lineage, cmdline).
"""

from ecs_utils import as_text, get_field, is_private_ip


# ------------------------------------------------------------
# Elastic = detection-rule confidence seed (NOT final severity)
# ------------------------------------------------------------

ELASTIC_CONFIDENCE_SEED = {
    "low": 8,
    "medium": 14,
    "high": 20,
    "critical": 28,
}

# Context starting points for analyst assessment
CONTEXT_SEED = {
    "developer_workflow": 20,  # Low
    "administrative": 24,      # Low
    "potential_attack": 42,    # Medium floor; evidence escalates
    "unknown": 26,
}

# Hard caps for clean contexts (no independent malice)
CONTEXT_CLEAN_CAP = {
    "developer_workflow": 35,  # max Low
    "administrative": 35,
    "potential_attack": 100,
    "unknown": 55,
}

ADMIN_PARENTS = {
    "explorer.exe", "explorer",
    "userinit.exe",
    "sihost.exe",
    "taskmgr.exe",
}

ADMIN_TOOLS = {
    "gpupdate.exe", "gpupdate",
    "netsh.exe", "netsh",
    "sc.exe", "sc",
    "net.exe", "net",
    "reg.exe", "reg",
    "mmc.exe",
}

# ------------------------------------------------------------
# Trusted developer allowlist
# ------------------------------------------------------------

TRUSTED_DEVELOPER_PROCESSES = {
    "cursor.exe", "cursor",
    "code.exe", "code",
    "code - insiders.exe", "code - insiders",
    "git.exe", "git",
    "python.exe", "python", "pythonw.exe",
    "node.exe", "node",
    "npm.exe", "npm.cmd", "npm",
    "npx.exe", "npx.cmd", "npx",
    "devenv.exe",
    "msbuild.exe", "msbuild",
    "dotnet.exe", "dotnet",
    "pip.exe", "pip", "pip3.exe",
    "docker.exe", "docker",
    "yarn.exe", "yarn",
    "cargo.exe",
    "go.exe",
    "java.exe", "javaw.exe",
    "idea64.exe", "pycharm64.exe", "webstorm64.exe",
    "studio64.exe",
}

DEV_IDES = {
    "cursor.exe", "cursor",
    "code.exe", "code",
    "code - insiders.exe", "code - insiders",
    "devenv.exe",
    "idea64.exe", "idea.exe",
    "pycharm64.exe", "pycharm.exe",
    "webstorm64.exe",
    "rider64.exe", "clion64.exe", "goland64.exe",
    "studio64.exe",
    "eclipse.exe",
}

COMMON_SHELLS = {
    "cmd.exe", "cmd",
    "powershell.exe", "powershell", "pwsh.exe", "pwsh",
    "conhost.exe", "conhost",
    "windowsterminal.exe", "wt.exe",
    "bash.exe", "wsl.exe",
}

LOLBINS = {
    "rundll32.exe", "rundll32",
    "regsvr32.exe", "regsvr32",
    "mshta.exe", "mshta",
    "certutil.exe", "certutil",
    "bitsadmin.exe", "bitsadmin",
    "wmic.exe", "wmic",
    "cscript.exe", "cscript",
    "wscript.exe", "wscript",
    "msiexec.exe", "msiexec",
    "installutil.exe",
    "cmstp.exe",
}

OFFICE_APPS = {
    "winword.exe", "winword",
    "excel.exe", "excel",
    "powerpnt.exe", "powerpnt",
    "outlook.exe", "outlook",
}

PERSISTENCE_PATHS = (
    "\\currentversion\\run",
    "\\currentversion\\runonce",
    "\\startupapproved\\",
    "\\winlogon\\",
    "image file execution options",
    "\\appinit_dlls",
    "\\currentcontrolset\\services\\",
    "\\control\\session manager\\",
    "userinit",
    "\\windows\\system\\policies",
    "\\windows\\currentversion\\policies",
    "\\shell\\open\\command",
)

BENIGN_REGISTRY_MARKERS = (
    "\\microsoftedge", "\\edge\\", "autolaunch",
    "\\office\\", "\\microsoft\\office",
    "\\mru", "recentdocs", "typedpaths", "userassist",
    "shellbags", "\\bam\\", "\\dam\\", "appcompat",
    "\\explorer\\runmru", "\\internet explorer\\",
    "\\chrome\\", "\\firefox\\", "\\teams\\", "\\onedrive\\",
)

SUSPICIOUS_DROP_DIRS = (
    "\\temp\\", "\\tmp\\",
    "\\downloads\\",
    "\\users\\public\\",
    "\\programdata\\",
    "\\appdata\\local\\temp\\",
    "\\startup\\",
    "\\start menu\\programs\\startup",
    "\\windows\\system32\\",
    "\\windows\\syswow64\\",
)

SCRIPT_EXTS = (
    ".exe", ".dll", ".scr", ".com", ".sys",
    ".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta", ".msi",
)

BENIGN_FILE_EXTS = (
    ".pdf", ".docx", ".doc", ".xlsx", ".pptx", ".txt", ".log",
    ".json", ".db", ".sqlite", ".cache", ".tmp", ".md", ".csv",
    ".png", ".jpg", ".jpeg", ".gif", ".xml", ".yml", ".yaml",
    ".html", ".css", ".map", ".pyc", ".pyo", ".lock",
)

ENCODED_PS = (
    "-encodedcommand", "-enc ", "-enc\"",
    "frombase64string", "iex(", "invoke-expression",
)

DOWNLOAD_PS = (
    "downloadstring", "downloadfile", "invoke-webrequest",
    "iwr ", "wget ", "curl ", "net.webclient", "start-bitstransfer",
)

CRED_DUMP = (
    "mimikatz", "sekurlsa", "lsadump", "procdump",
    "lsass", "comsvcs.dll", "ntdsutil", "secretsdump",
)

RANSOMWARE_MARKERS = (
    "vssadmin delete", "wbadmin delete", "bcdedit",
    ".encrypted", "readme_for_decrypt", "your files are encrypted",
)


def _safe_len(items):
    if not items:
        return 0
    if (
        isinstance(items, list)
        and items
        and isinstance(items[0], dict)
        and "_error" in items[0]
    ):
        return 0
    return len(items)


def _basename(name):
    text = as_text(name).lower().strip()
    # Normalize "Code - Insiders.exe"
    if "\\" in text:
        text = text.rsplit("\\", 1)[-1]
    if "/" in text:
        text = text.rsplit("/", 1)[-1]
    return text


def _dedupe(items):
    out, seen = [], set()
    for item in items:
        if item and item not in seen:
            out.append(item)
            seen.add(item)
    return out


def _elastic_confidence_seed(severity):
    """Elastic severity contributes detection confidence only."""
    if not severity:
        return 10, "unknown"
    key = str(severity).lower().strip()
    return ELASTIC_CONFIDENCE_SEED.get(key, 10), key


def _elastic_baseline(severity):
    """Backward-compatible alias — returns confidence seed."""
    return _elastic_confidence_seed(severity)


def _overall_label(score):
    """Final severity bands per SOC mapping."""
    if score >= 81:
        return "CRITICAL"
    if score >= 61:
        return "HIGH"
    if score >= 36:
        return "MEDIUM"
    if score >= 16:
        return "LOW"
    return "INFORMATIONAL"


def _recommendation(score):
    if score >= 81:
        return "High Priority Investigation"
    if score >= 61:
        return "Priority Investigation"
    if score >= 36:
        return "Standard Investigation"
    if score >= 16:
        return "Monitor / Tune Detection"
    return "Informational / Likely Benign"


def _elastic_label(sev_key, severity):
    return {
        "low": "LOW",
        "medium": "MEDIUM",
        "high": "HIGH",
        "critical": "CRITICAL",
    }.get(sev_key, str(severity or "UNKNOWN").upper())


def _vt_stats(payload):
    if not isinstance(payload, dict):
        return None
    try:
        return payload["data"]["attributes"]["last_analysis_stats"]
    except Exception:
        return None


def _alert_context(alert, investigation):
    inv = investigation or {}
    process = _basename(
        get_field(alert, "process.name")
        or (alert.get("process") or {}).get("name")
    )
    parent = _basename(
        get_field(alert, "process.parent.name")
        or ((alert.get("process") or {}).get("parent") or {}).get("name")
        or ((inv.get("parent_process") or {}).get("name"))
    )
    cmdline = as_text(
        get_field(alert, "process.command_line")
        or (alert.get("process") or {}).get("command_line")
    ).lower()
    rule = as_text(get_field(alert, "kibana.alert.rule.name")).lower()

    children = []
    for child in inv.get("child_processes") or []:
        if isinstance(child, dict) and not child.get("_error"):
            children.append({
                "name": _basename(child.get("name")),
                "command_line": as_text(child.get("command_line")).lower(),
            })

    chain_parts = []
    if parent:
        chain_parts.append(parent)
    if process:
        chain_parts.append(process)
    for child in children[:5]:
        if child["name"] and child["name"] not in chain_parts:
            chain_parts.append(child["name"])

    return {
        "process": process,
        "parent": parent,
        "cmdline": cmdline,
        "rule": rule,
        "children": children,
        "chain": " -> ".join(chain_parts) if chain_parts else "unknown",
    }


def _malicious_cmdline(text):
    text = (text or "").lower()
    return any(
        m in text
        for m in (ENCODED_PS + DOWNLOAD_PS + CRED_DUMP + RANSOMWARE_MARKERS)
    )


def _is_trusted_developer_process(name):
    return _basename(name) in TRUSTED_DEVELOPER_PROCESSES


def _is_developer_workflow(ctx):
    """
    Allowlisted developer activity: IDE / toolchain parentage
    or PowerShell launched by Code/Cursor.
    """
    parent = ctx["parent"]
    process = ctx["process"]
    rule = ctx["rule"]

    if parent in DEV_IDES or process in DEV_IDES:
        return True
    if parent in TRUSTED_DEVELOPER_PROCESSES:
        return True
    if process in TRUSTED_DEVELOPER_PROCESSES and parent in (
        TRUSTED_DEVELOPER_PROCESSES | COMMON_SHELLS | {""}
    ):
        return True
    # powershell launched by Code/Cursor
    if process in {"powershell.exe", "pwsh.exe", "powershell", "pwsh"}:
        if parent in DEV_IDES:
            return True
    if any(
        t in rule
        for t in (
            "vscode", "visual studio code", "cursor",
            "genai", "mcp server", "jetbrains",
        )
    ):
        return True
    return False


# ------------------------------------------------------------
# Independent "strong evidence" that may exceed Elastic
# ------------------------------------------------------------

def _signal_ti(enrichment):
    """
    TI dominates. Returns delta, reasons, strong, clean, breakdown.
    Weights roughly:
      VT malicious >10  +30 (scaled)
      AbuseIPDB >75     +25
      Known malware     +35
      Malicious URL     +35
      Clean IOC         -10 (applied later as dampener credit)
      Private/unknown   0
    """
    enrichment = enrichment or {}
    delta = 0
    reasons = []
    strong = False
    clean = True
    breakdown = {}
    confirmed_malware = False

    best_mal = 0
    best_sus = 0
    saw_vt = False
    vt_url_mal = 0

    for label, key in (
        ("hash", "virustotal_hash"),
        ("url", "virustotal_url"),
        ("domain", "virustotal_domain"),
        ("ip", "virustotal_ip"),
        ("combined", "virustotal"),
    ):
        stats = _vt_stats(enrichment.get(key))
        if not stats:
            continue
        saw_vt = True
        mal = int(stats.get("malicious") or 0)
        sus = int(stats.get("suspicious") or 0)
        if label == "url" and mal > vt_url_mal:
            vt_url_mal = mal
        if mal > best_mal or (mal == best_mal and sus > best_sus):
            best_mal, best_sus = mal, sus
            breakdown[f"virustotal_{label}"] = f"{mal}m/{sus}s"

    if best_mal > 10:
        add = 30 + min(20, best_mal - 10)
        delta += add
        reasons.append(
            f"VirusTotal malicious >10 ({best_mal} detections) (+{add})"
        )
        strong = True
        clean = False
        confirmed_malware = True
    elif best_mal > 5:
        delta += 22
        reasons.append(
            f"VirusTotal malicious >5 ({best_mal} detections) (+22)"
        )
        strong = True
        clean = False
        confirmed_malware = True
    elif best_mal > 0:
        delta += 12
        reasons.append(
            f"VirusTotal malicious detections: {best_mal} (+12)"
        )
        strong = True
        clean = False
    elif best_sus >= 8:
        delta += 6
        reasons.append(f"VirusTotal suspicious: {best_sus} (+6)")
        clean = False
    elif saw_vt:
        reasons.append("VirusTotal clean")

    if vt_url_mal > 5:
        # Known malicious URL weight
        extra = 35 if vt_url_mal >= 10 else 20
        # Avoid double-counting if hash already counted same payload heavily
        if "url" not in str(breakdown.keys()) or best_mal < vt_url_mal:
            delta += max(0, extra - (12 if best_mal > 0 else 0))
            reasons.append(
                f"Known malicious URL (VT {vt_url_mal}) "
                f"(+{extra})"
            )
            strong = True
            clean = False
            confirmed_malware = True

    abuse = enrichment.get("abuseipdb")
    if isinstance(abuse, dict):
        try:
            score = int(abuse["data"].get("abuseConfidenceScore", 0) or 0)
            breakdown["abuseipdb"] = f"{score}%"
            if score > 75:
                delta += 25
                reasons.append(f"AbuseIPDB confidence >75 ({score}%) (+25)")
                strong = True
                clean = False
            elif score >= 50:
                delta += 10
                reasons.append(f"AbuseIPDB elevated ({score}%) (+10)")
                clean = False
            else:
                reasons.append(f"AbuseIPDB not malicious ({score}%)")
        except Exception:
            pass

    hybrid = enrichment.get("hybrid_analysis")
    if hybrid:
        threat = None
        if isinstance(hybrid, dict):
            threat = (
                hybrid.get("threat_score")
                or hybrid.get("av_detect")
                or (hybrid.get("data") or {}).get("threat_score")
            )
        try:
            threat_n = int(threat) if threat is not None else None
        except (TypeError, ValueError):
            threat_n = None
        if threat_n is not None and threat_n >= 50:
            delta += 35
            reasons.append(
                f"Known malware / Hybrid Analysis ({threat_n}) (+35)"
            )
            strong = True
            clean = False
            confirmed_malware = True
            breakdown["hybrid_analysis"] = threat_n
        elif threat_n is not None and threat_n >= 30:
            delta += 12
            reasons.append(f"Hybrid Analysis elevated ({threat_n}) (+12)")
            clean = False
            breakdown["hybrid_analysis"] = threat_n

    # Private IPs / unknown IOCs: 0 (explicit)
    iocs = enrichment.get("iocs") or {}
    if iocs.get("private_ips") and not iocs.get("public_ips"):
        reasons.append("Only private/internal IPs (0 risk from network IOCs)")

    return delta, reasons, strong, clean, confirmed_malware, breakdown


def _signal_lineage(ctx, developer_workflow):
    """Combinations only — never score cmd/ps/python alone."""
    parent = ctx["parent"]
    process = ctx["process"]
    children = {c["name"] for c in ctx["children"]}
    hits = []

    script_hosts = {
        "cmd.exe", "cmd", "powershell.exe", "pwsh.exe", "pwsh",
        "wscript.exe", "cscript.exe", "mshta.exe",
    } | LOLBINS

    if parent in OFFICE_APPS and (
        process in script_hosts or children & script_hosts
    ):
        hits.append("Office spawning PowerShell/script host")

    if parent in {"explorer.exe", "explorer"} and process in LOLBINS:
        hits.append(f"explorer → LOLBin ({process})")

    if parent in {"wscript.exe", "cscript.exe", "mshta.exe"} and process in {
        "cmd.exe", "cmd", "powershell.exe", "pwsh.exe",
    }:
        hits.append(f"{parent} → {process}")

    # LOLBin outside developer allowlist
    if process in LOLBINS and not developer_workflow:
        hits.append(f"LOLBin execution: {process}")

    if not developer_workflow:
        lol_kids = children & LOLBINS
        if lol_kids:
            hits.append(f"Child LOLBin: {', '.join(sorted(lol_kids))}")

    # Trusted shells alone under IDE: 0
    if developer_workflow and not hits:
        return 0, [], False

    if not hits:
        return 0, [], False

    delta = min(35, 20 + 8 * len(hits))
    return delta, [f"Suspicious lineage: {h}" for h in hits], True


def _signal_powershell(ctx):
    texts = [ctx["cmdline"]] + [c["command_line"] for c in ctx["children"]]
    blob = " ".join(texts)
    is_ps = (
        "powershell" in ctx["process"]
        or "pwsh" in ctx["process"]
        or "powershell" in blob
        or any(
            "powershell" in c["name"] or "pwsh" in c["name"]
            for c in ctx["children"]
        )
    )
    if not is_ps:
        return 0, [], False

    encoded = any(m in blob for m in ENCODED_PS)
    download = any(m in blob for m in DOWNLOAD_PS)

    if encoded and download:
        return 40, [
            "Encoded PowerShell + download cradle (+40)"
        ], True
    if encoded:
        return 30, ["PowerShell EncodedCommand / Base64 (+30)"], True
    if download:
        return 28, ["PowerShell download cradle (+28)"], True
    return 0, [], False  # bare PS = 0


def _is_persistence_path(path):
    path = (path or "").lower()
    if not path:
        return False
    if any(b in path for b in BENIGN_REGISTRY_MARKERS):
        return False
    return any(p in path for p in PERSISTENCE_PATHS)


def _signal_persistence(inv):
    persistence = (inv or {}).get("persistence") or {}
    registry_events = (inv or {}).get("registry_changes") or []
    persistence_registry = persistence.get("registry_persistence") or []

    delta = 0
    reasons = []
    strong = False

    for item in list(registry_events) + list(persistence_registry):
        if not isinstance(item, dict) or item.get("_error"):
            continue
        path = (
            as_text(item.get("path")) + " " + as_text(item.get("key"))
        ).lower()
        if _is_persistence_path(path):
            delta += 40
            reasons.append(
                "Confirmed persistence (Run/RunOnce/IFEO/Winlogon/"
                "Services/Policies) (+40)"
            )
            strong = True
            break

    if _safe_len(persistence.get("startup_folder")):
        delta += 25
        reasons.append("Startup folder persistence (+25)")
        strong = True
    if _safe_len(persistence.get("wmi_persistence")):
        delta += 35
        reasons.append("WMI persistence (+35)")
        strong = True
    if _safe_len(persistence.get("scheduled_tasks")):
        delta += 25
        reasons.append("Scheduled task persistence (+25)")
        strong = True
    if _safe_len(persistence.get("services") or inv.get("services")):
        # Only count if also persistence-tagged or ImagePath-like;
        # generic service start/stop is noise — require persistence bucket
        if _safe_len(persistence.get("services")):
            delta += 20
            reasons.append("Service persistence / creation (+20)")
            strong = True

    return delta, reasons, strong


def _executed_names(ctx, inv):
    names = {ctx["process"]}
    for child in ctx["children"]:
        if child["name"]:
            names.add(child["name"])
    for event in (inv or {}).get("process_events") or []:
        if isinstance(event, dict) and event.get("name"):
            names.add(_basename(event.get("name")))
    return {n for n in names if n}


def _signal_file_drops(ctx, inv, ti_strong):
    """Exec/DLL/script in persistence/temp paths + exec or TI only."""
    inv = inv or {}
    executed = _executed_names(ctx, inv)
    drops = []

    for event in inv.get("file_creations") or []:
        if not isinstance(event, dict) or event.get("_error"):
            continue
        path = as_text(event.get("path") or event.get("name")).lower()
        name = _basename(event.get("name") or path)
        if any(path.endswith(ext) or name.endswith(ext)
               for ext in BENIGN_FILE_EXTS):
            continue
        is_script = any(
            path.endswith(ext) or name.endswith(ext)
            for ext in SCRIPT_EXTS
        )
        in_bad = any(d in path for d in SUSPICIOUS_DROP_DIRS)
        if is_script and in_bad:
            drops.append(name or path)

    if not drops:
        return 0, [], False

    executed_drop = any(
        d in executed or any(d and d in e for e in executed)
        for d in drops
    )
    if ti_strong:
        return 25, [
            f"Suspicious executable/script drop + malicious TI "
            f"({len(drops)}) (+25)"
        ], True
    if executed_drop:
        return 25, [
            "Executable/script written to Temp/Startup/System32/"
            "ProgramData and executed (+25)"
        ], True
    return 0, [], False


def _signal_cred_ransomware(ctx):
    blob = ctx["cmdline"] + " " + " ".join(
        c["command_line"] for c in ctx["children"]
    )
    if any(m in blob for m in CRED_DUMP):
        return 45, ["Credential dumping indicators (+45)"], True
    if any(m in blob for m in RANSOMWARE_MARKERS):
        return 45, ["Ransomware indicators (+45)"], True
    return 0, [], False


def _signal_network(enrichment, inv, ti_strong):
    """Private IP = 0. External without malicious TI = 0."""
    enrichment = enrichment or {}
    iocs = enrichment.get("iocs") or {}
    external = False

    lookup = iocs.get("lookup_ip")
    if lookup and not is_private_ip(lookup):
        external = True
    for conn in (inv or {}).get("network_connections") or []:
        if not isinstance(conn, dict) or conn.get("_error"):
            continue
        for key in ("destination_ip", "source_ip"):
            ip = conn.get(key)
            if ip and not is_private_ip(ip):
                external = True
                break

    if not external:
        return 0, [], False, False
    if ti_strong:
        return 10, [
            "External communication corroborates malicious TI (+10)"
        ], False, True
    return 0, [], False, True


def _signal_history(history, ti_strong):
    by_type = (history or {}).get("by_type") or {}
    if by_type.get("hash") and ti_strong:
        return 15, [
            f"Historical malicious hash correlation "
            f"({len(by_type['hash'])}) (+15)"
        ], True
    if by_type.get("hash"):
        return 8, [
            f"Historical hash match ({len(by_type['hash'])}) (+8)"
        ], False
    return 0, [], False


def _has_disqualifying_malice(
    ti_strong, persist_strong, ps_strong, lineage_strong,
    cred_strong, file_strong, external_malicious,
):
    """Any of these voids clean developer/admin classification."""
    return any([
        ti_strong,
        persist_strong,
        ps_strong,
        lineage_strong,
        cred_strong,
        file_strong,
        external_malicious,
    ])


def _is_administrative(ctx):
    parent = ctx["parent"]
    process = ctx["process"]
    if parent in ADMIN_PARENTS and process in (
        COMMON_SHELLS | ADMIN_TOOLS | {
            "powershell.exe", "pwsh.exe", "cmd.exe", "cmd",
        }
    ):
        return True
    if process in ADMIN_TOOLS:
        return True
    return False


def classify_alert_context(
    ctx,
    ti_strong,
    persist_strong,
    ps_strong,
    lineage_strong,
    cred_strong,
    file_strong,
    external_malicious,
    confirmed_malware,
):
    """
    Context engine: classify before assigning severity.
    Returns (context_name, clean_bool).
    """
    malice = _has_disqualifying_malice(
        ti_strong, persist_strong, ps_strong, lineage_strong,
        cred_strong, file_strong, external_malicious,
    )
    attack_shape = (
        confirmed_malware
        or (lineage_strong and (ps_strong or persist_strong or ti_strong))
        or (ps_strong and (persist_strong or ti_strong or file_strong))
        or (persist_strong and ti_strong)
        or (lineage_strong and external_malicious)
        or cred_strong
    )

    if attack_shape:
        return "potential_attack", False

    if _is_developer_workflow(ctx):
        return "developer_workflow", (not malice)

    if _is_administrative(ctx):
        return "administrative", (not malice)

    if malice:
        return "potential_attack", False

    return "unknown", True


def _tier2_would_escalate(
    confirmed_malware, strong_override, strong_count, context
):
    """Would an experienced Tier-2 escalate to High/Critical?"""
    if confirmed_malware:
        return True
    if strong_override and strong_count >= 2:
        return True
    if context == "potential_attack" and strong_override:
        return True
    return False


def _evidence_confidence(
    strong_count,
    ti_strong,
    persist_strong,
    lineage_strong,
    ps_strong,
    external_malicious,
    clean_context,
    mitre_count,
    cred_strong,
):
    if clean_context and strong_count == 0:
        return "High"

    quality = 0
    if ti_strong:
        quality += 2
    if persist_strong:
        quality += 2
    if lineage_strong:
        quality += 1
    if ps_strong:
        quality += 1
    if external_malicious:
        quality += 1
    if cred_strong:
        quality += 2
    if mitre_count >= 3:
        quality += 1
    if strong_count >= 2:
        quality += 1

    if quality >= 4:
        return "High"
    if quality >= 2:
        return "Medium"
    return "Low"


def _build_reason_for_difference(
    elastic_lbl,
    our_label,
    score,
    context,
    clean_context,
    strong_override,
    ctx,
    evidence_bits,
):
    """Single analyst paragraph explaining Elastic vs our assessment."""
    if clean_context and context == "developer_workflow":
        return (
            f"Elastic generated a {elastic_lbl} severity alert because "
            f"the detection rule fired. Our investigation classified "
            f"this as {our_label} (Score: {score}/100) because the "
            f"activity originated from Cursor/IDE developer tooling "
            f"({ctx['chain']}), Threat Intelligence returned clean "
            f"results, no persistence was detected, and all observed "
            f"behavior matches a normal software development workflow."
        )
    if clean_context and context == "administrative":
        return (
            f"Elastic generated a {elastic_lbl} severity alert. Our "
            f"assessment remains {our_label} (Score: {score}/100) "
            f"because this matches routine administrative activity "
            f"({ctx['chain']}) without malicious IOC, persistence, or "
            f"suspicious command lines."
        )
    if strong_override:
        detail = "; ".join(evidence_bits[:4]) if evidence_bits else (
            "independent malicious indicators were corroborated"
        )
        return (
            f"Although Elastic classified the alert as {elastic_lbl}, "
            f"the Analyst Risk Assessment is {our_label} "
            f"(Score: {score}/100) because {detail}."
        )
    if our_label == elastic_lbl:
        return (
            f"Elastic Detection Severity ({elastic_lbl}) and Analyst "
            f"Risk Assessment ({our_label}, Score: {score}/100) align. "
            f"Context={context.replace('_', ' ')}; no material "
            f"independent override applied."
        )
    return (
        f"Elastic Detection Severity is {elastic_lbl}. Analyst Risk "
        f"Assessment is {our_label} (Score: {score}/100) after "
        f"context classification ({context.replace('_', ' ')}) and "
        f"correlation of available evidence."
    )


def calculate_risk_score(
    alert, enrichment, investigation, history=None, mitre=None
):
    """
    Context-first probability-of-malice assessment.

    Elastic severity is a confidence seed only. Final severity is
    driven by context + correlated evidence.
    """
    inv = investigation or {}
    enrichment = enrichment or {}
    ctx = _alert_context(alert, inv)
    mitre_count = len((mitre or {}).get("techniques") or [])

    severity = (
        get_field(alert, "kibana.alert.severity")
        or get_field(alert, "kibana.alert.rule.severity")
        or alert.get("kibana.alert.severity")
        or alert.get("kibana.alert.rule.severity")
    )
    elastic_seed, sev_key = _elastic_confidence_seed(severity)
    elastic_lbl = _elastic_label(sev_key, severity)

    # Correlate signals first
    (
        ti_delta, ti_reasons, ti_strong, ti_clean,
        confirmed_malware, ti_bd,
    ) = _signal_ti(enrichment)

    developer = _is_developer_workflow(ctx)
    lin_delta, lin_reasons, lineage_strong = _signal_lineage(
        ctx, developer
    )
    ps_delta, ps_reasons, ps_strong = _signal_powershell(ctx)
    persist_delta, persist_reasons, persist_strong = (
        _signal_persistence(inv)
    )
    cred_delta, cred_reasons, cred_strong = _signal_cred_ransomware(ctx)
    net_delta, net_reasons, _, external = _signal_network(
        enrichment, inv, ti_strong
    )
    external_malicious = bool(external and ti_strong)
    file_delta, file_reasons, file_strong = _signal_file_drops(
        ctx, inv, ti_strong
    )
    hist_delta, hist_reasons, hist_strong = _signal_history(
        history, ti_strong
    )

    context, clean_context = classify_alert_context(
        ctx,
        ti_strong,
        persist_strong,
        ps_strong,
        lineage_strong,
        cred_strong,
        file_strong,
        external_malicious,
        confirmed_malware,
    )

    context_seed = CONTEXT_SEED[context]
    score = float(context_seed + elastic_seed)
    modifiers = [
        {
            "delta": context_seed,
            "reason": (
                f"Context seed: {context.replace('_', ' ')} "
                f"→ {context_seed}"
            ),
            "type": "baseline",
        },
        {
            "delta": elastic_seed,
            "reason": (
                f"Elastic detection confidence seed "
                f"({severity or 'unknown'} → +{elastic_seed})"
            ),
            "type": "baseline",
        },
    ]
    narrative = [
        f"Alert context classified as: {context.replace('_', ' ')}"
    ]
    narrative.extend(ti_reasons)
    breakdown = {
        "elastic_detection_severity": severity,
        "elastic_confidence_seed": elastic_seed,
        "alert_context": context,
        "clean_context": clean_context,
    }
    breakdown.update(ti_bd)

    positive_delta = 0
    strong_count = 0
    evidence_bits = []

    def _apply(delta, reasons, strong=False, kind="positive"):
        nonlocal score, positive_delta, strong_count
        if not delta and not reasons:
            return
        if delta:
            score += delta
            if kind == "positive" and delta > 0:
                positive_delta += delta
            modifiers.append({
                "delta": delta,
                "reason": "; ".join(reasons) if reasons else kind,
                "type": kind,
            })
        narrative.extend(reasons)
        if strong:
            strong_count += 1
            evidence_bits.extend(reasons)

    if ti_delta:
        _apply(ti_delta, ti_reasons, ti_strong)
    if lin_delta:
        _apply(lin_delta, lin_reasons, lineage_strong)
    if ps_delta:
        _apply(ps_delta, ps_reasons, ps_strong)
    if persist_delta:
        _apply(persist_delta, persist_reasons, persist_strong)
    if ps_strong and persist_strong:
        _apply(
            15,
            ["Encoded/download PowerShell + persistence (+15)"],
            True,
        )
    if cred_delta:
        _apply(cred_delta, cred_reasons, cred_strong)
        if cred_strong:
            confirmed_malware = True
    if net_delta:
        _apply(net_delta, net_reasons, False)
    if lineage_strong and external_malicious:
        _apply(
            12,
            ["LOLBin/suspicious lineage + malicious network (+12)"],
            True,
        )
    if file_delta:
        _apply(file_delta, file_reasons, file_strong)
    if hist_delta:
        _apply(hist_delta, hist_reasons, hist_strong)
    if mitre_count >= 3 and (
        ti_strong or persist_strong or ps_strong or lineage_strong
    ):
        _apply(
            8,
            [
                f"Multiple correlated ATT&CK techniques "
                f"({mitre_count}) (+8)"
            ],
            True,
        )

    if ti_clean:
        _apply(-10, ["Clean IOC / no malicious TI (-10)"], kind="negative")

    strong_override = (
        confirmed_malware
        or (ti_strong and (persist_strong or ps_strong or lineage_strong))
        or (ps_strong and persist_strong)
        or (lineage_strong and external_malicious)
        or cred_strong
        or (strong_count >= 2 and positive_delta >= 35)
    )

    damp_reasons = []
    if clean_context and context == "developer_workflow":
        damp_reasons = [
            f"Trusted developer allowlist matched ({ctx['chain']})",
            "Threat Intelligence clean",
            "No persistence",
            "No malicious command line",
            "No suspicious external malicious communication",
        ]
        narrative.extend(damp_reasons)
        narrative.append(
            "Developer workflow detected. This activity is consistent "
            "with normal software development and is unlikely to "
            "represent malicious behavior."
        )
        score = min(score, CONTEXT_CLEAN_CAP["developer_workflow"])
        score = max(18, min(score, 28))
    elif clean_context and context == "administrative":
        damp_reasons = [
            f"Administrative activity pattern ({ctx['chain']})",
            "No independent malicious evidence",
        ]
        narrative.extend(damp_reasons)
        score = min(score, CONTEXT_CLEAN_CAP["administrative"])
        score = max(18, min(score, 30))
    elif clean_context and context == "unknown":
        score = min(score, CONTEXT_CLEAN_CAP["unknown"])

    raw_score = score
    score = max(0, min(100, int(round(score))))

    confidence = _evidence_confidence(
        strong_count,
        ti_strong,
        persist_strong,
        lineage_strong,
        ps_strong,
        external_malicious,
        clean_context,
        mitre_count,
        cred_strong,
    )

    if confidence == "Low" and score > 60 and not confirmed_malware:
        score = 60
        narrative.append(
            "Evidence Confidence Low — capped at Medium pending "
            "stronger corroboration"
        )

    if score >= 61 and not _tier2_would_escalate(
        confirmed_malware, strong_override, strong_count, context
    ):
        score = min(score, 55)
        narrative.append(
            "Tier-2 gate: would not escalate — reduced below High"
        )

    if context == "potential_attack" and strong_override:
        score = max(score, 55 if not confirmed_malware else 70)

    score = max(0, min(100, int(score)))
    our_label = _overall_label(score)

    elastic_numeric_ref = {
        "low": 22, "medium": 45, "high": 68, "critical": 88,
    }.get(sev_key, 22)
    display_delta = score - elastic_numeric_ref

    reason = _build_reason_for_difference(
        elastic_lbl,
        our_label,
        score,
        context,
        clean_context,
        strong_override,
        ctx,
        evidence_bits or [
            r for r in narrative
            if any(
                k in r.lower()
                for k in (
                    "virustotal", "hybrid", "abuseipdb", "persistence",
                    "encoded", "download", "lolbin", "office",
                    "credential", "ransomware",
                )
            )
        ],
    )

    divergence = [
        f"Elastic Detection Severity: {elastic_lbl}",
        f"Analyst Risk Assessment: {our_label} (Score: {score}/100)",
        f"Alert Context: {context.replace('_', ' ')}",
        f"Evidence Confidence: {confidence}",
        f"Reason for Difference: {reason}",
    ]

    return {
        "risk_score": score,
        "risk_score_label": f"{score}/100",
        "overall_risk": our_label,
        "elastic_severity": severity,
        "elastic_detection_severity": elastic_lbl,
        "elastic_baseline": elastic_seed,
        "elastic_confidence_seed": elastic_seed,
        "analyst_risk_assessment": our_label,
        "alert_context": context,
        "risk_delta": display_delta,
        "risk_delta_label": f"{display_delta:+d}",
        "evidence_confidence": confidence,
        "recommendation": _recommendation(score),
        "breakdown": breakdown,
        "modifiers": modifiers,
        "reasons": _dedupe(narrative),
        "positive_reasons": [
            m["reason"] for m in modifiers if m["type"] == "positive"
        ],
        "dampen_reasons": damp_reasons,
        "divergence_reasons": _dedupe(divergence),
        "reason_for_difference": reason,
        "analyst_rationale": reason,
        "aligned_with_elastic": our_label == elastic_lbl,
        "strong_malicious_override": strong_override,
        "confirmed_malware": confirmed_malware,
        "developer_workflow": context == "developer_workflow",
        "clean_developer_workflow": (
            context == "developer_workflow" and clean_context
        ),
        "process_chain": ctx["chain"],
        "raw_score_before_cap": int(round(raw_score)),
    }


def print_risk_score(result):
    print("\nSeverity Scoring")
    print("-" * 60)
    print(
        "Elastic Detection Severity : "
        f"{result.get('elastic_detection_severity') or result.get('elastic_severity')}"
    )
    print(
        "Analyst Risk Assessment    : "
        f"{result.get('overall_risk')} "
        f"(Score: {result.get('risk_score_label')})"
    )
    print(f"Alert Context              : {result.get('alert_context')}")
    print(
        f"Evidence Confidence        : "
        f"{result.get('evidence_confidence')}"
    )
    print(
        f"Recommendation             : "
        f"{result.get('recommendation')}"
    )
    print(
        "Reason for Difference      : "
        f"{result.get('reason_for_difference')}"
    )
