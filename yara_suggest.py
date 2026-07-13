"""
YARA recommendations for malware / file-centric alerts only.

YARA scans file content. Behavioral, auth, registry, and network-only
alerts should NOT get a YARA section.

When applicable, recommend scanning with org YARA rules.
Draft YARA rule text is optional and only emitted when there is
enough malware-file evidence (malicious TI and/or dropped sample
indicators).
"""

import re
from datetime import datetime, timezone

from ecs_utils import as_text, get_field


# Rule-name patterns that are file/malware oriented
_MALWARE_RULE_HINTS = (
    "malware",
    "ransomware",
    "trojan",
    "virus",
    "worm",
    "backdoor",
    "rootkit",
    "malicious file",
    "malicious executable",
    "suspicious executable",
    "suspicious dll",
    "suspicious exe",
    "unsigned executable",
    "file download",
    "file dropped",
    "script dropped",
    "macro",
    "office child",
    "encoded powershell",
    "obfuscated powershell",
    "frombase64",
    "hollowing",
    "process injection",
    "suspicious python",
)

# Behavioral / non-file alerts — YARA is not useful
_NON_FILE_RULE_HINTS = (
    "successful login",
    "failed login",
    "authentication",
    "user creation",
    "user added",
    "service start",
    "service stop",
    "service installed",
    "network scan",
    "port scan",
    "dns query",
    "dns lookup",
    "lateral movement",
    "privilege escalation",
    "registry run key",
    "registry persistence",
    "scheduled task",
    "wmi persistence",
    "brute force",
    "rdp",
    "ssh login",
    "kerberos",
    "ntlm",
)

_BENIGN_DEV_PARENTS = (
    "code.exe",
    "code",
    "cursor.exe",
    "cursor",
    "devenv.exe",
    "pycharm",
    "idea64.exe",
    "windbg.exe",
)

_SCRIPT_EXTS = (
    ".exe", ".dll", ".sys", ".scr", ".com",
    ".ps1", ".bat", ".cmd", ".vbs", ".js",
    ".msi", ".hta", ".wsf",
)

_ENCODED_PS_MARKERS = (
    "-enc",
    "-e ",
    "-encodedcommand",
    "frombase64string",
    "iex(",
    "invoke-expression",
    "downloadstring",
    "downloadfile",
    "invoke-webrequest",
    "wget ",
    "curl ",
    "net.webclient",
)


def _safe_ident(text, fallback="Sample"):
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", as_text(text) or "")
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    if not cleaned:
        cleaned = fallback
    if cleaned[0].isdigit():
        cleaned = f"File_{cleaned}"
    return cleaned[:48]


def _yara_escape(text):
    return (
        as_text(text)
        .replace("\\", "\\\\")
        .replace('"', '\\"')
    )


def _vt_malicious_stats(payload):
    if not isinstance(payload, dict):
        return 0, 0
    try:
        stats = payload["data"]["attributes"]["last_analysis_stats"]
        return (
            int(stats.get("malicious") or 0),
            int(stats.get("suspicious") or 0),
        )
    except Exception:
        return 0, 0


def _ti_malware_signal(enrichment):
    """True if VT/Hybrid indicate a malicious file sample."""
    enrichment = enrichment or {}
    reasons = []

    for label, key in (
        ("VirusTotal hash", "virustotal_hash"),
        ("VirusTotal file", "virustotal"),
        ("VirusTotal URL", "virustotal_url"),
    ):
        mal, sus = _vt_malicious_stats(enrichment.get(key))
        if mal > 0:
            reasons.append(f"{label}: {mal} malicious")
        elif sus >= 3:
            reasons.append(f"{label}: {sus} suspicious")

    hybrid = enrichment.get("hybrid_analysis")
    if hybrid:
        # Hybrid payload present usually means a sample was found
        score = None
        if isinstance(hybrid, dict):
            score = (
                hybrid.get("threat_score")
                or hybrid.get("av_detect")
                or (hybrid.get("data") or {}).get("threat_score")
            )
        reasons.append(
            "Hybrid Analysis sample found"
            + (f" (score={score})" if score is not None else "")
        )

    return reasons


def _path_has_script_ext(path_or_name):
    text = as_text(path_or_name).lower()
    return any(text.endswith(ext) for ext in _SCRIPT_EXTS)


def _is_download_drop_path(path):
    lower = as_text(path).lower().replace("/", "\\")
    return any(
        token in lower
        for token in (
            "\\temp\\",
            "\\tmp\\",
            "\\downloads\\",
            "\\appdata\\local\\temp\\",
            "\\users\\public\\",
            "\\programdata\\",
        )
    )


def _encoded_or_download_cmdline(cmdline):
    text = as_text(cmdline).lower()
    return any(marker in text for marker in _ENCODED_PS_MARKERS)


def _dropped_executable_evidence(investigation):
    """File creates that look like dropped malware samples."""
    inv = investigation or {}
    drops = []
    for event in (inv.get("file_creations") or [])[:30]:
        if not isinstance(event, dict) or event.get("_error"):
            continue
        name = as_text(event.get("name"))
        path = as_text(event.get("path"))
        target = path or name
        if not target:
            continue
        if _path_has_script_ext(target) or _is_download_drop_path(
            target
        ):
            drops.append({
                "name": name or None,
                "path": path or None,
                "hash_sha256": event.get("hash_sha256"),
                "hash_md5": event.get("hash_md5"),
            })
    return drops


def _collect_sample_indicators(alert, enrichment, investigation):
    iocs = (enrichment or {}).get("iocs") or {}
    names = set()
    paths = set()
    hashes = {"sha256": set(), "sha1": set(), "md5": set()}

    for name in (
        iocs.get("file_name"),
        get_field(alert, "file.name"),
    ):
        if name:
            names.add(as_text(name))

    for path in (
        iocs.get("file_path"),
        get_field(alert, "file.path"),
    ):
        if path:
            paths.add(as_text(path))

    for algo in ("sha256", "sha1", "md5"):
        value = iocs.get(algo)
        if value:
            hashes[algo].add(as_text(value).lower())

    for drop in _dropped_executable_evidence(investigation):
        if drop.get("name"):
            names.add(drop["name"])
        if drop.get("path"):
            paths.add(drop["path"])
        if drop.get("hash_sha256"):
            hashes["sha256"].add(
                as_text(drop["hash_sha256"]).lower()
            )
        if drop.get("hash_md5"):
            hashes["md5"].add(as_text(drop["hash_md5"]).lower())

    cmdline = as_text(
        iocs.get("command_line")
        or get_field(alert, "process.command_line")
    )
    # Pull downloaded/script paths from cmdline when present
    for token in re.findall(
        r"[A-Za-z0-9._-]{3,}\.(?:exe|dll|ps1|bat|cmd|vbs|js|msi|scr)",
        cmdline,
        flags=re.IGNORECASE,
    ):
        names.add(token)

    return {
        "file_names": sorted(names),
        "file_paths": sorted(paths),
        "sha256": sorted(hashes["sha256"]),
        "sha1": sorted(hashes["sha1"]),
        "md5": sorted(hashes["md5"]),
        "command_line": cmdline or None,
    }


def evaluate_yara_applicability(
    alert, enrichment=None, investigation=None
):
    """
    Decide whether a YARA recommendation belongs on this alert.

    Returns (applicable: bool, reasons: list[str], strength: str).
    strength: none | recommend | draft
      - recommend: advise org YARA scan / hash hunt
      - draft: also emit an optional draft rule (strong malware evidence)
    """
    enrichment = enrichment or {}
    investigation = investigation or {}
    reasons = []

    rule = as_text(
        get_field(alert, "kibana.alert.rule.name")
    ).lower()
    process = as_text(get_field(alert, "process.name")).lower()
    parent = as_text(
        get_field(alert, "process.parent.name")
    ).lower()
    cmdline = as_text(get_field(alert, "process.command_line"))
    iocs = enrichment.get("iocs") or {}

    # Explicit non-file / behavioral alerts
    if any(hint in rule for hint in _NON_FILE_RULE_HINTS):
        # Still allow override if strong file malware TI exists
        ti_reasons = _ti_malware_signal(enrichment)
        hash_present = bool(
            iocs.get("sha256") or iocs.get("sha1") or iocs.get("md5")
        )
        if not (ti_reasons and hash_present):
            return False, [
                "Behavioral/auth/network alert — YARA scans files, "
                "not this activity type"
            ], "none"

    ti_reasons = _ti_malware_signal(enrichment)
    if ti_reasons:
        reasons.extend(ti_reasons)

    if any(hint in rule for hint in _MALWARE_RULE_HINTS):
        reasons.append(f"Malware/file-oriented detection: {rule}")

    drops = _dropped_executable_evidence(investigation)
    if drops:
        reasons.append(
            f"Dropped executable/script evidence "
            f"({len(drops)} file create(s))"
        )

    file_name = as_text(iocs.get("file_name") or get_field(alert, "file.name"))
    file_path = as_text(iocs.get("file_path") or get_field(alert, "file.path"))
    has_hash = bool(
        iocs.get("sha256") or iocs.get("sha1") or iocs.get("md5")
        or get_field(alert, "file.hash.sha256")
        or get_field(alert, "file.hash.md5")
    )

    if has_hash and (
        _path_has_script_ext(file_name)
        or _path_has_script_ext(file_path)
        or drops
        or ti_reasons
        or any(hint in rule for hint in _MALWARE_RULE_HINTS)
    ):
        reasons.append("File hash available for sample hunting")

    if _encoded_or_download_cmdline(cmdline):
        # Only count if also involves a dropped/downloaded file pattern
        if drops or any(
            ext in cmdline.lower() for ext in _SCRIPT_EXTS
        ):
            reasons.append(
                "Encoded/download PowerShell with file artifact"
            )
        elif "macro" in rule or "office" in rule:
            reasons.append("Office/macro style encoded execution")

    # Office spawning cmd/powershell is malware-relevant
    if (
        any(x in parent for x in ("winword", "excel", "powerpnt", "outlook"))
        and any(x in process for x in ("cmd", "powershell", "wscript", "cscript"))
    ):
        reasons.append("Office application spawned scripting host")

    # Pure IDE / GenAI / normal PowerShell without file malware cues
    benign_dev = (
        any(p in parent for p in _BENIGN_DEV_PARENTS)
        or "genai" in rule
        or "mcp server" in rule
        or "vscode" in rule
        or "visual studio code" in rule
    )
    if benign_dev and not ti_reasons and not drops and not (
        has_hash and _path_has_script_ext(file_name or file_path)
    ):
        return False, [
            "Developer/IDE or GenAI child-process behavior without "
            "malware file evidence — YARA not recommended"
        ], "none"

    # PowerShell / python execution alone is not enough
    if not reasons:
        if process in ("powershell.exe", "pwsh.exe", "python.exe", "python"):
            return False, [
                "Process execution without malware file indicators "
                "— YARA not recommended"
            ], "none"
        if "child process" in rule or "parent" in rule:
            return False, [
                "Parent-child process alert without malware file "
                "indicators — YARA not recommended"
            ], "none"
        return False, [
            "No malware/file evidence suitable for YARA"
        ], "none"

    # Strength: draft only with TI malware or clear drop+hash
    strength = "recommend"
    if ti_reasons or (
        drops and has_hash
    ) or (
        has_hash and any(hint in rule for hint in _MALWARE_RULE_HINTS)
    ):
        strength = "draft"

    # Deduplicate reasons
    deduped = []
    seen = set()
    for item in reasons:
        if item not in seen:
            deduped.append(item)
            seen.add(item)

    return True, deduped, strength


def _default_recommendations(indicators, reasons):
    actions = [
        "Scan the sample with the organization's malware YARA rules "
        "before allowing execution elsewhere.",
        "Submit the file for malware analysis / sandbox detonation.",
        "Collect SHA256 (and SHA1/MD5 if available) and hunt the hash "
        "across the environment.",
        "Compare the sample against existing malware signatures and "
        "known-bad hash lists.",
    ]
    if indicators.get("sha256") or indicators.get("md5"):
        actions.insert(
            0,
            "Run a YARA scan on the hashed sample and quarantine if "
            "any organizational malware rules match.",
        )
    if any("VirusTotal" in r or "Hybrid" in r for r in reasons):
        actions.append(
            "Treat positive VirusTotal/Hybrid findings as confirmation "
            "to prioritize YARA + sandbox analysis of this sample."
        )
    if any("Dropped" in r or "download" in r.lower() for r in reasons):
        actions.append(
            "Locate the dropped/downloaded executable on disk and scan "
            "it with org YARA rules before cleanup."
        )
    # Dedup
    out = []
    seen = set()
    for item in actions:
        if item not in seen:
            out.append(item)
            seen.add(item)
    return out


def _optional_draft_rule(indicators, rule_hint, reasons):
    """
    Draft YARA only when strength == draft and we have useful strings.
    This is an advanced aid — not emitted for every eligible alert.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    base = _safe_ident(rule_hint or "Malware_Sample")
    strings = []

    for index, name in enumerate(indicators["file_names"][:4], start=1):
        if len(name) >= 4:
            strings.append(
                (f"name{index}", name, "ascii wide nocase")
            )

    cmdline = indicators.get("command_line") or ""
    for marker in (
        "FromBase64String",
        "DownloadString",
        "DownloadFile",
        "Invoke-Expression",
        "-EncodedCommand",
        "VirtualAllocEx",
        "WriteProcessMemory",
        "CreateRemoteThread",
    ):
        if marker.lower() in cmdline.lower():
            sid = re.sub(r"[^A-Za-z0-9]", "", marker)[:16]
            strings.append((sid or "m", marker, "ascii wide nocase"))

    for frag in (
        "\\Users\\Public\\",
        "\\AppData\\Local\\Temp\\",
        "\\Downloads\\",
    ):
        if any(frag.lower() in p.lower() for p in indicators["file_paths"]):
            strings.append(
                (f"path{len(strings)+1}", frag, "ascii wide nocase")
            )

    if not strings and not (
        indicators["sha256"] or indicators["md5"] or indicators["sha1"]
    ):
        return None

    meta = {
        "author": "Elastic Alert Analyzer",
        "date": today,
        "description": (
            "Optional draft from malware-file evidence — validate "
            "in a lab before production use"
        ),
        "confidence": "low",
        "reference_alert": as_text(rule_hint),
    }
    if indicators["sha256"]:
        meta["hash_sha256"] = indicators["sha256"][0]
    if indicators["sha1"]:
        meta["hash_sha1"] = indicators["sha1"][0]
    if indicators["md5"]:
        meta["hash_md5"] = indicators["md5"][0]

    if not strings:
        strings.append(("tag", "ElasticAlertAnalyzer", "ascii"))
        condition = "$tag"
        rationale = (
            "Hash documented in meta for exact matching; extend with "
            "extracted sample strings after lab analysis."
        )
    else:
        condition = "any of them"
        rationale = (
            "Draft strings from observed filenames / cmdline / drop "
            "paths. Prefer org malware rules first; use this only as "
            "a starting point after sample analysis."
        )

    meta_lines = [
        f'        {key} = "{_yara_escape(value)}"'
        for key, value in meta.items()
    ]
    string_lines = [
        f'        ${sid} = "{_yara_escape(value)}" {modifiers}'
        for sid, value, modifiers in strings
    ]
    rule_text = (
        f"rule SOC_Draft_{base} {{\n"
        f"    meta:\n"
        + "\n".join(meta_lines) + "\n"
        + "    strings:\n"
        + "\n".join(string_lines) + "\n"
        + "    condition:\n"
        f"        {condition}\n"
        f"}}\n"
    )
    return {
        "name": f"SOC_Draft_{base}",
        "rationale": rationale,
        "rule": rule_text,
        "evidence": reasons[:5],
    }


def suggest_yara_rules(alert, enrichment=None, investigation=None):
    """
    Return YARA guidance only when malware/file evidence warrants it.

    Shape:
      applicable: bool
      strength: none|recommend|draft
      reasons: why included/excluded
      recommendations: analyst actions (when applicable)
      draft_rules: optional list (only when strength=draft)
    """
    applicable, reasons, strength = evaluate_yara_applicability(
        alert, enrichment, investigation
    )
    indicators = _collect_sample_indicators(
        alert, enrichment, investigation
    )

    if not applicable:
        return {
            "applicable": False,
            "strength": "none",
            "reasons": reasons,
            "recommendations": [],
            "draft_rules": [],
            "rule_count": 0,
            "suggestions": [],  # backward compatible empty
            "indicators": indicators,
            "note": reasons[0] if reasons else "YARA not applicable",
        }

    recommendations = _default_recommendations(indicators, reasons)
    draft_rules = []
    if strength == "draft":
        draft = _optional_draft_rule(
            indicators,
            get_field(alert, "kibana.alert.rule.name"),
            reasons,
        )
        if draft:
            draft_rules.append(draft)

    return {
        "applicable": True,
        "strength": strength,
        "reasons": reasons,
        "recommendations": recommendations,
        "draft_rules": draft_rules,
        # Keep legacy keys for any callers; prefer draft_rules
        "rule_count": len(draft_rules),
        "suggestions": draft_rules,
        "indicators": indicators,
        "note": (
            "YARA is recommended because this alert involves a "
            "possible malware/file sample. Prefer organization YARA "
            "rules; draft rules below are optional starting points."
            if draft_rules
            else "YARA is recommended for this malware/file-related "
            "alert. Scan the sample with organization YARA rules."
        ),
    }
