"""
Map investigation / alert signals to MITRE ATT&CK techniques.
Heuristic mapping for SOC report context — not a full ATT&CK engine.
"""

from ecs_utils import as_lower


def _safe_len(items):
    if not items:
        return 0
    if isinstance(items, list) and items and isinstance(
        items[0], dict
    ) and "_error" in items[0]:
        return 0
    return len(items)


def map_mitre(alert, enrichment, investigation, risk=None):
    """
    Return MITRE tactics/techniques inferred from available evidence.
    """
    inv = investigation or {}
    persistence = inv.get("persistence") or {}
    iocs = (enrichment or {}).get("iocs") or {}
    techniques = []
    seen = set()

    def add(technique_id, name, tactic, evidence):
        key = technique_id
        if key in seen:
            return
        seen.add(key)
        techniques.append({
            "id": technique_id,
            "name": name,
            "tactic": tactic,
            "evidence": evidence,
        })

    process = as_lower(
        alert.get("process.name")
        or (alert.get("process") or {}).get("name")
    )
    command = as_lower(
        alert.get("process.command_line")
        or (alert.get("process") or {}).get("command_line")
        or iocs.get("command_line")
    )
    rule = as_lower(alert.get("kibana.alert.rule.name"))

    if "powershell" in process or "powershell" in command:
        add(
            "T1059.001",
            "PowerShell",
            "Execution",
            "PowerShell process/command observed",
        )
    if process in ("cmd.exe", "cmd") or "cmd.exe" in command:
        add(
            "T1059.003",
            "Windows Command Shell",
            "Execution",
            "cmd.exe execution observed",
        )
    if "python" in process or "python" in command:
        add(
            "T1059",
            "Command and Scripting Interpreter",
            "Execution",
            "Script interpreter execution observed",
        )
    if "malware" in rule:
        add(
            "T1204",
            "User Execution",
            "Execution",
            "Malware prevention / file alert",
        )

    if _safe_len(inv.get("child_processes")) > 0:
        add(
            "T1106",
            "Native API / Process Creation",
            "Execution",
            "Child process creation observed",
        )

    if persistence.get("registry_persistence") or any(
        "run" in as_lower(
            (r.get("path") or "") + (r.get("key") or "")
        )
        for r in (inv.get("registry_changes") or [])
        if isinstance(r, dict) and not r.get("_error")
    ):
        add(
            "T1547.001",
            "Registry Run Keys / Startup Folder",
            "Persistence",
            "Registry Run-key style persistence",
        )

    if _safe_len(
        inv.get("scheduled_tasks")
        or persistence.get("scheduled_tasks")
    ):
        add(
            "T1053.005",
            "Scheduled Task",
            "Persistence",
            "Scheduled task activity observed",
        )

    if _safe_len(inv.get("services") or persistence.get("services")):
        add(
            "T1543.003",
            "Windows Service",
            "Persistence",
            "Service creation/modification observed",
        )

    if persistence.get("startup_folder") or persistence.get(
        "wmi_persistence"
    ):
        if persistence.get("startup_folder"):
            add(
                "T1547.001",
                "Registry Run Keys / Startup Folder",
                "Persistence",
                "Startup folder file activity",
            )
        if persistence.get("wmi_persistence"):
            add(
                "T1546.003",
                "WMI Event Subscription",
                "Persistence",
                "WMI persistence indicators",
            )

    if _safe_len(inv.get("file_creations")):
        add(
            "T1105",
            "Ingress Tool Transfer",
            "Command and Control",
            "File creation/drop observed",
        )

    if _safe_len(inv.get("network_connections")) or iocs.get(
        "lookup_ip"
    ):
        add(
            "T1071",
            "Application Layer Protocol",
            "Command and Control",
            "Network connection / external IP activity",
        )

    if _safe_len(inv.get("dns_events")) or iocs.get("domain"):
        add(
            "T1071.004",
            "DNS",
            "Command and Control",
            "DNS / domain activity observed",
        )

    if _safe_len(inv.get("authentication_events")):
        add(
            "T1078",
            "Valid Accounts",
            "Defense Evasion / Persistence",
            "Authentication / logon activity near alert",
        )

    if enrichment.get("virustotal_hash") or enrichment.get(
        "hybrid_analysis"
    ):
        add(
            "T1204.002",
            "Malicious File",
            "Execution",
            "Hash reputation / malware sample signal",
        )

    tactics = sorted({t["tactic"] for t in techniques})

    return {
        "techniques": techniques,
        "tactics": tactics,
        "technique_count": len(techniques),
    }


def print_mitre(mitre):
    print("\nMITRE ATT&CK")
    print("-" * 60)
    techniques = (mitre or {}).get("techniques") or []
    if not techniques:
        print("  No mapped techniques")
        return
    for item in techniques:
        print(
            f"  {item.get('id')} | {item.get('tactic')} | "
            f"{item.get('name')} — {item.get('evidence')}"
        )
