from elastic_client import es
from enrichment import enrich_alert

response = es.search(
    index=".internal.alerts-security.alerts-default-000001",
    size=10,
    sort=[
        {
            "@timestamp": {
                "order": "desc"
            }
        }
    ]
)

hits = response["hits"]["hits"]

print(f"\nFound {len(hits)} alerts\n")

for alert in hits:

    src = alert["_source"]

    enrichment = enrich_alert(src)

    rule = src.get("kibana.alert.rule.name")

    severity = (
        src.get("kibana.alert.severity")
        or src.get("kibana.alert.rule.severity")
    )

    reason = src.get("kibana.alert.reason")

    timestamp = src.get("@timestamp")

    host = (
        src.get("host.name")
        or src.get("host", {}).get("name")
    )

    user = (
        src.get("user.name")
        or src.get("user", {}).get("name")
    )

    process = (
        src.get("process.name")
        or src.get("process", {}).get("name")
    )

    command = (
        src.get("process.command_line")
        or src.get("process", {}).get("command_line")
    )

    source_ip = (
        src.get("source.ip")
        or src.get("source", {}).get("ip")
    )

    destination_ip = (
        src.get("destination.ip")
        or src.get("destination", {}).get("ip")
    )

    print("=" * 100)

    print(f"Rule          : {rule}")
    print(f"Severity      : {severity}")
    print(f"Reason        : {reason}")
    print(f"Host          : {host}")
    print(f"User          : {user}")
    print(f"Process       : {process}")
    print(f"Command Line  : {command}")
    print(f"Source IP     : {source_ip}")
    print(f"Destination IP: {destination_ip}")
    print(f"Timestamp     : {timestamp}")

    print("\nThreat Intelligence")
    print("-" * 60)

    # ---------------- VirusTotal ----------------

    vt = enrichment["virustotal"]

    if vt:
        try:
            stats = vt["data"]["attributes"]["last_analysis_stats"]

            print(
                f"VirusTotal    : "
                f"{stats['malicious']} malicious | "
                f"{stats['suspicious']} suspicious"
            )

        except Exception:
            print("VirusTotal    : Data Available")

    else:
        print("VirusTotal    : No data")

    # ---------------- AbuseIPDB ----------------

    abuse = enrichment["abuseipdb"]

    if abuse:
        try:
            score = abuse["data"]["abuseConfidenceScore"]

            print(
                f"AbuseIPDB     : "
                f"{score}% Abuse Confidence"
            )

        except Exception:
            print("AbuseIPDB     : Data Available")

    else:
        print("AbuseIPDB     : No data")

    # ---------------- Shodan ----------------

    shodan = enrichment["shodan"]

    if shodan:

        print(
            f"Organization  : {shodan.get('org')}"
        )

        print(
            f"Operating Sys : {shodan.get('os')}"
        )

        print(
            f"Country       : {shodan.get('country_name')}"
        )

    else:

        print("Shodan        : No data")

    # ---------------- Hybrid Analysis ----------------

    hybrid = enrichment["hybrid_analysis"]

    if hybrid:
        print("HybridAnalysis: Sample Found")
    else:
        print("HybridAnalysis: No data")

    print()