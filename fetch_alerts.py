"""
Fetch Elastic Security alerts, investigate each one, and write a
combined SOC report to disk.

Console output is intentionally minimal:
  - progress lines
  - errors only when an alert fails
  - final saved report paths
"""

from elastic_client import es
from enrichment import enrich_alert
from investigation import investigate_alert
from timeline import build_timeline
from scoring import calculate_risk_score
from mitre import map_mitre
from llm_summary import summarize_alert
from yara_suggest import suggest_yara_rules
from history import find_related_alerts, extract_history_fields, record_alert_history
from report import generate_soc_report, save_combined_report
from config import SAVE_REPORTS, REPORTS_DIR, HISTORY_LOOKBACK_DAYS

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
total = len(hits)

print(f"Found {total} alerts. Analyzing...")

all_reports = []
failures = 0

for index, alert in enumerate(hits, start=1):
    src = alert["_source"]
    rule = src.get("kibana.alert.rule.name") or "Unknown Rule"

    try:
        enrichment = enrich_alert(src)
        investigation = investigate_alert(src)
        yara = suggest_yara_rules(
            src, enrichment, investigation
        )
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
        all_reports.append(report)
        print(
            f"[{index}/{total}] OK  {rule}  "
            f"risk={risk.get('risk_score_label')} "
            f"({risk.get('overall_risk')}, "
            f"conf={risk.get('evidence_confidence')})"
        )

    except Exception as exc:
        failures += 1
        print(f"[{index}/{total}] FAIL  {rule}")
        print(f"         Error: {exc}")

if not all_reports:
    print("No reports generated. Fix the errors above and re-run.")
    raise SystemExit(1)

if SAVE_REPORTS:
    saved_paths = save_combined_report(
        all_reports,
        output_dir=REPORTS_DIR,
    )
    print()
    print("Combined SOC report saved:")
    print(f"  Markdown : {saved_paths.get('markdown')}")
    print(f"  JSON     : {saved_paths.get('json')}")
    print(f"  HTML     : {saved_paths.get('html')}")
    if saved_paths.get("pdf"):
        print(f"  PDF      : {saved_paths.get('pdf')}")
    elif saved_paths.get("pdf_error"):
        print(f"  PDF      : skipped ({saved_paths.get('pdf_error')})")
    print(f"  Alerts   : {len(all_reports)}")
    if failures:
        print(f"  Failed   : {failures}")
else:
    print(
        f"Processed {len(all_reports)} alerts "
        "(SAVE_REPORTS=false, nothing written)."
    )
