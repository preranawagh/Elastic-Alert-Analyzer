"""
Regenerate PDF from an existing combined JSON report.

Usage:
  python regenerate_pdf.py reports/soc_report_YYYYMMDDTHHMMSSZ.json
  python regenerate_pdf.py   # uses newest reports/soc_report_*.json
"""

import glob
import json
import os
import sys

from pdf_export import build_pdf_report


def newest_json(reports_dir="reports"):
    paths = sorted(
        glob.glob(os.path.join(reports_dir, "soc_report_*.json")),
        key=os.path.getmtime,
        reverse=True,
    )
    return paths[0] if paths else None


def main():
    if len(sys.argv) > 1:
        json_path = sys.argv[1]
    else:
        json_path = newest_json()
        if not json_path:
            print("No soc_report_*.json found in reports/")
            return 1

    with open(json_path, encoding="utf-8") as handle:
        data = json.load(handle)

    reports = []
    for item in data.get("alerts") or []:
        report = {
            k: v
            for k, v in item.items()
            if k not in ("alert_number", "alert_label")
        }
        reports.append(report)

    pdf_path = os.path.splitext(json_path)[0] + "_v2.pdf"
    ok, err = build_pdf_report(
        reports,
        pdf_path,
        generated_at=data.get("generated_at"),
    )
    if ok:
        print(f"Wrote {pdf_path}")
        return 0
    print(f"Failed: {err}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
