"""
Incremental combined-report writer for batched pipeline processing.

Stages per-batch report JSON on disk, then finalizes to the same
Markdown / JSON / HTML / PDF outputs as save_combined_report().
"""

from __future__ import annotations

import glob
import json
import logging
import os
import shutil
from datetime import datetime, timezone

from config import REPORTS_DIR
from report import (
    _badge,
    _data_table,
    _html_esc,
    _render_alert_html,
    _report_css,
    render_alert_section,
)
from pdf_export import build_pdf_report

logger = logging.getLogger("soc_pipeline")


def iter_staged_report_pairs(staging_dir: str):
    """Yield (alert_number, report) tuples from staged batch files."""
    pattern = os.path.join(staging_dir, "batch_*.json")
    index = 0
    for batch_path in sorted(glob.glob(pattern)):
        with open(batch_path, encoding="utf-8") as handle:
            batch = json.load(handle)
        for report in batch:
            index += 1
            yield index, report
        del batch


def make_report_source(staging_dir: str):
    """Return a factory that produces a fresh iterator for each pass."""

    def factory():
        return iter_staged_report_pairs(staging_dir)

    return factory


class IncrementalReportWriter:
    """
    Stage completed alert reports in batches, then finalize once.

    Only one batch of report dicts needs to reside in memory at a time.
    """

    def __init__(self, output_dir: str | None = None):
        self.output_dir = output_dir or REPORTS_DIR
        self.generated_at = datetime.now(timezone.utc).isoformat()
        self.stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self.base = f"soc_report_{self.stamp}"
        self.staging_dir = os.path.join(
            self.output_dir, ".staging", self.stamp
        )
        self._batch_num = 0
        self.total_reports = 0
        os.makedirs(self.staging_dir, exist_ok=True)

    @property
    def md_path(self) -> str:
        return os.path.join(self.output_dir, f"{self.base}.md")

    @property
    def json_path(self) -> str:
        return os.path.join(self.output_dir, f"{self.base}.json")

    @property
    def html_path(self) -> str:
        return os.path.join(self.output_dir, f"{self.base}.html")

    @property
    def pdf_path(self) -> str:
        return os.path.join(self.output_dir, f"{self.base}.pdf")

    def add_batch(self, reports: list) -> None:
        """Persist one batch of completed reports and release them from RAM."""
        if not reports:
            return
        self._batch_num += 1
        batch_path = os.path.join(
            self.staging_dir,
            f"batch_{self._batch_num:05d}.json",
        )
        with open(batch_path, "w", encoding="utf-8") as handle:
            json.dump(reports, handle, default=str)
        count = len(reports)
        self.total_reports += count
        logger.info(
            "Batch %s staged (%s reports, %s total)",
            self._batch_num,
            count,
            self.total_reports,
        )

    def _write_markdown(self) -> None:
        header = "\n".join([
            "# SOC Investigation Report",
            "",
            f"**Generated:** {self.generated_at}",
            f"**Alert Count:** {self.total_reports}",
            "",
            "---",
            "",
        ])
        with open(self.md_path, "w", encoding="utf-8") as handle:
            handle.write(header)
            for index, report in iter_staged_report_pairs(
                self.staging_dir
            ):
                handle.write(render_alert_section(report, index))
                handle.write("\n")

    def _write_json(self) -> None:
        with open(self.json_path, "w", encoding="utf-8") as handle:
            handle.write("{\n")
            handle.write(
                f'  "generated_at": {json.dumps(self.generated_at)},\n'
            )
            handle.write(
                f'  "alert_count": {self.total_reports},\n'
            )
            handle.write('  "alerts": [\n')
            first = True
            for index, report in iter_staged_report_pairs(
                self.staging_dir
            ):
                entry = {
                    "alert_number": index,
                    "alert_label": f"Alert {index}",
                    **report,
                }
                dumped = json.dumps(entry, indent=2, default=str)
                indented = "\n".join(
                    "    " + line for line in dumped.splitlines()
                )
                if not first:
                    handle.write(",\n")
                else:
                    first = False
                handle.write(indented)
            handle.write("\n  ]\n}\n")

    def _write_html(self) -> None:
        toc_rows = []
        for index, report in iter_staged_report_pairs(self.staging_dir):
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

        with open(self.html_path, "w", encoding="utf-8") as handle:
            handle.write(
                f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <title>SOC Investigation Report</title>
  <style>{_report_css(for_pdf=False)}</style>
</head>
<body>
  <div class="page">
    <header class="cover">
      <h1>SOC Investigation Report</h1>
      <div class="meta">
        Generated: {_html_esc(self.generated_at)}<br/>
        Alert Count: {self.total_reports}
      </div>
    </header>

    <section class="alert-card">
      <h1>Report Index</h1>
      {toc}
    </section>

"""
            )
            for index, report in iter_staged_report_pairs(
                self.staging_dir
            ):
                handle.write(_render_alert_html(report, index))
                handle.write("\n")
            handle.write(
                """  </div>
</body>
</html>
"""
            )

    def finalize(self) -> dict:
        """
        Build final combined outputs from staged batches.

        Returns the same path dict shape as save_combined_report().
        """
        os.makedirs(self.output_dir, exist_ok=True)
        logger.info(
            "Report finalization starting (%s alerts)...",
            self.total_reports,
        )

        self._write_markdown()
        self._write_json()
        self._write_html()

        pdf_ok, pdf_error = build_pdf_report(
            reports=None,
            output_path=self.pdf_path,
            generated_at=self.generated_at,
            report_source=make_report_source(self.staging_dir),
            alert_count=self.total_reports,
        )

        try:
            shutil.rmtree(self.staging_dir)
        except OSError as exc:
            logger.warning(
                "Could not remove staging dir %s: %s",
                self.staging_dir,
                exc,
            )

        result = {
            "markdown": self.md_path,
            "json": self.json_path,
            "html": self.html_path,
        }
        if pdf_ok:
            result["pdf"] = self.pdf_path
        else:
            result["pdf"] = None
            result["pdf_error"] = pdf_error

        return result
