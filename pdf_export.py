"""
ReportLab-based SOC PDF export.

Replaces xhtml2pdf HTML→PDF so tables wrap, process trees use
ASCII arrows, and severity badges keep HTML-like color coding.
"""

import os
from datetime import datetime, timezone

from ecs_utils import as_text


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


def _plain(value, max_len=None):
    if value is None:
        return "-"
    if isinstance(value, (list, dict)):
        text = str(value)
    else:
        text = str(value).strip() or "-"
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    if max_len and len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def _severity_colors(value):
    text = as_text(value).lower()
    if text in ("critical", "crit"):
        return "#b91c1c", "#ffffff"
    if text in ("high", "suspicious", "malicious"):
        return "#c2410c", "#ffffff"
    if text in ("medium", "med", "moderate"):
        return "#a16207", "#ffffff"
    if text in (
        "low",
        "informational",
        "info",
        "likely_benign",
        "benign",
    ):
        return "#15803d", "#ffffff"
    return "#4b5563", "#ffffff"


def _esc(text):
    return (
        _plain(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def build_pdf_report(reports, output_path, generated_at=None):
    """
    Build a formatted SOC PDF with ReportLab.
    Returns (ok, error).
    """
    try:
        from reportlab.lib import colors
        from reportlab.lib.enums import TA_LEFT
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            ListFlowable,
            ListItem,
            PageBreak,
            Paragraph,
            Preformatted,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError:
        return False, (
            "reportlab is not installed. "
            "Run: pip install reportlab"
        )

    generated_at = generated_at or datetime.now(
        timezone.utc
    ).isoformat()

    try:
        styles = getSampleStyleSheet()
        styles.add(ParagraphStyle(
            name="CoverTitle",
            parent=styles["Heading1"],
            fontSize=20,
            textColor=colors.white,
            spaceAfter=6,
            leading=24,
        ))
        styles.add(ParagraphStyle(
            name="CoverMeta",
            parent=styles["Normal"],
            fontSize=10,
            textColor=colors.white,
            leading=14,
        ))
        styles.add(ParagraphStyle(
            name="AlertTitle",
            parent=styles["Heading1"],
            fontSize=14,
            textColor=colors.HexColor("#0f766e"),
            spaceBefore=4,
            spaceAfter=8,
            leading=18,
        ))
        styles.add(ParagraphStyle(
            name="SectionHead",
            parent=styles["Heading2"],
            fontSize=11,
            textColor=colors.HexColor("#0f172a"),
            spaceBefore=10,
            spaceAfter=4,
            leading=14,
        ))
        styles.add(ParagraphStyle(
            name="SubHead",
            parent=styles["Heading3"],
            fontSize=10,
            textColor=colors.HexColor("#334155"),
            spaceBefore=6,
            spaceAfter=3,
            leading=12,
        ))
        styles.add(ParagraphStyle(
            name="BodyText2",
            parent=styles["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#1f2937"),
            leading=12,
            alignment=TA_LEFT,
        ))
        styles.add(ParagraphStyle(
            name="Muted",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#6b7280"),
            leading=11,
        ))
        styles.add(ParagraphStyle(
            name="Cell",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#1f2937"),
            leading=10,
            wordWrap="CJK",
        ))
        styles.add(ParagraphStyle(
            name="CellKey",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.HexColor("#334155"),
            leading=10,
            fontName="Helvetica-Bold",
        ))
        styles.add(ParagraphStyle(
            name="Badge",
            parent=styles["Normal"],
            fontSize=8,
            textColor=colors.white,
            leading=10,
            alignment=TA_LEFT,
            fontName="Helvetica-Bold",
        ))
        styles.add(ParagraphStyle(
            name="TreePre",
            parent=styles["Code"],
            fontName="Courier",
            fontSize=8,
            textColor=colors.HexColor("#0f172a"),
            leading=11,
            leftIndent=4,
            rightIndent=4,
        ))
        styles.add(ParagraphStyle(
            name="SummaryBox",
            parent=styles["Normal"],
            fontSize=9,
            textColor=colors.HexColor("#134e4a"),
            leading=12,
        ))

        accent = colors.HexColor("#0f766e")
        border = colors.HexColor("#cbd5e1")
        header_bg = colors.HexColor("#e2e8f0")
        key_bg = colors.HexColor("#f8fafc")
        summary_bg = colors.HexColor("#ecfeff")
        page_w, _ = A4
        usable = page_w - 36 * 2

        def P(text, style="BodyText2"):
            return Paragraph(
                _esc(text).replace("\n", "<br/>"),
                styles[style],
            )

        def summary_box(text):
            """Colored callout that does not overlap the section heading."""
            cell = Paragraph(_esc(text), styles["SummaryBox"])
            t = Table([[cell]], colWidths=[usable])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), summary_bg),
                ("BOX", (0, 0), (-1, -1), 0.6, accent),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            return t

        def badge_flowable(value):
            label = _plain(value)
            bg, fg = _severity_colors(value)
            cell = Paragraph(
                _esc(label),
                ParagraphStyle(
                    "BadgeDyn",
                    parent=styles["Badge"],
                    textColor=colors.HexColor(fg),
                ),
            )
            t = Table([[cell]], colWidths=[usable * 0.22])
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor(bg)),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ]))
            return t

        def kv_table(rows, col0=0.28):
            data = [[P("Field", "CellKey"), P("Value", "CellKey")]]
            for key, value in rows:
                if hasattr(value, "wrapOn"):
                    val_cell = value
                else:
                    val_cell = P(value, "Cell")
                data.append([P(key, "CellKey"), val_cell])
            t = Table(
                data,
                colWidths=[usable * col0, usable * (1 - col0)],
                repeatRows=1,
            )
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), header_bg),
                ("GRID", (0, 0), (-1, -1), 0.4, border),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                ("TOPPADDING", (0, 0), (-1, -1), 4),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                ("BACKGROUND", (0, 1), (0, -1), key_bg),
            ]))
            return t

        def data_table(headers, rows, widths=None):
            if widths is None:
                widths = [usable / len(headers)] * len(headers)
            data = [[P(h, "CellKey") for h in headers]]
            if not rows:
                filler = [P("No data", "Muted")] + [
                    P("", "Muted")
                ] * (len(headers) - 1)
                data.append(filler)
            else:
                for row in rows:
                    cells = []
                    for cell in row:
                        if hasattr(cell, "wrapOn"):
                            cells.append(cell)
                        else:
                            cells.append(P(cell, "Cell"))
                    data.append(cells)
            t = Table(data, colWidths=widths, repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), header_bg),
                ("GRID", (0, 0), (-1, -1), 0.4, border),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                ("LEFTPADDING", (0, 0), (-1, -1), 4),
                ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                ("TOPPADDING", (0, 0), (-1, -1), 3),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
                (
                    "ROWBACKGROUNDS",
                    (0, 1),
                    (-1, -1),
                    [colors.white, colors.HexColor("#f8fafc")],
                ),
            ]))
            return t

        def bullet_list(items):
            if not items:
                return P("None", "Muted")
            flow = [
                ListItem(P(item, "BodyText2"), leftIndent=8)
                for item in items
            ]
            return ListFlowable(
                flow,
                bulletType="bullet",
                start="•",
                leftIndent=12,
                bulletFontSize=8,
            )

        def section(title, *flowables):
            block = [Paragraph(title, styles["SectionHead"])]
            block.extend(flowables)
            block.append(Spacer(1, 4))
            return block

        story = []

        cover = Table(
            [
                [Paragraph(
                    "SOC Investigation Report", styles["CoverTitle"]
                )],
                [Paragraph(
                    f"Generated: {_esc(generated_at)}<br/>"
                    f"Alert Count: {len(reports)}",
                    styles["CoverMeta"],
                )],
            ],
            colWidths=[usable],
        )
        cover.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), accent),
            ("LEFTPADDING", (0, 0), (-1, -1), 14),
            ("RIGHTPADDING", (0, 0), (-1, -1), 14),
            ("TOPPADDING", (0, 0), (0, 0), 14),
            ("BOTTOMPADDING", (0, -1), (0, -1), 14),
            ("TOPPADDING", (0, 1), (0, 1), 2),
            ("BOTTOMPADDING", (0, 0), (0, 0), 2),
        ]))
        story.append(cover)
        story.append(Spacer(1, 12))

        story.append(Paragraph("Report Index", styles["AlertTitle"]))
        toc_rows = []
        for index, report in enumerate(reports, start=1):
            alert = report.get("alert") or {}
            risk = report.get("risk") or {}
            toc_rows.append([
                str(index),
                _plain(alert.get("rule"), 80),
                badge_flowable(
                    risk.get("elastic_severity") or alert.get("severity")
                ),
                badge_flowable(risk.get("overall_risk") or "UNKNOWN"),
                _plain(risk.get("risk_score_label")),
                _plain(alert.get("host")),
            ])
        story.append(data_table(
            ["#", "Rule", "Elastic Sev", "Risk", "Score", "Host"],
            toc_rows,
            widths=[
                usable * 0.05,
                usable * 0.32,
                usable * 0.16,
                usable * 0.16,
                usable * 0.14,
                usable * 0.17,
            ],
        ))
        story.append(PageBreak())

        for index, report in enumerate(reports, start=1):
            alert = report.get("alert") or {}
            risk = report.get("risk") or {}
            summary = report.get("summary") or {}
            ti = report.get("threat_intelligence") or {}
            iocs = ti.get("iocs") or {}
            inv = report.get("investigation") or {}
            counts = inv.get("counts") or {}
            persistence = inv.get("persistence") or {}
            mitre = report.get("mitre") or {}
            timeline = report.get("timeline") or {}
            tree_obj = inv.get("process_tree") or {}
            tree = tree_obj.get("display_ascii")
            if not tree:
                # Fallback: convert Unicode box-drawing to ASCII arrows
                raw = tree_obj.get("display") or "No process tree"
                tree = (
                    raw.replace("└──", "+-->")
                    .replace("├──", "+-->")
                    .replace("│", "|")
                    .replace("\u2500", "-")
                    .replace("\u2514", "+")
                    .replace("\u251c", "+")
                )

            elastic_sev = (
                risk.get("elastic_severity") or alert.get("severity")
            )
            overall = risk.get("overall_risk") or "UNKNOWN"
            disposition = summary.get("disposition") or "-"

            story.append(Paragraph(
                f"{index}. {_esc(alert.get('rule') or 'Alert')}",
                styles["AlertTitle"],
            ))

            story.extend(section(
                "Executive Summary",
                summary_box(summary.get("executive_summary")),
                Spacer(1, 4),
                kv_table([
                    ("Disposition", badge_flowable(disposition)),
                    ("Overall Risk", badge_flowable(overall)),
                    ("Risk Score", risk.get("risk_score_label")),
                ]),
            ))

            story.extend(section(
                "Alert Overview",
                kv_table([
                    ("Rule", alert.get("rule")),
                    ("Elastic Severity", badge_flowable(elastic_sev)),
                    ("Overall Risk", badge_flowable(overall)),
                    ("Risk Score", risk.get("risk_score_label")),
                    ("Recommendation", risk.get("recommendation")),
                    ("Disposition", badge_flowable(disposition)),
                    ("Timestamp", alert.get("timestamp")),
                    ("Host", alert.get("host")),
                    ("User", alert.get("user")),
                    (
                        "Process",
                        f"{alert.get('process')} "
                        f"(pid={alert.get('process_pid')})",
                    ),
                    ("Parent", alert.get("parent_process")),
                    ("Command Line", alert.get("command_line")),
                    ("Elastic Reason", alert.get("reason")),
                ]),
            ))

            story.extend(section(
                "Risk Score",
                kv_table([
                    ("Elastic Severity", badge_flowable(elastic_sev)),
                    ("Computed Score", risk.get("risk_score_label")),
                    ("Overall Risk", badge_flowable(overall)),
                    ("Recommendation", risk.get("recommendation")),
                ]),
                Paragraph("Score Reasons", styles["SubHead"]),
                bullet_list(risk.get("reasons") or []),
            ))

            mitre_rows = [
                [
                    item.get("id"),
                    item.get("tactic"),
                    item.get("name"),
                    _plain(item.get("evidence"), 200),
                ]
                for item in (mitre.get("techniques") or [])
            ]
            story.extend(section(
                "MITRE ATT&CK",
                data_table(
                    ["ID", "Tactic", "Technique", "Evidence"],
                    mitre_rows,
                    widths=[
                        usable * 0.12,
                        usable * 0.18,
                        usable * 0.28,
                        usable * 0.42,
                    ],
                ),
            ))

            # Prefer ASCII tree so arrows render in PDF fonts
            tree_table = Table(
                [[Preformatted(
                    _plain(tree),
                    styles["TreePre"],
                    maxLineLength=95,
                )]],
                colWidths=[usable],
            )
            tree_table.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f1f5f9")),
                ("BOX", (0, 0), (-1, -1), 0.4, border),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.extend(section(
                "Attack Chain / Process Tree",
                tree_table,
            ))

            story.extend(section(
                "Threat Intelligence",
                kv_table([
                    ("VirusTotal (best)", ti.get("virustotal")),
                    ("VirusTotal IP", ti.get("virustotal_ip")),
                    ("VirusTotal Hash", ti.get("virustotal_hash")),
                    ("VirusTotal Domain", ti.get("virustotal_domain")),
                    ("VirusTotal URL", ti.get("virustotal_url")),
                    ("AbuseIPDB", ti.get("abuseipdb")),
                    ("Shodan", _plain(ti.get("shodan"), 300)),
                    ("Hybrid Analysis", ti.get("hybrid_analysis")),
                ]),
            ))

            story.extend(section(
                "IOC Summary",
                kv_table([
                    (
                        "Lookup IP",
                        iocs.get("lookup_ip") or alert.get("lookup_ip"),
                    ),
                    (
                        "Source IP",
                        iocs.get("source_ip") or alert.get("source_ip"),
                    ),
                    (
                        "Destination IP",
                        iocs.get("destination_ip")
                        or alert.get("destination_ip"),
                    ),
                    ("Related IPs", iocs.get("related_ips")),
                    ("Domain", iocs.get("domain") or alert.get("domain")),
                    ("URL", iocs.get("url") or alert.get("url")),
                    ("File Name", alert.get("file_name")),
                    ("File Path", alert.get("file_path")),
                    ("SHA256", alert.get("sha256")),
                    ("SHA1", alert.get("sha1")),
                    ("MD5", alert.get("md5")),
                    ("Public IPs", iocs.get("public_ips")),
                    ("Private IPs", iocs.get("private_ips")),
                ]),
            ))

            story.extend(section(
                "Investigation Findings",
                data_table(
                    ["Signal", "Count"],
                    [
                        ["Child Processes", counts.get("child_processes")],
                        ["File Creations", counts.get("file_creations")],
                        [
                            "File Modifications",
                            counts.get("file_modifications"),
                        ],
                        [
                            "Registry Changes",
                            counts.get("registry_changes"),
                        ],
                        [
                            "Network Connections",
                            counts.get("network_connections"),
                        ],
                        ["DNS Events", counts.get("dns_events")],
                        [
                            "Auth Events",
                            counts.get("authentication_events"),
                        ],
                        ["Services", counts.get("services")],
                        [
                            "Scheduled Tasks",
                            counts.get("scheduled_tasks"),
                        ],
                        [
                            "Persistence Registry",
                            _safe_len(
                                persistence.get("registry_persistence")
                            ),
                        ],
                        [
                            "Startup Folder",
                            _safe_len(persistence.get("startup_folder")),
                        ],
                        [
                            "WMI Persistence",
                            _safe_len(persistence.get("wmi_persistence")),
                        ],
                    ],
                    widths=[usable * 0.7, usable * 0.3],
                ),
            ))

            timeline_rows = [
                [
                    _plain(event.get("timestamp"), 40),
                    _plain(event.get("category"), 40),
                    _plain(event.get("action"), 40),
                    _plain(event.get("detail"), 500),
                ]
                for event in (timeline.get("events") or [])[:25]
            ]
            story.extend(section(
                "Timeline",
                P(
                    f"Showing up to 25 of "
                    f"{timeline.get('event_count', 0)} events",
                    "Muted",
                ),
                data_table(
                    ["Timestamp", "Category", "Action", "Detail"],
                    timeline_rows,
                    widths=[
                        usable * 0.18,
                        usable * 0.12,
                        usable * 0.14,
                        usable * 0.56,
                    ],
                ),
            ))

            provider = summary.get("provider") or "-"
            model = summary.get("model")
            provider_line = (
                f"{provider} ({model})" if model else provider
            )
            story.extend(section(
                "Analyst Assessment",
                P(f"Provider: {provider_line}"),
                Paragraph("Key Findings", styles["SubHead"]),
                bullet_list(summary.get("key_findings") or []),
            ))
            story.extend(section(
                "Recommended Actions",
                bullet_list(summary.get("recommended_actions") or []),
            ))

            if index < len(reports):
                story.append(PageBreak())

        doc = SimpleDocTemplate(
            output_path,
            pagesize=A4,
            leftMargin=18 * mm,
            rightMargin=18 * mm,
            topMargin=14 * mm,
            bottomMargin=14 * mm,
            title="SOC Investigation Report",
            author="Elastic Alert Analyzer",
        )
        doc.build(story)

        if (
            not os.path.exists(output_path)
            or os.path.getsize(output_path) < 100
        ):
            return False, "PDF file was empty after write"

        with open(output_path, "rb") as handle:
            if not handle.read(4).startswith(b"%PDF"):
                return False, "PDF renderer produced an invalid file"

        return True, None

    except Exception as exc:
        if os.path.exists(output_path):
            try:
                os.remove(output_path)
            except OSError:
                pass
        return False, str(exc)
