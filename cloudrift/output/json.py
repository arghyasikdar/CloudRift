"""JSON report serialization."""

from __future__ import annotations

from pathlib import Path

from cloudrift.models.report import IntelligenceReport


def report_to_json(report: IntelligenceReport) -> str:
    """Serialize a report to formatted JSON."""

    return report.model_dump_json(indent=2)


def write_json_report(report: IntelligenceReport, path: Path) -> None:
    """Write a report to disk."""

    path.write_text(report_to_json(report), encoding="utf-8")
