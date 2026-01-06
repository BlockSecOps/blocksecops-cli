"""JSON formatter for machine-readable output."""

import json
from typing import Any, Dict

from ..api.models import Scan, ScanResult
from .base import BaseFormatter


class JSONFormatter(BaseFormatter):
    """Format output as JSON."""

    @property
    def format_name(self) -> str:
        return "json"

    def format_scan(self, scan: Scan, result: ScanResult) -> str:
        """Format scan results as JSON."""
        output: Dict[str, Any] = {
            "scan": {
                "id": str(scan.id),
                "contract_id": str(scan.contract_id),
                "status": scan.status.value,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            },
            "summary": {
                "total_vulnerabilities": result.total_vulnerabilities,
                "critical": result.critical_count,
                "high": result.high_count,
                "medium": result.medium_count,
                "low": result.low_count,
                "informational": result.info_count,
            },
            "scanners_used": result.scanners_used,
            "duration_seconds": result.duration_seconds,
            "vulnerabilities": [
                {
                    "id": str(v.id),
                    "title": v.title,
                    "description": v.description,
                    "severity": v.severity.value,
                    "confidence": v.confidence,
                    "category": v.category,
                    "file_path": v.file_path,
                    "line_number": v.line_number,
                    "code_snippet": v.code_snippet,
                    "recommendation": v.recommendation,
                    "references": v.references,
                    "scanner_id": v.scanner_id,
                }
                for v in result.vulnerabilities
            ],
        }

        return json.dumps(output, indent=2)

    def format_summary(self, result: ScanResult) -> str:
        """Format a brief summary as JSON."""
        summary = {
            "total_vulnerabilities": result.total_vulnerabilities,
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "low": result.low_count,
            "informational": result.info_count,
        }
        return json.dumps(summary, indent=2)
