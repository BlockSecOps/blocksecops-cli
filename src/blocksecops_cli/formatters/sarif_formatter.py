"""SARIF formatter for CI/CD integration."""

import json
from typing import Any, Dict, List

from ..api.models import Scan, ScanResult, VulnerabilitySeverity
from .base import BaseFormatter


# SARIF severity mapping
SEVERITY_TO_SARIF_LEVEL = {
    VulnerabilitySeverity.CRITICAL: "error",
    VulnerabilitySeverity.HIGH: "error",
    VulnerabilitySeverity.MEDIUM: "warning",
    VulnerabilitySeverity.LOW: "note",
    VulnerabilitySeverity.INFO: "none",
}


class SARIFFormatter(BaseFormatter):
    """Format output as SARIF (Static Analysis Results Interchange Format)."""

    @property
    def format_name(self) -> str:
        return "sarif"

    def format_scan(self, scan: Scan, result: ScanResult) -> str:
        """Format scan results as SARIF."""
        sarif: Dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "BlockSecOps",
                            "version": "0.1.0",
                            "informationUri": "https://blocksecops.io",
                            "rules": self._build_rules(result),
                        }
                    },
                    "results": self._build_results(result),
                    "invocations": [
                        {
                            "executionSuccessful": scan.status == "completed",
                            "startTimeUtc": scan.started_at.isoformat() if scan.started_at else None,
                            "endTimeUtc": scan.completed_at.isoformat() if scan.completed_at else None,
                        }
                    ],
                }
            ],
        }

        return json.dumps(sarif, indent=2)

    def format_summary(self, result: ScanResult) -> str:
        """Format a brief summary as SARIF (minimal format)."""
        sarif: Dict[str, Any] = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "BlockSecOps",
                            "version": "0.1.0",
                        }
                    },
                    "results": [],
                    "properties": {
                        "totalVulnerabilities": result.total_vulnerabilities,
                        "criticalCount": result.critical_count,
                        "highCount": result.high_count,
                        "mediumCount": result.medium_count,
                        "lowCount": result.low_count,
                        "infoCount": result.info_count,
                    },
                }
            ],
        }

        return json.dumps(sarif, indent=2)

    def _build_rules(self, result: ScanResult) -> List[Dict[str, Any]]:
        """Build SARIF rules from vulnerabilities."""
        rules: Dict[str, Dict[str, Any]] = {}

        for vuln in result.vulnerabilities:
            rule_id = vuln.category or f"BSO-{vuln.id}"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": vuln.title,
                    "shortDescription": {"text": vuln.title},
                    "fullDescription": {"text": vuln.description or vuln.title},
                    "helpUri": vuln.references[0] if vuln.references else None,
                    "defaultConfiguration": {
                        "level": SEVERITY_TO_SARIF_LEVEL.get(vuln.severity, "warning")
                    },
                    "properties": {
                        "severity": vuln.severity.value,
                        "category": vuln.category,
                    },
                }

        return list(rules.values())

    def _build_results(self, result: ScanResult) -> List[Dict[str, Any]]:
        """Build SARIF results from vulnerabilities."""
        results = []

        for vuln in result.vulnerabilities:
            rule_id = vuln.category or f"BSO-{vuln.id}"

            sarif_result: Dict[str, Any] = {
                "ruleId": rule_id,
                "level": SEVERITY_TO_SARIF_LEVEL.get(vuln.severity, "warning"),
                "message": {"text": vuln.description or vuln.title},
                "locations": [],
            }

            # Add location if available
            if vuln.file_path:
                location: Dict[str, Any] = {
                    "physicalLocation": {
                        "artifactLocation": {"uri": vuln.file_path},
                    }
                }

                if vuln.line_number:
                    location["physicalLocation"]["region"] = {
                        "startLine": vuln.line_number,
                    }

                    if vuln.code_snippet:
                        location["physicalLocation"]["region"]["snippet"] = {
                            "text": vuln.code_snippet
                        }

                sarif_result["locations"].append(location)

            # Add fix recommendation
            if vuln.recommendation:
                sarif_result["fixes"] = [
                    {
                        "description": {"text": vuln.recommendation},
                    }
                ]

            # Add properties
            sarif_result["properties"] = {
                "confidence": vuln.confidence,
                "scanner": vuln.scanner_id,
            }

            results.append(sarif_result)

        return results
