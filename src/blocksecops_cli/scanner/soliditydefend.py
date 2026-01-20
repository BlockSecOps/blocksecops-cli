"""Execute SolidityDefend locally and transform results."""

import json
import subprocess
from pathlib import Path
from typing import Any

from .downloader import SolidityDefendDownloader


class ScannerError(Exception):
    """Error running local scanner."""
    pass


class SolidityDefendScanner:
    """Execute SolidityDefend locally and transform results."""

    def __init__(self):
        self.downloader = SolidityDefendDownloader()

    async def scan(self, path: Path, timeout: int = 600) -> dict:
        """
        Run SolidityDefend on a file or directory.

        Args:
            path: Path to contract file or directory
            timeout: Maximum scan time in seconds

        Returns:
            Raw scanner output as dict
        """
        # Ensure latest version is installed
        binary = await self.downloader.ensure_latest()

        # Run scanner
        try:
            result = subprocess.run(
                [str(binary), str(path), "-f", "json"],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise ScannerError(f"Scan timed out after {timeout} seconds")
        except FileNotFoundError:
            raise ScannerError(f"Scanner binary not found at {binary}")
        except Exception as e:
            raise ScannerError(f"Failed to run scanner: {e}")

        # Check for errors
        if result.returncode != 0 and not result.stdout:
            error_msg = result.stderr.strip() if result.stderr else f"Exit code {result.returncode}"
            raise ScannerError(f"Scanner failed: {error_msg}")

        # Parse output
        try:
            return json.loads(result.stdout)
        except json.JSONDecodeError as e:
            raise ScannerError(f"Failed to parse scanner output: {e}")

    def transform_results(self, raw: dict) -> list[dict[str, Any]]:
        """
        Transform SolidityDefend JSON output to API vulnerability format.

        Args:
            raw: Raw scanner output

        Returns:
            List of vulnerability dicts in API format
        """
        vulnerabilities = []

        for finding in raw.get("findings", []):
            vuln = {
                "vulnerability_type": finding.get("detector_id", "unknown"),
                "severity": self._normalize_severity(finding.get("severity", "info")),
                "title": self._format_title(finding.get("detector_id", "Unknown Issue")),
                "description": finding.get("message", ""),
                "scanner_id": "soliditydefend",
            }

            # Add location if available
            location = finding.get("location", {})
            if location.get("line"):
                vuln["line_number"] = location["line"]
            if location.get("file"):
                vuln["file_path"] = location["file"]
            if location.get("column"):
                vuln["column"] = location["column"]

            # Add code snippet if available
            if finding.get("code_snippet"):
                vuln["code_snippet"] = finding["code_snippet"]

            # Add recommendation if available
            if finding.get("fix_suggestion"):
                vuln["recommendation"] = finding["fix_suggestion"]

            # Add references if available
            if finding.get("references"):
                vuln["references"] = finding["references"]

            # Add confidence if available
            if finding.get("confidence"):
                vuln["confidence"] = finding["confidence"]

            # Add category if available
            if finding.get("category"):
                vuln["category"] = finding["category"]

            vulnerabilities.append(vuln)

        return vulnerabilities

    def _normalize_severity(self, severity: str) -> str:
        """Normalize severity to standard levels."""
        severity = severity.lower()
        severity_map = {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
            "info": "informational",
            "informational": "informational",
            "warning": "medium",
            "error": "high",
        }
        return severity_map.get(severity, "informational")

    def _format_title(self, detector_id: str) -> str:
        """Format detector ID as human-readable title."""
        return detector_id.replace("-", " ").replace("_", " ").title()

    def get_version(self) -> str | None:
        """Get installed SolidityDefend version."""
        return self.downloader.get_version()
