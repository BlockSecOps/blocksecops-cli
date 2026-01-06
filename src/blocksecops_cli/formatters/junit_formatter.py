"""JUnit XML formatter for CI/CD integration."""

import xml.etree.ElementTree as ET
from typing import Optional
from xml.dom import minidom

from ..api.models import Scan, ScanResult, VulnerabilitySeverity
from .base import BaseFormatter


class JUnitFormatter(BaseFormatter):
    """Format output as JUnit XML for CI/CD test reporting."""

    @property
    def format_name(self) -> str:
        return "junit"

    def format_scan(self, scan: Scan, result: ScanResult) -> str:
        """Format scan results as JUnit XML."""
        # Create root element
        testsuites = ET.Element("testsuites")
        testsuites.set("name", "BlockSecOps Security Scan")
        testsuites.set("tests", str(result.total_vulnerabilities or 1))
        testsuites.set("failures", str(result.critical_count + result.high_count))
        testsuites.set("errors", "0")

        if result.duration_seconds:
            testsuites.set("time", f"{result.duration_seconds:.3f}")

        # Create testsuite for each scanner
        scanners = result.scanners_used or ["blocksecops"]
        for scanner in scanners:
            scanner_vulns = [
                v for v in result.vulnerabilities if v.scanner_id == scanner
            ]

            testsuite = ET.SubElement(testsuites, "testsuite")
            testsuite.set("name", f"BlockSecOps - {scanner}")
            testsuite.set("tests", str(len(scanner_vulns) or 1))

            failures = sum(
                1
                for v in scanner_vulns
                if v.severity in (VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH)
            )
            testsuite.set("failures", str(failures))
            testsuite.set("errors", "0")

            if not scanner_vulns:
                # Add a passing test case if no vulnerabilities
                testcase = ET.SubElement(testsuite, "testcase")
                testcase.set("name", "No vulnerabilities found")
                testcase.set("classname", f"blocksecops.{scanner}")
            else:
                for vuln in scanner_vulns:
                    testcase = self._create_testcase(vuln, scanner)
                    testsuite.append(testcase)

        return self._prettify(testsuites)

    def format_summary(self, result: ScanResult) -> str:
        """Format a brief summary as JUnit XML."""
        testsuites = ET.Element("testsuites")
        testsuites.set("name", "BlockSecOps Security Summary")
        testsuites.set("tests", "1")

        failures = "1" if result.critical_count > 0 or result.high_count > 0 else "0"
        testsuites.set("failures", failures)
        testsuites.set("errors", "0")

        testsuite = ET.SubElement(testsuites, "testsuite")
        testsuite.set("name", "Security Scan Summary")
        testsuite.set("tests", "1")
        testsuite.set("failures", failures)
        testsuite.set("errors", "0")

        testcase = ET.SubElement(testsuite, "testcase")
        testcase.set("name", "Security Scan")
        testcase.set("classname", "blocksecops.summary")

        if result.critical_count > 0 or result.high_count > 0:
            failure = ET.SubElement(testcase, "failure")
            failure.set("type", "SecurityVulnerability")
            failure.set("message", f"Found {result.critical_count} critical and {result.high_count} high severity vulnerabilities")
            failure.text = self._build_summary_text(result)

        return self._prettify(testsuites)

    def _create_testcase(self, vuln, scanner: str) -> ET.Element:
        """Create a JUnit testcase element from a vulnerability."""
        testcase = ET.Element("testcase")

        # Use file path as classname if available
        classname = f"blocksecops.{scanner}"
        if vuln.file_path:
            # Convert file path to classname format
            path = vuln.file_path.replace("/", ".").replace("\\", ".")
            if path.startswith("."):
                path = path[1:]
            classname = path

        testcase.set("classname", classname)
        testcase.set("name", vuln.title)

        # Add location as system-out
        if vuln.file_path:
            location = vuln.file_path
            if vuln.line_number:
                location += f":{vuln.line_number}"
            system_out = ET.SubElement(testcase, "system-out")
            system_out.text = f"Location: {location}"

        # Critical and High are failures
        if vuln.severity in (VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH):
            failure = ET.SubElement(testcase, "failure")
            failure.set("type", vuln.severity.value.upper())
            failure.set("message", vuln.title)
            failure.text = self._build_failure_text(vuln)
        # Medium and Low are skipped (not failures but notable)
        elif vuln.severity in (VulnerabilitySeverity.MEDIUM, VulnerabilitySeverity.LOW):
            # Use system-err for warnings
            system_err = ET.SubElement(testcase, "system-err")
            system_err.text = self._build_failure_text(vuln)

        return testcase

    def _build_failure_text(self, vuln) -> str:
        """Build detailed failure text for a vulnerability."""
        lines = [
            f"Severity: {vuln.severity.value.upper()}",
            f"Confidence: {vuln.confidence or 'N/A'}",
            "",
            "Description:",
            vuln.description or vuln.title,
        ]

        if vuln.code_snippet:
            lines.extend(["", "Code:", vuln.code_snippet])

        if vuln.recommendation:
            lines.extend(["", "Recommendation:", vuln.recommendation])

        if vuln.references:
            lines.extend(["", "References:"])
            lines.extend([f"  - {ref}" for ref in vuln.references])

        return "\n".join(lines)

    def _build_summary_text(self, result: ScanResult) -> str:
        """Build summary text for the summary testcase."""
        lines = [
            "Vulnerability Summary:",
            f"  Total: {result.total_vulnerabilities}",
            f"  Critical: {result.critical_count}",
            f"  High: {result.high_count}",
            f"  Medium: {result.medium_count}",
            f"  Low: {result.low_count}",
            f"  Info: {result.info_count}",
        ]

        if result.scanners_used:
            lines.extend(["", "Scanners Used:", f"  {', '.join(result.scanners_used)}"])

        return "\n".join(lines)

    def _prettify(self, elem: ET.Element) -> str:
        """Return a pretty-printed XML string."""
        rough_string = ET.tostring(elem, encoding="unicode")
        reparsed = minidom.parseString(rough_string)
        return reparsed.toprettyxml(indent="  ")
