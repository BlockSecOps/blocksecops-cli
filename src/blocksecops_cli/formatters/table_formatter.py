"""Rich table formatter for terminal output."""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text

from ..api.models import Scan, ScanResult, VulnerabilitySeverity
from .base import BaseFormatter


SEVERITY_COLORS = {
    VulnerabilitySeverity.CRITICAL: "red bold",
    VulnerabilitySeverity.HIGH: "orange1",
    VulnerabilitySeverity.MEDIUM: "yellow",
    VulnerabilitySeverity.LOW: "green",
    VulnerabilitySeverity.INFO: "blue",
}


class TableFormatter(BaseFormatter):
    """Format output as rich terminal tables."""

    def __init__(self):
        self.console = Console()

    @property
    def format_name(self) -> str:
        return "table"

    def format_scan(self, scan: Scan, result: ScanResult) -> str:
        """Format scan results as a rich table."""
        output_parts = []

        # Summary panel
        summary = self._create_summary_panel(scan, result)
        output_parts.append(summary)

        # Vulnerabilities table
        if result.vulnerabilities:
            vuln_table = self._create_vulnerabilities_table(result)
            output_parts.append(vuln_table)

        # Capture output as string
        with self.console.capture() as capture:
            for part in output_parts:
                self.console.print(part)
                self.console.print()

        return capture.get()

    def format_summary(self, result: ScanResult) -> str:
        """Format a brief summary."""
        lines = []

        if result.total_vulnerabilities == 0:
            lines.append("[green]No vulnerabilities found[/green]")
        else:
            lines.append(f"Found {result.total_vulnerabilities} vulnerabilities:")
            if result.critical_count:
                lines.append(f"  [red bold]Critical: {result.critical_count}[/red bold]")
            if result.high_count:
                lines.append(f"  [orange1]High: {result.high_count}[/orange1]")
            if result.medium_count:
                lines.append(f"  [yellow]Medium: {result.medium_count}[/yellow]")
            if result.low_count:
                lines.append(f"  [green]Low: {result.low_count}[/green]")
            if result.info_count:
                lines.append(f"  [blue]Info: {result.info_count}[/blue]")

        with self.console.capture() as capture:
            for line in lines:
                self.console.print(line)

        return capture.get()

    def _create_summary_panel(self, scan: Scan, result: ScanResult) -> Panel:
        """Create summary panel."""
        summary_text = Text()

        # Status
        status_color = "green" if scan.status == "completed" else "yellow"
        summary_text.append(f"Status: ", style="bold")
        summary_text.append(f"{scan.status.upper()}\n", style=status_color)

        # Severity counts
        summary_text.append(f"\nVulnerabilities: ", style="bold")
        summary_text.append(f"{result.total_vulnerabilities}\n")

        if result.total_vulnerabilities > 0:
            summary_text.append("  ")
            if result.critical_count:
                summary_text.append(f"{result.critical_count} Critical  ", style="red bold")
            if result.high_count:
                summary_text.append(f"{result.high_count} High  ", style="orange1")
            if result.medium_count:
                summary_text.append(f"{result.medium_count} Medium  ", style="yellow")
            if result.low_count:
                summary_text.append(f"{result.low_count} Low  ", style="green")
            if result.info_count:
                summary_text.append(f"{result.info_count} Info", style="blue")
            summary_text.append("\n")

        # Scanners
        if result.scanners_used:
            summary_text.append(f"\nScanners: ", style="bold")
            summary_text.append(", ".join(result.scanners_used))

        # Duration
        if result.duration_seconds:
            summary_text.append(f"\nDuration: ", style="bold")
            summary_text.append(f"{result.duration_seconds:.1f}s")

        return Panel(summary_text, title="Scan Summary", border_style="blue")

    def _create_vulnerabilities_table(self, result: ScanResult) -> Table:
        """Create vulnerabilities table."""
        table = Table(
            title="Vulnerabilities",
            show_header=True,
            header_style="bold",
        )

        table.add_column("Severity", width=10)
        table.add_column("Title", width=40)
        table.add_column("Location", width=30)
        table.add_column("Scanner", width=15)

        # Sort by severity
        severity_order = {
            VulnerabilitySeverity.CRITICAL: 0,
            VulnerabilitySeverity.HIGH: 1,
            VulnerabilitySeverity.MEDIUM: 2,
            VulnerabilitySeverity.LOW: 3,
            VulnerabilitySeverity.INFO: 4,
        }

        sorted_vulns = sorted(
            result.vulnerabilities,
            key=lambda v: severity_order.get(v.severity, 5)
        )

        for vuln in sorted_vulns:
            severity_style = SEVERITY_COLORS.get(vuln.severity, "white")

            # Location
            location = ""
            if vuln.file_path:
                location = vuln.file_path
                if vuln.line_number:
                    location += f":{vuln.line_number}"

            table.add_row(
                Text(vuln.severity.value.upper(), style=severity_style),
                vuln.title[:40],
                location[:30] if location else "-",
                vuln.scanner_id or "-",
            )

        return table
