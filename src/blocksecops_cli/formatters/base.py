"""Base formatter interface."""

from abc import ABC, abstractmethod
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..api.models import Scan, ScanResult


class OutputFormat(str, Enum):
    """Available output formats."""
    TABLE = "table"
    JSON = "json"
    SARIF = "sarif"
    JUNIT = "junit"


class BaseFormatter(ABC):
    """Base class for output formatters."""

    @property
    @abstractmethod
    def format_name(self) -> str:
        """Return the format name."""
        pass

    @abstractmethod
    def format_scan(self, scan: "Scan", result: "ScanResult") -> str:
        """
        Format scan results for output.

        Args:
            scan: The scan object
            result: The scan results

        Returns:
            Formatted string output
        """
        pass

    @abstractmethod
    def format_summary(self, result: "ScanResult") -> str:
        """
        Format a summary of results.

        Args:
            result: The scan results

        Returns:
            Formatted summary string
        """
        pass


def get_formatter(format: OutputFormat) -> BaseFormatter:
    """Get the appropriate formatter for the output format."""
    from .json_formatter import JSONFormatter
    from .junit_formatter import JUnitFormatter
    from .sarif_formatter import SARIFFormatter
    from .table_formatter import TableFormatter

    formatters = {
        OutputFormat.TABLE: TableFormatter,
        OutputFormat.JSON: JSONFormatter,
        OutputFormat.SARIF: SARIFFormatter,
        OutputFormat.JUNIT: JUnitFormatter,
    }

    formatter_class = formatters.get(format, TableFormatter)
    return formatter_class()
