"""Local scanner module for running SolidityDefend locally."""

from .downloader import SolidityDefendDownloader
from .soliditydefend import SolidityDefendScanner

__all__ = ["SolidityDefendDownloader", "SolidityDefendScanner"]
