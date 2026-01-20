"""
Download and manage SolidityDefend binary from GitHub releases.
Always fetches latest release from: https://github.com/BlockSecOps/SolidityDefend
"""

import platform
import stat
from pathlib import Path
from typing import Optional

import httpx

from ..config import get_config_dir


GITHUB_REPO = "BlockSecOps/SolidityDefend"
GITHUB_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"


class DownloadError(Exception):
    """Error downloading SolidityDefend."""
    pass


class SolidityDefendDownloader:
    """Download and manage SolidityDefend binary from GitHub releases."""

    def __init__(self):
        self.install_dir = get_config_dir() / "bin"
        self.version_file = self.install_dir / ".soliditydefend_version"

    async def ensure_latest(self) -> Path:
        """
        Ensure latest SolidityDefend is installed, download if needed.

        Returns:
            Path to the SolidityDefend binary
        """
        try:
            latest = await self._get_latest_release()
            current = self._get_installed_version()

            if current != latest["tag_name"]:
                await self._download_release(latest)

            binary_path = self._get_binary_path()
            if not binary_path.exists():
                await self._download_release(latest)

            return binary_path
        except httpx.HTTPError as e:
            raise DownloadError(f"Failed to fetch release info: {e}")
        except Exception as e:
            raise DownloadError(f"Failed to ensure SolidityDefend: {e}")

    async def _get_latest_release(self) -> dict:
        """Fetch latest release info from GitHub API."""
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(
                GITHUB_API,
                headers={"Accept": "application/vnd.github+json"},
            )
            resp.raise_for_status()
            return resp.json()

    async def _download_release(self, release: dict) -> None:
        """Download appropriate binary for current platform."""
        platform_map = {
            ("linux", "x86_64"): "soliditydefend-linux-amd64",
            ("linux", "amd64"): "soliditydefend-linux-amd64",
            ("linux", "aarch64"): "soliditydefend-linux-arm64",
            ("linux", "arm64"): "soliditydefend-linux-arm64",
            ("darwin", "x86_64"): "soliditydefend-macos-amd64",
            ("darwin", "amd64"): "soliditydefend-macos-amd64",
            ("darwin", "arm64"): "soliditydefend-macos-arm64",
            ("darwin", "aarch64"): "soliditydefend-macos-arm64",
            ("windows", "x86_64"): "soliditydefend-windows-amd64.exe",
            ("windows", "amd64"): "soliditydefend-windows-amd64.exe",
        }

        system = platform.system().lower()
        machine = platform.machine().lower()
        asset_prefix = platform_map.get((system, machine))

        if not asset_prefix:
            raise DownloadError(
                f"Unsupported platform: {system}/{machine}. "
                f"Supported: Linux (amd64/arm64), macOS (amd64/arm64), Windows (amd64)"
            )

        # Find matching asset in release
        asset = None
        for a in release.get("assets", []):
            if asset_prefix in a["name"]:
                asset = a
                break

        if not asset:
            raise DownloadError(
                f"No binary found for {system}/{machine} in release {release['tag_name']}"
            )

        # Create install directory
        self.install_dir.mkdir(parents=True, exist_ok=True)
        binary_path = self._get_binary_path()

        # Download binary
        async with httpx.AsyncClient(timeout=300.0, follow_redirects=True) as client:
            resp = await client.get(asset["browser_download_url"])
            resp.raise_for_status()
            binary_path.write_bytes(resp.content)

        # Set executable permission on Unix
        if system != "windows":
            binary_path.chmod(binary_path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)

        # Save version
        self.version_file.write_text(release["tag_name"])

    def _get_binary_path(self) -> Path:
        """Get path to the SolidityDefend binary."""
        name = "soliditydefend.exe" if platform.system().lower() == "windows" else "soliditydefend"
        return self.install_dir / name

    def _get_installed_version(self) -> Optional[str]:
        """Get currently installed version, or None if not installed."""
        if self.version_file.exists():
            return self.version_file.read_text().strip()
        return None

    def get_version(self) -> Optional[str]:
        """Get the installed version string."""
        return self._get_installed_version()

    def is_installed(self) -> bool:
        """Check if SolidityDefend is installed."""
        return self._get_binary_path().exists()
