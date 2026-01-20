"""HTTP client for BlockSecOps API."""

import asyncio
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from uuid import UUID

import httpx

from ..config import get_api_key, get_api_url
from .models import Contract, Scan, ScanResult, UploadResponse, UserInfo, Vulnerability


class APIError(Exception):
    """API request error."""

    def __init__(self, message: str, status_code: Optional[int] = None, response: Optional[str] = None):
        super().__init__(message)
        self.status_code = status_code
        self.response = response


class AuthenticationError(APIError):
    """Authentication failed."""
    pass


class BlockSecOpsClient:
    """HTTP client for interacting with the BlockSecOps API."""

    def __init__(
        self,
        api_url: Optional[str] = None,
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ):
        """
        Initialize the client.

        Args:
            api_url: API base URL (defaults to config/env)
            api_key: API key (defaults to config/env/keyring)
            timeout: Request timeout in seconds
        """
        self.api_url = (api_url or get_api_url()).rstrip("/")
        self.api_key = api_key or get_api_key()
        self.timeout = timeout

    def _get_headers(self) -> Dict[str, str]:
        """Get request headers with authentication."""
        headers = {
            "Accept": "application/json",
            "User-Agent": "blocksecops-cli/0.1.0",
        }
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        **kwargs: Any,
    ) -> Any:
        """Make an API request."""
        url = f"{self.api_url}{path}"
        headers = self._get_headers()

        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            response = await client.request(
                method,
                url,
                headers=headers,
                **kwargs,
            )

        if response.status_code == 401:
            raise AuthenticationError(
                "Authentication failed. Please run 'blocksecops auth login'.",
                status_code=401,
            )

        if response.status_code == 403:
            raise AuthenticationError(
                "Access denied. Check your API key permissions.",
                status_code=403,
            )

        if response.status_code >= 400:
            try:
                error_data = response.json()
                message = error_data.get("detail", response.text)
            except Exception:
                message = response.text

            raise APIError(
                f"API error: {message}",
                status_code=response.status_code,
                response=response.text,
            )

        if response.status_code == 204:
            return None

        return response.json()

    # =========================================================================
    # Authentication
    # =========================================================================

    async def whoami(self) -> UserInfo:
        """Get current user information."""
        data = await self._request("GET", "/api/v1/users/me")
        return UserInfo(**data)

    async def validate_api_key(self, api_key: str) -> bool:
        """Validate an API key."""
        old_key = self.api_key
        self.api_key = api_key
        try:
            await self.whoami()
            return True
        except AuthenticationError:
            return False
        finally:
            self.api_key = old_key

    # =========================================================================
    # File Upload
    # =========================================================================

    async def upload_file(
        self,
        file_path: Path,
        contract_name: Optional[str] = None,
        network: str = "ethereum",
    ) -> UploadResponse:
        """
        Upload a contract file for scanning.

        Args:
            file_path: Path to the contract file (.sol, .vy, .rs) or archive (.zip, .tar.gz)
            contract_name: Optional name for the contract
            network: Blockchain network (default: ethereum)

        Returns:
            UploadResponse with contract details
        """
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(file_path, "rb") as f:
            files = {"file": (file_path.name, f, "application/octet-stream")}
            data = {"network": network}
            if contract_name:
                data["contract_name"] = contract_name

            result = await self._request(
                "POST",
                "/api/v1/upload",
                files=files,
                data=data,
            )

        return UploadResponse(**result)

    # =========================================================================
    # Scanning
    # =========================================================================

    async def create_scan(
        self,
        contract_id: UUID,
        scanners: Optional[List[str]] = None,
        scan_source: str = "cli",
    ) -> Scan:
        """
        Create a new scan for a contract.

        Args:
            contract_id: Contract ID to scan
            scanners: Optional list of specific scanners to use
            scan_source: Source identifier (cli, vscode, jetbrains, neovim, github_actions, etc.)

        Returns:
            Scan object with scan details
        """
        payload: Dict[str, Any] = {
            "contract_id": str(contract_id),
            "scan_source": scan_source,
        }
        if scanners:
            payload["scanner_ids"] = scanners

        result = await self._request("POST", "/api/v1/scans", json=payload)
        return Scan(**result)

    async def get_scan(self, scan_id: UUID) -> Scan:
        """Get scan details by ID."""
        result = await self._request("GET", f"/api/v1/scans/{scan_id}")
        return Scan(**result)

    async def get_scan_results(self, scan_id: UUID) -> ScanResult:
        """Get scan results with all vulnerabilities."""
        result = await self._request("GET", f"/api/v1/scans/{scan_id}/results")

        # Parse vulnerabilities
        vulns = [Vulnerability(**v) for v in result.get("vulnerabilities", [])]

        return ScanResult(
            total_vulnerabilities=result.get("total_vulnerabilities", len(vulns)),
            critical_count=result.get("critical_count", 0),
            high_count=result.get("high_count", 0),
            medium_count=result.get("medium_count", 0),
            low_count=result.get("low_count", 0),
            info_count=result.get("info_count", 0),
            vulnerabilities=vulns,
            scanners_used=result.get("scanners_used", []),
            duration_seconds=result.get("duration_seconds"),
        )

    async def wait_for_scan(
        self,
        scan_id: UUID,
        poll_interval: float = 2.0,
        timeout: float = 600.0,
        progress_callback: Optional[callable] = None,
    ) -> Scan:
        """
        Wait for a scan to complete.

        Args:
            scan_id: Scan ID to wait for
            poll_interval: Seconds between status checks
            timeout: Maximum wait time in seconds
            progress_callback: Optional callback(scan) for progress updates

        Returns:
            Completed Scan object
        """
        start_time = time.time()

        while True:
            scan = await self.get_scan(scan_id)

            if progress_callback:
                progress_callback(scan)

            if scan.status in ("completed", "failed", "cancelled"):
                return scan

            if time.time() - start_time > timeout:
                raise TimeoutError(f"Scan timed out after {timeout}s")

            await asyncio.sleep(poll_interval)

    # =========================================================================
    # Contracts
    # =========================================================================

    async def get_contract(self, contract_id: UUID) -> Contract:
        """Get contract details by ID."""
        result = await self._request("GET", f"/api/v1/contracts/{contract_id}")
        return Contract(**result)

    async def list_contracts(
        self,
        skip: int = 0,
        limit: int = 50,
    ) -> List[Contract]:
        """List user's contracts."""
        result = await self._request(
            "GET",
            "/api/v1/contracts",
            params={"skip": skip, "limit": limit},
        )
        return [Contract(**c) for c in result.get("contracts", [])]

    async def delete_contract(self, contract_id: UUID) -> None:
        """Delete a contract."""
        await self._request("DELETE", f"/api/v1/contracts/{contract_id}")

    # =========================================================================
    # High-Level Operations
    # =========================================================================

    async def scan_file(
        self,
        file_path: Path,
        wait: bool = True,
        scanners: Optional[List[str]] = None,
        scan_source: str = "cli",
        progress_callback: Optional[callable] = None,
    ) -> tuple[Scan, Optional[ScanResult]]:
        """
        Upload and scan a file in one operation.

        Args:
            file_path: Path to the contract file
            wait: Whether to wait for scan completion
            scanners: Optional list of specific scanners
            scan_source: Source identifier (cli, vscode, jetbrains, neovim, github_actions, etc.)
            progress_callback: Optional callback for progress updates

        Returns:
            Tuple of (Scan, ScanResult or None)
        """
        # Upload
        upload = await self.upload_file(file_path)

        # Create scan
        scan = await self.create_scan(
            upload.contract_id,
            scanners=scanners,
            scan_source=scan_source,
        )

        if not wait:
            return scan, None

        # Wait for completion
        scan = await self.wait_for_scan(
            scan.id,
            progress_callback=progress_callback,
        )

        # Get results if completed
        result = None
        if scan.status == "completed":
            result = await self.get_scan_results(scan.id)

        return scan, result

    async def submit_local_results(
        self,
        scan_id: UUID,
        vulnerabilities: List[Dict[str, Any]],
    ) -> ScanResult:
        """
        Submit locally-generated scan results to the API.

        Args:
            scan_id: ID of the scan to submit results for
            vulnerabilities: List of vulnerability dicts from local scanner

        Returns:
            ScanResult with processed vulnerabilities
        """
        payload = {
            "scanner_id": "soliditydefend",
            "vulnerabilities": vulnerabilities,
            "status": "completed",
        }

        result = await self._request(
            "POST",
            f"/api/v1/scans/{scan_id}/results",
            json=payload,
        )

        # Parse response as ScanResult
        vulns = [Vulnerability(**v) for v in result.get("vulnerabilities", [])]

        return ScanResult(
            total_vulnerabilities=result.get("total_vulnerabilities", len(vulns)),
            critical_count=result.get("critical_count", 0),
            high_count=result.get("high_count", 0),
            medium_count=result.get("medium_count", 0),
            low_count=result.get("low_count", 0),
            info_count=result.get("info_count", 0),
            vulnerabilities=vulns,
            scanners_used=result.get("scanners_used", ["soliditydefend"]),
            duration_seconds=result.get("duration_seconds"),
        )
