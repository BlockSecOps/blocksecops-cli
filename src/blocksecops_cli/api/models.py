"""Data models for BlockSecOps API responses."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


class VulnerabilitySeverity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class ScanStatus(str, Enum):
    """Scan status values."""
    PENDING = "pending"
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Vulnerability(BaseModel):
    """A security vulnerability finding."""
    id: UUID
    title: str
    description: str
    severity: VulnerabilitySeverity
    confidence: Optional[str] = None
    category: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None
    recommendation: Optional[str] = None
    references: List[str] = Field(default_factory=list)
    scanner_id: Optional[str] = None
    created_at: datetime


class Contract(BaseModel):
    """A smart contract."""
    id: UUID
    name: str
    address: Optional[str] = None
    network: str = "ethereum"
    language: str = "solidity"
    is_multi_file: bool = False
    file_count: int = 1
    lines_of_code: Optional[int] = None
    status: str
    created_at: datetime


class ScanResult(BaseModel):
    """Aggregated scan results."""
    total_vulnerabilities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    vulnerabilities: List[Vulnerability] = Field(default_factory=list)
    scanners_used: List[str] = Field(default_factory=list)
    duration_seconds: Optional[float] = None


class Scan(BaseModel):
    """A security scan."""
    id: UUID
    contract_id: UUID
    contract_name: Optional[str] = None
    status: ScanStatus
    progress: int = 0
    priority: int = 50
    scanners_requested: List[str] = Field(default_factory=list)
    scanners_completed: List[str] = Field(default_factory=list)
    result: Optional[ScanResult] = None
    error_message: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    created_at: datetime


class UploadResponse(BaseModel):
    """Response from file upload."""
    contract_id: UUID
    filename: str
    status: str
    message: str
    is_multi_file: bool = False
    file_count: int = 1


class UserInfo(BaseModel):
    """Current user information."""
    id: UUID
    email: str
    tier: str
    quota: Optional[Dict[str, Any]] = None
