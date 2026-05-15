"""
AEGIS SOC — Pydantic Request/Response Models
Used by FastAPI endpoints for validation and serialization.
"""

from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime


# ──────────────────────────────────────────────
# Request Models
# ──────────────────────────────────────────────

class AlertPayload(BaseModel):
    """Incoming alert from any monitoring source (webhook)."""
    source: str = Field(..., description="Alert source (e.g., 'siem', 'crowdstrike', 'manual')")
    alert_type: Optional[str] = Field(None, description="Optional hint: 'suspicious_ip', 'malware_hash', etc.")
    title: str = Field(..., description="Short alert title")
    description: Optional[str] = Field(None, description="Detailed alert description")
    severity_hint: Optional[str] = Field(None, description="Optional severity from source")

    # IOC fields — at least one should be provided
    source_ip: Optional[str] = Field(None, description="Source IP address")
    destination_ip: Optional[str] = Field(None, description="Destination IP address")
    file_hash: Optional[str] = Field(None, description="MD5/SHA-256 file hash")
    domain: Optional[str] = Field(None, description="Suspicious domain")
    url: Optional[str] = Field(None, description="Suspicious URL")
    cve_id: Optional[str] = Field(None, description="CVE identifier (e.g., CVE-2024-1234)")
    email_sender: Optional[str] = Field(None, description="Phishing email sender")
    raw_log: Optional[str] = Field(None, description="Raw log snippet for context")

    # Metadata
    timestamp: Optional[str] = Field(None, description="When the alert was generated")
    hostname: Optional[str] = Field(None, description="Affected hostname")
    user: Optional[str] = Field(None, description="Affected user account")


class DemoTrigger(BaseModel):
    """Trigger a demo alert scenario."""
    scenario: str = Field(
        ...,
        description="Demo scenario name",
        examples=["suspicious_ip", "malware_hash", "phishing_email", "cve_exploit"]
    )


class ApprovalAction(BaseModel):
    """Human approval/rejection of a recommended action."""
    approved: bool = Field(..., description="True = approve, False = reject")
    analyst_notes: Optional[str] = Field(None, description="Optional analyst comments")


# ──────────────────────────────────────────────
# Response Models
# ──────────────────────────────────────────────

class IncidentSummary(BaseModel):
    """Brief incident info for list view."""
    id: str
    alert_type: Optional[str] = None
    severity: Optional[str] = None
    status: str
    confidence: Optional[float] = None
    decision: Optional[str] = None
    created_at: str
    resolved_at: Optional[str] = None
    duration_seconds: Optional[float] = None


class IncidentDetail(BaseModel):
    """Full incident detail including agent logs."""
    id: str
    alert_payload: dict
    alert_type: Optional[str] = None
    severity: Optional[str] = None
    status: str
    confidence: Optional[float] = None
    decision: Optional[str] = None
    recommended_actions: Optional[list] = None
    actions_taken: Optional[list] = None
    report_md: Optional[str] = None
    report_pdf_path: Optional[str] = None
    mitre_techniques: Optional[list] = None
    attack_chain: Optional[str] = None
    evidence: Optional[list] = None
    reasoning_trace: Optional[list] = None
    created_at: str
    resolved_at: Optional[str] = None
    duration_seconds: Optional[float] = None
    agent_logs: list[dict] = []


class MetricsResponse(BaseModel):
    """Dashboard metrics."""
    total_incidents: int
    resolved_incidents: int
    active_incidents: int
    avg_mttr_seconds: float
    severity_counts: dict


class AlertResponse(BaseModel):
    """Response after alert ingestion."""
    incident_id: str
    status: str
    message: str


class WebSocketMessage(BaseModel):
    """Message format sent over WebSocket to dashboard."""
    type: str = Field(..., description="Message type: agent_update, status_change, metric_update, error")
    incident_id: str
    agent: Optional[str] = None
    message: str
    data: Optional[dict] = None
    timestamp: str = Field(default_factory=lambda: datetime.now().isoformat())
