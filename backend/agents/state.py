"""
AEGIS SOC — LangGraph Shared State
Every agent reads from and writes to this SOCState TypedDict.
LangGraph passes the full state between nodes automatically.
"""

from typing import TypedDict, Optional, Annotated
from langgraph.graph import add_messages


class SOCState(TypedDict):
    """
    Shared state for the entire SOC incident pipeline.
    Each agent reads what it needs and writes its outputs.
    """

    # ── Identity ──
    incident_id: str
    alert_payload: dict
    alert_type: str                           # "suspicious_ip", "malware_hash", "phishing", "cve"
    created_at: str

    # ── Triage Output ──
    severity: str                              # "critical", "high", "medium", "low"
    urgency: str                               # "immediate", "soon", "routine"
    enrichment_path: list[str]                 # Which enrichment agents to invoke
    extracted_iocs: list[dict]                 # [{type: "ip", value: "1.2.3.4"}, ...]

    # ── Enrichment Outputs (populated in parallel) ──
    vt_results: Optional[dict]                 # VirusTotal response
    abuse_results: Optional[dict]              # AbuseIPDB response
    cve_results: Optional[dict]                # NVD/CVE response
    threat_intel: Optional[dict]               # Tavily search results
    enrichment_errors: list[str]               # Track partial failures

    # ── Investigation Output ──
    mitre_techniques: list[dict]               # [{id, name, tactic, confidence}]
    attack_chain: Optional[str]                # Narrative of attack sequence
    ioc_correlations: list[dict]               # Prior incident matches from ioc_graph
    confidence: float                          # 0.0–1.0 overall confidence
    evidence: list[dict]                       # [{source, finding, weight}]
    reasoning_trace: list[dict]                # Step-by-step reasoning for transparency

    # ── Decision Output ──
    decision: str                              # "auto_remediate", "request_approval", "monitor"
    recommended_actions: list[str]             # ["block_ip", "slack_alert", "create_ticket"]
    awaiting_approval: bool                    # True = pipeline paused for human input

    # ── Remediation Output ──
    actions_taken: list[dict]                  # [{action, target, success, details, reversible}]
    remediation_status: str                    # "completed", "partial", "failed", "skipped"

    # ── Reporting Output ──
    report_md: Optional[str]                   # Full markdown incident report
    report_pdf_path: Optional[str]             # Path to generated PDF
    memory_updated: bool                       # Whether ioc_graph was updated

    # ── Meta ──
    status: str                                # Current pipeline stage
    agent_logs: list[dict]                     # In-memory log of all agent actions
    soul_constraints: str                      # Loaded from SOUL.md at pipeline start
