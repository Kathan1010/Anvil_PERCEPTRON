"""
AEGIS SOC — Configuration
Pydantic Settings: loads all API keys, ports, model config, and confidence thresholds from .env
"""

from pydantic_settings import BaseSettings
from pydantic import Field
from pathlib import Path
import os


class Settings(BaseSettings):
    """Central configuration loaded from .env file."""

    # ── API Keys ──
    groq_api_key: str = Field(default="", description="Groq API key")
    virustotal_api_key: str = Field(default="", description="VirusTotal API v3 key")
    abuseipdb_api_key: str = Field(default="", description="AbuseIPDB API key")
    tavily_api_key: str = Field(default="", description="Tavily search API key")
    slack_webhook_url: str = Field(default="", description="Slack Incoming Webhook URL")

    # ── Server Config ──
    host: str = Field(default="0.0.0.0", description="Server bind address")
    port: int = Field(default=8000, description="Server port")
    cors_origins: list[str] = Field(
        default=["http://localhost:3000", "http://localhost:5173"],
        description="Allowed CORS origins"
    )

    # ── LLM Config ──
    groq_model: str = Field(default="llama-3.3-70b-versatile", description="Groq model name")
    llm_temperature: float = Field(default=0.1, description="LLM temperature (low = deterministic)")

    # ── Confidence Thresholds ──
    auto_remediate_threshold: float = Field(
        default=0.95,
        description="Confidence >= this → auto-remediate without human approval"
    )
    approval_threshold: float = Field(
        default=0.70,
        description="Confidence >= this (but < auto) → request human approval"
    )

    # ── Safety Limits ──
    max_remediation_attempts: int = Field(default=2, description="Max retries for remediation actions")
    dedup_window_seconds: int = Field(default=300, description="Alert dedup window (5 min)")

    # ── Supabase ──
    supabase_url: str = Field(default="", description="Supabase project URL")
    supabase_key: str = Field(default="", description="Supabase anon/service key")

    # ── Paths ──
    soul_path: str = Field(default="SOUL.md", description="Path to SOUL.md safety constraints")
    reports_dir: str = Field(default="reports", description="Directory for generated PDF reports")
    mitre_data_path: str = Field(
        default="data/mitre_techniques.json",
        description="Path to simplified MITRE ATT&CK data"
    )

    # ── Protected Networks (never auto-block) ──
    protected_networks: list[str] = Field(
        default=["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"],
        description="Internal IP ranges that must never be auto-blocked"
    )

    # ── Destructive Actions (require high confidence) ──
    destructive_actions: list[str] = Field(
        default=["block_ip", "isolate_host", "disable_account"],
        description="Actions that require >= auto_remediate_threshold OR human approval"
    )

    model_config = {
        "env_file": ".env",
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore",
    }

    def load_soul_constraints(self) -> str:
        """Load SOUL.md safety constraints at runtime."""
        soul_file = Path(self.soul_path)
        if soul_file.exists():
            return soul_file.read_text(encoding="utf-8")
        return "No SOUL.md found — operate with maximum caution."


# Singleton instance
settings = Settings()

# Ensure reports directory exists
os.makedirs(settings.reports_dir, exist_ok=True)
