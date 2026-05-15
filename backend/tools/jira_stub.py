"""AEGIS SOC — Jira Ticket Stub"""
import uuid
from datetime import datetime, timezone

_ticket_counter = 0

async def create_ticket(title: str, description: str, severity: str) -> dict:
    global _ticket_counter
    _ticket_counter += 1
    return {
        "ticket_id": f"AEGIS-{_ticket_counter:04d}",
        "title": title,
        "description": description[:500],
        "severity": severity,
        "status": "Open",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "simulated": True,
    }
