"""AEGIS SOC — Simulated Firewall (logs to DB, broadcasts visually)"""
import random
from datetime import datetime, timezone

_rule_counter = 1000

async def block_ip_address(ip: str) -> dict:
    global _rule_counter
    _rule_counter += 1
    return {
        "rule_id": _rule_counter,
        "action": "BLOCK",
        "target_ip": ip,
        "protocol": "ALL",
        "direction": "INBOUND",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "simulated": True,
    }

async def remove_rule(rule_id: int) -> dict:
    return {"rule_id": rule_id, "action": "REMOVED", "simulated": True}
