"""AEGIS SOC — Slack Webhook Notifier (Block Kit formatted)"""
import aiohttp, json
from backend.config import settings

async def send_slack_alert(incident_id: str, severity: str, alert_type: str,
                           confidence: float, attack_chain: str, decision: str,
                           actions: list) -> dict:
    if not settings.slack_webhook_url or settings.slack_webhook_url.startswith("https://hooks.slack.com/services/YOUR"):
        print(f"[SLACK STUB] {severity} | {alert_type} | {decision} | {incident_id[:8]}")
        return {"ok": True, "stub": True}

    color = {"critical": "#FF0000", "high": "#FF6600", "ESCALATION": "#FF0000"}.get(severity, "#FFCC00")
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": f"🛡️ AEGIS — {severity.upper()} Alert"}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Type:* {alert_type}"},
            {"type": "mrkdwn", "text": f"*Confidence:* {confidence:.0%}"},
            {"type": "mrkdwn", "text": f"*Decision:* {decision}"},
            {"type": "mrkdwn", "text": f"*Incident:* `{incident_id[:8]}`"},
        ]},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Attack Chain:* {attack_chain[:300]}"}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*Actions:* {', '.join(actions)}"}},
    ]
    payload = {"attachments": [{"color": color, "blocks": blocks}]}
    async with aiohttp.ClientSession() as session:
        async with session.post(settings.slack_webhook_url, json=payload, timeout=aiohttp.ClientTimeout(total=10)) as resp:
            return {"ok": resp.status == 200, "status": resp.status}
