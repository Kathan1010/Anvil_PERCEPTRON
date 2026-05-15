"""
AEGIS SOC — Remediation Agent
Executes real side-effects: Slack alerts, firewall blocks, Jira tickets, escalations.
Each action logged with rollback info.
"""
from backend.agents.state import SOCState
from backend.agents.llm import broadcast_agent, broadcast_status
from backend.database import update_incident
from backend.tools.slack_notifier import send_slack_alert
from backend.tools.firewall import block_ip_address
from backend.tools.jira_stub import create_ticket
from backend.config import settings


async def remediation_node(state: SOCState) -> SOCState:
    """REMEDIATION AGENT — execute recommended actions with safety checks."""
    incident_id = state["incident_id"]
    decision = state.get("decision", "monitor")
    recommended = state.get("recommended_actions", [])
    iocs = state.get("extracted_iocs", [])

    await broadcast_status(incident_id, "remediating")
    await broadcast_agent(incident_id, "remediation",
        f"🔧 Remediation Agent activated — executing {len(recommended)} actions")

    if decision == "monitor":
        await broadcast_agent(incident_id, "remediation",
            "👁️ Monitor-only mode — skipping destructive actions, sending alert only")
        recommended = ["slack_alert"]

    actions_taken = []
    target_ips = [i["value"] for i in iocs if i["type"] == "ip"]
    primary_ip = target_ips[0] if target_ips else None

    for action in recommended:
        attempt = 0
        while attempt < settings.max_remediation_attempts:
            attempt += 1
            try:
                if action == "slack_alert":
                    result = await _execute_slack_alert(incident_id, state)
                    actions_taken.append(result)
                    break

                elif action == "block_ip" and primary_ip:
                    result = await _execute_block_ip(incident_id, primary_ip)
                    actions_taken.append(result)
                    break

                elif action == "create_ticket":
                    result = await _execute_create_ticket(incident_id, state)
                    actions_taken.append(result)
                    break

                elif action == "escalate":
                    result = await _execute_escalate(incident_id, state)
                    actions_taken.append(result)
                    break

                else:
                    await broadcast_agent(incident_id, "remediation",
                        f"⏭️ Skipping unknown action: {action}")
                    break

            except Exception as e:
                if attempt >= settings.max_remediation_attempts:
                    await broadcast_agent(incident_id, "remediation",
                        f"❌ {action} failed after {attempt} attempts: {str(e)[:80]}")
                    actions_taken.append({
                        "action": action, "success": False,
                        "details": f"Failed: {str(e)[:200]}", "reversible": False
                    })
                else:
                    await broadcast_agent(incident_id, "remediation",
                        f"⚠️ {action} attempt {attempt} failed, retrying...")

    # ── Determine overall status ──
    success_count = sum(1 for a in actions_taken if a.get("success"))
    total = len(actions_taken)

    if success_count == total and total > 0:
        rem_status = "completed"
    elif success_count > 0:
        rem_status = "partial"
    elif total == 0:
        rem_status = "skipped"
    else:
        rem_status = "failed"

    await broadcast_agent(incident_id, "remediation",
        f"✅ Remediation {rem_status} — {success_count}/{total} actions succeeded",
        {"actions_taken": actions_taken})

    await update_incident(incident_id, actions_taken=actions_taken, status="remediated")

    return {**state, "actions_taken": actions_taken,
            "remediation_status": rem_status, "status": "remediated"}


async def _execute_slack_alert(incident_id: str, state: SOCState) -> dict:
    """Send a Slack alert with incident details."""
    await broadcast_agent(incident_id, "remediation", "📢 Sending Slack alert...")
    try:
        await send_slack_alert(
            incident_id=incident_id,
            severity=state.get("severity", "unknown"),
            alert_type=state.get("alert_type", "unknown"),
            confidence=state.get("confidence", 0),
            attack_chain=state.get("attack_chain", ""),
            decision=state.get("decision", ""),
            actions=state.get("recommended_actions", []),
        )
        await broadcast_agent(incident_id, "remediation", "📢 Slack alert sent successfully")
        return {"action": "slack_alert", "success": True,
                "details": "Alert sent to Slack", "reversible": False}
    except Exception as e:
        await broadcast_agent(incident_id, "remediation", f"📢 Slack failed (non-critical): {str(e)[:60]}")
        return {"action": "slack_alert", "success": False,
                "details": f"Slack error: {str(e)[:100]}", "reversible": False}


async def _execute_block_ip(incident_id: str, ip: str) -> dict:
    """Block an IP via simulated firewall."""
    await broadcast_agent(incident_id, "remediation", f"🔒 Blocking IP: {ip}...")
    result = await block_ip_address(ip)
    rule_id = result.get("rule_id", "unknown")
    await broadcast_agent(incident_id, "remediation",
        f"🔒 IP {ip} BLOCKED — Rule #{rule_id}",
        {"blocked_ip": ip, "rule_id": rule_id})
    return {"action": "block_ip", "target": ip, "success": True,
            "details": f"Firewall rule #{rule_id} created",
            "reversible": True, "rollback_cmd": f"remove_rule({rule_id})"}


async def _execute_create_ticket(incident_id: str, state: SOCState) -> dict:
    """Create a Jira-style ticket stub."""
    await broadcast_agent(incident_id, "remediation", "🎫 Creating incident ticket...")
    ticket = await create_ticket(
        title=f"[AEGIS] {state.get('severity','').upper()} — {state.get('alert_type','')} — {incident_id[:8]}",
        description=state.get("attack_chain", "Security incident detected by AEGIS"),
        severity=state.get("severity", "medium"),
    )
    ticket_id = ticket.get("ticket_id", "AEGIS-???")
    await broadcast_agent(incident_id, "remediation", f"🎫 Ticket {ticket_id} created")
    return {"action": "create_ticket", "success": True,
            "details": f"Ticket {ticket_id}", "reversible": False}


async def _execute_escalate(incident_id: str, state: SOCState) -> dict:
    """Send priority escalation via Slack."""
    await broadcast_agent(incident_id, "remediation", "🚨 ESCALATING to senior analyst...")
    try:
        await send_slack_alert(
            incident_id=incident_id,
            severity="ESCALATION",
            alert_type=state.get("alert_type", "unknown"),
            confidence=state.get("confidence", 0),
            attack_chain=state.get("attack_chain", ""),
            decision="escalate",
            actions=["Requires senior analyst review"],
        )
        await broadcast_agent(incident_id, "remediation", "🚨 Escalation sent")
        return {"action": "escalate", "success": True,
                "details": "Escalated to senior analyst via Slack", "reversible": False}
    except Exception as e:
        return {"action": "escalate", "success": False,
                "details": f"Escalation failed: {str(e)[:100]}", "reversible": False}
