"""
AEGIS SOC — Decision Agent
Confidence-gated routing with hardcoded safety guardrails.
"""
import ipaddress
from backend.agents.state import SOCState
from backend.agents.llm import call_llm_json, broadcast_agent, broadcast_status, sanitize_for_prompt
from backend.database import update_incident
from backend.config import settings


def is_protected_ip(ip: str) -> bool:
    """Check if an IP falls within protected internal ranges."""
    try:
        addr = ipaddress.ip_address(ip)
        for network_str in settings.protected_networks:
            if addr in ipaddress.ip_network(network_str):
                return True
    except ValueError:
        pass
    return False


async def decision_node(state: SOCState) -> SOCState:
    """DECISION AGENT — confidence-gated action routing with safety checks."""
    incident_id = state["incident_id"]
    confidence = state.get("confidence", 0.5)
    severity = state.get("severity", "medium")
    iocs = state.get("extracted_iocs", [])

    await broadcast_status(incident_id, "deciding")
    await broadcast_agent(incident_id, "decision", "⚖️ Decision Agent activated — evaluating response...")

    # ── Step 1: LLM recommends actions ──
    llm_decision = await call_llm_json(
        prompt=f"""Based on this security incident, recommend response actions:

Alert Type: {state.get('alert_type', 'unknown')}
Severity: {severity}
Confidence: {confidence}
Attack Chain: {sanitize_for_prompt(state.get('attack_chain', 'unknown'))}
MITRE Techniques: {[t.get('id','') for t in state.get('mitre_techniques', [])]}
IOCs: {[i['value'] for i in iocs[:5]]}
Prior Sightings: {len(state.get('ioc_correlations', []))} IOCs seen before

Available actions: block_ip, slack_alert, create_ticket, escalate, isolate_host, disable_account

Respond with JSON:
{{
    "recommended_actions": ["action1", "action2"],
    "reasoning": "Why these actions are appropriate"
}}""",
        system_instruction="You are a SOC decision-maker. Recommend proportional response actions. Always include slack_alert. For high-confidence threats, include block_ip. For critical, add escalate."
    )

    recommended = llm_decision.get("recommended_actions", ["slack_alert"])
    reasoning = llm_decision.get("reasoning", "")

    # Ensure slack_alert is always included
    if "slack_alert" not in recommended:
        recommended.insert(0, "slack_alert")

    await broadcast_agent(incident_id, "decision",
        f"📋 Recommended: {', '.join(recommended)} | Reasoning: {reasoning[:100]}",
        {"recommended_actions": recommended, "reasoning": reasoning})

    # ── Step 2: Safety checks (HARDCODED, not prompt-based) ──
    destructive = set(settings.destructive_actions)
    has_destructive = bool(set(recommended) & destructive)

    # Check for protected IPs
    target_ips = [i["value"] for i in iocs if i["type"] == "ip"]
    protected_targets = [ip for ip in target_ips if is_protected_ip(ip)]

    if protected_targets:
        # Remove destructive actions targeting internal infra
        recommended = [a for a in recommended if a not in destructive]
        recommended.append("escalate")
        await broadcast_agent(incident_id, "decision",
            f"🛡️ SAFETY: Protected IPs detected ({', '.join(protected_targets)}) — destructive actions blocked, escalating",
            {"protected_ips": protected_targets})

    # ── Step 3: Confidence-gated decision ──
    if confidence >= settings.auto_remediate_threshold and not protected_targets:
        decision = "auto_remediate"
        awaiting_approval = False
        await broadcast_agent(incident_id, "decision",
            f"🟢 AUTO-REMEDIATE — Confidence {confidence:.1%} ≥ {settings.auto_remediate_threshold:.0%} threshold",
            {"decision": decision, "confidence": confidence})
    elif confidence >= settings.approval_threshold:
        decision = "request_approval"
        awaiting_approval = True
        await broadcast_agent(incident_id, "decision",
            f"🟡 APPROVAL REQUIRED — Confidence {confidence:.1%} (between {settings.approval_threshold:.0%}–{settings.auto_remediate_threshold:.0%})",
            {"decision": decision, "confidence": confidence})
    else:
        decision = "monitor"
        awaiting_approval = False
        # Remove destructive actions for monitor-only
        recommended = [a for a in recommended if a not in destructive]
        if "slack_alert" not in recommended:
            recommended.append("slack_alert")
        await broadcast_agent(incident_id, "decision",
            f"🔵 MONITOR ONLY — Confidence {confidence:.1%} < {settings.approval_threshold:.0%} threshold",
            {"decision": decision, "confidence": confidence})

    # ── Update DB ──
    await update_incident(incident_id,
        decision=decision,
        recommended_actions=recommended,
        status="awaiting_approval" if awaiting_approval else "decided")

    status = "awaiting_approval" if awaiting_approval else "decided"
    if awaiting_approval:
        await broadcast_status(incident_id, "awaiting_approval")
        await broadcast_agent(incident_id, "decision",
            "⏳ Pipeline PAUSED — waiting for analyst approval on dashboard")

    return {**state, "decision": decision, "recommended_actions": recommended,
            "awaiting_approval": awaiting_approval, "status": status}
