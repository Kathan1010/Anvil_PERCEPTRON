"""
AEGIS SOC — Reporting Agent
Generates incident report (markdown + PDF), updates IOC memory, calculates MTTR.
"""
import json
from datetime import datetime, timezone
from backend.agents.state import SOCState
from backend.agents.llm import call_llm_text, broadcast_agent, broadcast_status, sanitize_for_prompt
from backend.database import update_incident, upsert_ioc
from backend.tools.pdf_report import generate_pdf_report


async def reporting_node(state: SOCState) -> SOCState:
    """REPORTING AGENT — document everything and update institutional memory."""
    incident_id = state["incident_id"]

    await broadcast_status(incident_id, "reporting")
    await broadcast_agent(incident_id, "reporting", "📝 Reporting Agent activated — generating incident report...")

    # ── Step 1: Generate markdown report via LLM ──
    report_md = await _generate_report(state)
    await broadcast_agent(incident_id, "reporting", "📄 Incident report generated")

    # ── Step 2: Generate PDF ──
    pdf_path = None
    try:
        pdf_path = await generate_pdf_report(incident_id, report_md, state)
        await broadcast_agent(incident_id, "reporting", f"📋 PDF report saved: {pdf_path}")
    except Exception as e:
        await broadcast_agent(incident_id, "reporting", f"⚠️ PDF generation failed: {str(e)[:80]}")

    # ── Step 3: Update IOC graph (memory for future incidents) ──
    iocs = state.get("extracted_iocs", [])
    for ioc in iocs:
        await upsert_ioc(ioc["value"], ioc["type"], incident_id)
    await broadcast_agent(incident_id, "reporting",
        f"🧠 Memory updated — {len(iocs)} IOCs stored for future correlation")

    # ── Step 4: Calculate duration / MTTR ──
    created = state.get("created_at", "")
    now = datetime.now(timezone.utc)
    duration = None
    try:
        created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
        duration = round((now - created_dt).total_seconds(), 1)
    except (ValueError, TypeError):
        pass

    # ── Step 5: Update DB — mark resolved ──
    resolved_at = now.isoformat()
    final_status = "resolved" if state.get("decision") != "monitor" else "monitoring"

    await update_incident(incident_id,
        report_md=report_md,
        report_pdf_path=pdf_path,
        resolved_at=resolved_at,
        duration_seconds=duration,
        status=final_status)

    time_str = f"{duration:.0f}s" if duration else "unknown"
    await broadcast_agent(incident_id, "reporting",
        f"✅ Incident {final_status.upper()} — Total time: {time_str}",
        {"status": final_status, "duration": duration})
    await broadcast_status(incident_id, final_status)

    return {**state, "report_md": report_md, "report_pdf_path": pdf_path,
            "memory_updated": True, "status": final_status}


async def _generate_report(state: SOCState) -> str:
    """Generate a detailed incident report via LLM."""
    iocs = state.get("extracted_iocs", [])
    mitre = state.get("mitre_techniques", [])
    evidence = state.get("evidence", [])
    actions = state.get("actions_taken", [])

    report = await call_llm_text(
        prompt=f"""Generate a professional SOC incident report with these sections:

1. EXECUTIVE SUMMARY (2-3 sentences)
2. ALERT DETAILS (type, severity, source, timestamp)
3. INDICATORS OF COMPROMISE (table of IOCs)
4. ENRICHMENT FINDINGS (what VT, AbuseIPDB, CVE, Tavily found)
5. INVESTIGATION ANALYSIS (attack chain, confidence, MITRE techniques)
6. ACTIONS TAKEN (what was done, success/failure)
7. RECOMMENDATIONS (next steps)

Incident Data:
- ID: {state.get('incident_id', 'unknown')}
- Type: {state.get('alert_type', 'unknown')}
- Severity: {state.get('severity', 'unknown')}
- Confidence: {state.get('confidence', 0):.1%}
- Decision: {state.get('decision', 'unknown')}
- IOCs: {json.dumps([dict(type=i['type'], value=i['value']) for i in iocs[:10]])}
- Attack Chain: {sanitize_for_prompt(state.get('attack_chain', 'N/A'))}
- MITRE: {json.dumps([dict(id=t.get('id',''), name=t.get('name','')) for t in mitre[:5]])}
- Evidence: {json.dumps(evidence[:5])}
- Actions: {json.dumps(actions)}
- Prior IOC Sightings: {len(state.get('ioc_correlations', []))}

Format as clean markdown with headers, tables where appropriate.""",
        system_instruction="You are a senior SOC analyst writing a formal incident report. Be precise, factual, and professional."
    )
    return report
