"""
AEGIS SOC — Investigation Agent
Correlates all enrichment data into a unified threat assessment.
Deterministic scoring FIRST, then LLM synthesis, MITRE mapping, IOC correlation.
"""
import json
from backend.agents.state import SOCState
from backend.agents.llm import call_llm_json, call_llm_text, broadcast_agent, broadcast_status, sanitize_for_prompt
from backend.database import update_incident, get_ioc_history
from backend.mitre.mapper import map_to_mitre


def compute_threat_score(state: SOCState) -> float:
    """Deterministic threat score from enrichment data (0.0–1.0). Not LLM-dependent."""
    scores = []
    weights = []

    # VirusTotal score
    vt = state.get("vt_results") or {}
    for key, vt_data in vt.items():
        if isinstance(vt_data, dict):
            if "positives" in vt_data and "total" in vt_data and vt_data["total"] > 0:
                scores.append(vt_data["positives"] / vt_data["total"])
                weights.append(0.3)
            if "malicious_count" in vt_data:
                mc = min(vt_data["malicious_count"] / 20, 1.0)
                scores.append(mc)
                weights.append(0.3)

    # AbuseIPDB score
    abuse = state.get("abuse_results") or {}
    if isinstance(abuse, dict) and "abuse_confidence_score" in abuse:
        scores.append(abuse["abuse_confidence_score"] / 100.0)
        weights.append(0.25)

    # CVE CVSS score
    cve = state.get("cve_results") or {}
    if isinstance(cve, dict) and "cvss_score" in cve:
        scores.append(min(cve["cvss_score"] / 10.0, 1.0))
        weights.append(0.25)

    # IOC correlation boost (seen before = higher confidence)
    correlations = state.get("ioc_correlations", [])
    if correlations:
        scores.append(min(len(correlations) * 0.15, 1.0))
        weights.append(0.2)

    if not scores:
        return 0.5  # Default when no enrichment data

    weighted_sum = sum(s * w for s, w in zip(scores, weights))
    total_weight = sum(weights)
    return round(min(weighted_sum / total_weight, 1.0), 3)


async def investigation_node(state: SOCState) -> SOCState:
    """INVESTIGATION AGENT — correlate evidence, compute confidence, map MITRE."""
    incident_id = state["incident_id"]
    iocs = state.get("extracted_iocs", [])

    await broadcast_status(incident_id, "investigating")
    await broadcast_agent(incident_id, "investigation", "🧠 Investigation Agent activated — correlating evidence...")

    # ── Step 1: IOC Correlation (check prior incidents) ──
    all_correlations = []
    for ioc in iocs:
        history = await get_ioc_history(ioc["value"])
        # Exclude current incident
        prior = [h for h in history if h["incident_id"] != incident_id]
        if prior:
            all_correlations.append({
                "ioc": ioc["value"],
                "ioc_type": ioc["type"],
                "prior_incidents": prior,
                "times_seen_total": sum(h.get("times_seen", 1) for h in prior)
            })

    if all_correlations:
        await broadcast_agent(incident_id, "investigation",
            f"⚡ IOC correlation: {len(all_correlations)} IOCs seen in prior incidents!",
            {"correlations": all_correlations})
    else:
        await broadcast_agent(incident_id, "investigation", "🆕 No prior sightings — first encounter")

    # ── Step 2: Deterministic threat score ──
    state_with_corr = {**state, "ioc_correlations": all_correlations}
    threat_score = compute_threat_score(state_with_corr)
    await broadcast_agent(incident_id, "investigation",
        f"📊 Deterministic threat score: {threat_score:.1%}")

    # ── Step 3: MITRE ATT&CK mapping ──
    enrichment_summary = _build_enrichment_summary(state)
    mitre_techniques = await map_to_mitre(enrichment_summary, state.get("alert_type", "unknown"))
    if mitre_techniques:
        technique_str = ", ".join([f"{t['id']} {t['name']}" for t in mitre_techniques[:5]])
        await broadcast_agent(incident_id, "investigation",
            f"🎯 MITRE ATT&CK: {technique_str}", {"mitre": mitre_techniques})

    # ── Step 4: LLM synthesis — attack chain + evidence ──
    evidence_list = _build_evidence_list(state, all_correlations)

    llm_analysis = await call_llm_json(
        prompt=f"""Analyze this security incident and provide your assessment:

Alert Type: {state.get('alert_type', 'unknown')}
Severity: {state.get('severity', 'unknown')}
IOCs: {json.dumps([{"type": i["type"], "value": i["value"]} for i in iocs[:10]])}
Enrichment Summary: {sanitize_for_prompt(enrichment_summary)}
Prior IOC Sightings: {len(all_correlations)} IOCs seen before
Deterministic Score: {threat_score}
MITRE Techniques: {json.dumps([{"id": t["id"], "name": t["name"]} for t in mitre_techniques[:5]])}

Respond with JSON:
{{
    "attack_chain": "Narrative of the likely attack sequence (2-3 sentences)",
    "confidence_adjustment": 0.0,
    "reasoning_steps": [
        {{"step": 1, "analysis": "...", "conclusion": "..."}}
    ]
}}""",
        system_instruction="You are an expert SOC analyst. Provide attack chain analysis. confidence_adjustment should be between -0.1 and +0.1 to fine-tune the deterministic score."
    )

    attack_chain = llm_analysis.get("attack_chain", "Unable to determine attack chain")
    adjustment = max(-0.1, min(0.1, llm_analysis.get("confidence_adjustment", 0)))
    final_confidence = round(min(max(threat_score + adjustment, 0.0), 1.0), 3)
    reasoning = llm_analysis.get("reasoning_steps", [])

    await broadcast_agent(incident_id, "investigation",
        f"🧠 Final confidence: {final_confidence:.1%} | Attack: {attack_chain[:100]}...",
        {"confidence": final_confidence, "attack_chain": attack_chain})

    # ── Update DB ──
    await update_incident(incident_id,
        confidence=final_confidence,
        mitre_techniques=mitre_techniques,
        attack_chain=attack_chain,
        evidence=evidence_list,
        reasoning_trace=reasoning,
        status="investigated")

    await broadcast_agent(incident_id, "investigation", "✅ Investigation complete — passing to Decision Agent")

    return {**state,
        "confidence": final_confidence, "mitre_techniques": mitre_techniques,
        "attack_chain": attack_chain, "ioc_correlations": all_correlations,
        "evidence": evidence_list, "reasoning_trace": reasoning, "status": "investigated"}


def _build_enrichment_summary(state: SOCState) -> str:
    """Build a text summary of all enrichment results for the LLM."""
    parts = []
    vt = state.get("vt_results") or {}
    for key, data in vt.items():
        if isinstance(data, dict):
            parts.append(f"VirusTotal ({key}): {json.dumps(data)[:300]}")

    abuse = state.get("abuse_results")
    if abuse and isinstance(abuse, dict):
        parts.append(f"AbuseIPDB: score={abuse.get('abuse_confidence_score')}%, reports={abuse.get('total_reports')}")

    cve = state.get("cve_results")
    if cve and isinstance(cve, dict):
        parts.append(f"CVE: {cve.get('id','?')} CVSS={cve.get('cvss_score','?')}")

    intel = state.get("threat_intel")
    if intel and isinstance(intel, dict):
        parts.append(f"Threat Intel: {json.dumps(intel)[:300]}")

    return " | ".join(parts) if parts else "No enrichment data available"


def _build_evidence_list(state: SOCState, correlations: list) -> list[dict]:
    """Build structured evidence list from all sources."""
    evidence = []
    vt = state.get("vt_results") or {}
    for key, data in vt.items():
        if isinstance(data, dict):
            weight = 0.9 if data.get("positives", 0) > 10 or data.get("malicious_count", 0) > 5 else 0.5
            evidence.append({"source": f"VirusTotal ({key})", "finding": json.dumps(data)[:200], "weight": weight})

    abuse = state.get("abuse_results")
    if abuse and isinstance(abuse, dict):
        score = abuse.get("abuse_confidence_score", 0)
        evidence.append({"source": "AbuseIPDB", "finding": f"Abuse score: {score}%", "weight": score / 100.0})

    cve = state.get("cve_results")
    if cve and isinstance(cve, dict):
        cvss = cve.get("cvss_score", 0)
        evidence.append({"source": "NVD", "finding": f"CVSS: {cvss}", "weight": min(cvss / 10.0, 1.0)})

    if correlations:
        evidence.append({"source": "IOC Correlation",
            "finding": f"{len(correlations)} IOCs seen in prior incidents", "weight": 0.8})

    return evidence
