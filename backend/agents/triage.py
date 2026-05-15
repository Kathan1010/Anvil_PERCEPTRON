"""
AEGIS SOC — Triage Agent
First responder: classifies the incoming alert, extracts IOCs, determines severity,
and decides which enrichment agents to invoke.
"""

import re
from backend.agents.state import SOCState
from backend.agents.llm import call_llm_json, broadcast_agent, broadcast_status, sanitize_for_prompt
from backend.database import update_incident


# ── IOC extraction patterns ──
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
HASH_MD5 = re.compile(r'\b[a-fA-F0-9]{32}\b')
HASH_SHA256 = re.compile(r'\b[a-fA-F0-9]{64}\b')
DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')

# Domains to exclude (common false positives)
EXCLUDE_DOMAINS = {
    "virustotal.com", "abuseipdb.com", "nvd.nist.gov", "slack.com",
    "google.com", "github.com", "microsoft.com", "example.com",
}


def extract_iocs(alert: dict) -> list[dict]:
    """Extract all IOCs from the alert payload using regex + explicit fields."""
    iocs = []
    seen = set()

    def add_ioc(ioc_type: str, value: str):
        key = f"{ioc_type}:{value}"
        if key not in seen:
            seen.add(key)
            iocs.append({"type": ioc_type, "value": value})

    # ── From explicit fields ──
    if alert.get("source_ip"):
        add_ioc("ip", alert["source_ip"])
    if alert.get("destination_ip"):
        add_ioc("ip", alert["destination_ip"])
    if alert.get("file_hash"):
        add_ioc("hash", alert["file_hash"])
    if alert.get("domain"):
        add_ioc("domain", alert["domain"])
    if alert.get("cve_id"):
        add_ioc("cve", alert["cve_id"])
    if alert.get("email_sender"):
        add_ioc("email", alert["email_sender"])

    # ── From text fields (title, description, raw_log) ──
    text_fields = " ".join([
        str(alert.get("title", "")),
        str(alert.get("description", "")),
        str(alert.get("raw_log", "")),
    ])

    for ip in IP_PATTERN.findall(text_fields):
        # Skip localhost and private ranges in extraction (but don't filter them out completely)
        if not ip.startswith("0.") and not ip.startswith("255."):
            add_ioc("ip", ip)

    for h in HASH_SHA256.findall(text_fields):
        add_ioc("hash", h)
    for h in HASH_MD5.findall(text_fields):
        if len(h) == 32:  # Not a substring of a sha256
            add_ioc("hash", h)

    for domain in DOMAIN_PATTERN.findall(text_fields):
        if domain.lower() not in EXCLUDE_DOMAINS and "." in domain:
            add_ioc("domain", domain)

    for cve in CVE_PATTERN.findall(text_fields):
        add_ioc("cve", cve.upper())

    return iocs


def determine_enrichment_path(iocs: list[dict]) -> list[str]:
    """Decide which enrichment agents to invoke based on IOC types present."""
    path = []
    ioc_types = {ioc["type"] for ioc in iocs}

    if "ip" in ioc_types:
        path.extend(["virustotal_ip", "abuseipdb"])
    if "hash" in ioc_types:
        path.append("virustotal_hash")
    if "domain" in ioc_types:
        path.append("virustotal_domain")
    if "cve" in ioc_types:
        path.append("cve_lookup")

    # Always add threat intel search
    path.append("threat_intel")

    return path


async def triage_node(state: SOCState) -> SOCState:
    """
    TRIAGE AGENT — LangGraph node function.
    1. Extract IOCs from alert payload
    2. Classify severity via LLM
    3. Determine enrichment path
    4. Broadcast status to dashboard
    """
    incident_id = state["incident_id"]
    alert = state["alert_payload"]

    await broadcast_status(incident_id, "triaging")
    await broadcast_agent(incident_id, "triage", "🔍 Triage Agent activated — analyzing incoming alert...")

    # ── Step 1: Extract IOCs ──
    iocs = extract_iocs(alert)
    ioc_summary = ", ".join([f"{i['type']}:{i['value']}" for i in iocs[:5]])
    if len(iocs) > 5:
        ioc_summary += f" (+{len(iocs) - 5} more)"

    await broadcast_agent(
        incident_id, "triage",
        f"🔎 Extracted {len(iocs)} IOCs: {ioc_summary}",
        {"iocs": iocs}
    )

    # ── Step 2: LLM classification ──
    sanitized_title = sanitize_for_prompt(alert.get("title", "Unknown alert"))
    sanitized_desc = sanitize_for_prompt(alert.get("description", "No description"))

    classification = await call_llm_json(
        prompt=f"""Classify this security alert:

Title: {sanitized_title}
Description: {sanitized_desc}
IOCs found: {[{"type": i["type"], "value": i["value"]} for i in iocs]}
Source: {alert.get("source", "unknown")}
Severity hint from source: {alert.get("severity_hint", "none")}

Respond with JSON:
{{
    "severity": "critical|high|medium|low",
    "alert_type": "suspicious_ip|malware_hash|phishing|cve_exploit|brute_force|data_exfiltration|unknown",
    "urgency": "immediate|soon|routine",
    "reasoning": "one sentence explaining the classification"
}}""",
        system_instruction="You are a SOC Tier-1 analyst. Classify security alerts accurately based on the IOCs and context provided. Be conservative — when in doubt, classify higher severity."
    )

    severity = classification.get("severity", "medium")
    alert_type = classification.get("alert_type", alert.get("alert_type", "unknown"))
    urgency = classification.get("urgency", "soon")

    await broadcast_agent(
        incident_id, "triage",
        f"🎯 Classification: {severity.upper()} severity | Type: {alert_type} | Urgency: {urgency}",
        {"severity": severity, "alert_type": alert_type, "urgency": urgency,
         "reasoning": classification.get("reasoning", "")}
    )

    # ── Step 3: Determine enrichment path ──
    enrichment_path = determine_enrichment_path(iocs)
    await broadcast_agent(
        incident_id, "triage",
        f"📋 Enrichment plan: {', '.join(enrichment_path)}",
        {"enrichment_path": enrichment_path}
    )

    # ── Step 4: Update database ──
    await update_incident(
        incident_id,
        alert_type=alert_type,
        severity=severity,
        status="triaged"
    )

    await broadcast_agent(incident_id, "triage", f"✅ Triage complete — handing off to enrichment agents")

    # ── Return updated state ──
    return {
        **state,
        "severity": severity,
        "alert_type": alert_type,
        "urgency": urgency,
        "enrichment_path": enrichment_path,
        "extracted_iocs": iocs,
        "status": "triaged",
    }
