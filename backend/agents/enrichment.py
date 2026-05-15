"""
AEGIS SOC — Enrichment Agents
4 parallel sub-agents via asyncio.gather(). Partial failure tolerant.
"""
import asyncio
from backend.agents.state import SOCState
from backend.agents.llm import broadcast_agent, broadcast_status
from backend.database import update_incident, store_enrichment, get_cached_enrichment
from backend.tools.virustotal import lookup_hash, lookup_ip, lookup_domain
from backend.tools.abuseipdb import check_ip
from backend.tools.cve_lookup import lookup_cve
from backend.tools.threat_intel import search_threat_intel


async def _enrich_vt_ip(incident_id: str, ip: str) -> dict:
    await broadcast_agent(incident_id, "enrichment_vt", f"🌐 VirusTotal: Looking up IP {ip}...")
    cached = await get_cached_enrichment(ip, "virustotal")
    if cached:
        await broadcast_agent(incident_id, "enrichment_vt", f"📦 Cached result for {ip}")
        return cached
    result = await lookup_ip(ip)
    await store_enrichment(incident_id, ip, "ip", "virustotal", result)
    await broadcast_agent(incident_id, "enrichment_vt",
        f"🌐 VT IP: {result.get('malicious_count',0)} malicious | Rep: {result.get('reputation','?')}",
        {"source": "virustotal", "ioc": ip, "result": result})
    return result


async def _enrich_vt_hash(incident_id: str, h: str) -> dict:
    await broadcast_agent(incident_id, "enrichment_vt", f"🌐 VirusTotal: Looking up hash {h[:16]}...")
    cached = await get_cached_enrichment(h, "virustotal")
    if cached:
        return cached
    result = await lookup_hash(h)
    await store_enrichment(incident_id, h, "hash", "virustotal", result)
    await broadcast_agent(incident_id, "enrichment_vt",
        f"🦠 VT Hash: {result.get('positives',0)}/{result.get('total',0)} — {result.get('malware_family','?')}",
        {"source": "virustotal", "ioc": h, "result": result})
    return result


async def _enrich_vt_domain(incident_id: str, domain: str) -> dict:
    await broadcast_agent(incident_id, "enrichment_vt", f"🌐 VirusTotal: Looking up {domain}...")
    cached = await get_cached_enrichment(domain, "virustotal")
    if cached:
        return cached
    result = await lookup_domain(domain)
    await store_enrichment(incident_id, domain, "domain", "virustotal", result)
    await broadcast_agent(incident_id, "enrichment_vt",
        f"🌐 VT Domain: {result.get('malicious_count',0)} malicious flags",
        {"source": "virustotal", "ioc": domain, "result": result})
    return result


async def _enrich_abuse(incident_id: str, ip: str) -> dict:
    await broadcast_agent(incident_id, "enrichment_abuse", f"🛡️ AbuseIPDB: Checking {ip}...")
    cached = await get_cached_enrichment(ip, "abuseipdb")
    if cached:
        return cached
    result = await check_ip(ip)
    await store_enrichment(incident_id, ip, "ip", "abuseipdb", result)
    await broadcast_agent(incident_id, "enrichment_abuse",
        f"🛡️ AbuseIPDB: Score {result.get('abuse_confidence_score',0)}% | {result.get('total_reports',0)} reports",
        {"source": "abuseipdb", "ioc": ip, "result": result})
    return result


async def _enrich_cve(incident_id: str, cve_id: str) -> dict:
    await broadcast_agent(incident_id, "enrichment_cve", f"🔓 NVD: Looking up {cve_id}...")
    cached = await get_cached_enrichment(cve_id, "nvd")
    if cached:
        return cached
    result = await lookup_cve(cve_id)
    await store_enrichment(incident_id, cve_id, "cve", "nvd", result)
    await broadcast_agent(incident_id, "enrichment_cve",
        f"🔓 CVE: {cve_id} — CVSS {result.get('cvss_score','N/A')} ({result.get('severity','?')})",
        {"source": "nvd", "ioc": cve_id, "result": result})
    return result


async def _enrich_intel(incident_id: str, iocs: list[dict]) -> dict:
    primary = iocs[0] if iocs else {"type": "unknown", "value": "unknown"}
    await broadcast_agent(incident_id, "enrichment_intel",
        f"🔍 Tavily: Searching threat intel for {primary['value']}...")
    result = await search_threat_intel(f"{primary['type']} {primary['value']} threat intelligence")
    await broadcast_agent(incident_id, "enrichment_intel",
        f"🔍 Found {result.get('results_count',0)} sources", {"source": "tavily", "result": result})
    return result


async def parallel_enrichment_node(state: SOCState) -> SOCState:
    """ENRICHMENT NODE — runs all relevant sub-agents concurrently."""
    incident_id = state["incident_id"]
    path = state.get("enrichment_path", [])
    iocs = state.get("extracted_iocs", [])

    await broadcast_status(incident_id, "enriching")
    await broadcast_agent(incident_id, "enrichment",
        f"⚡ Parallel enrichment — {len(path)} agents activating")

    tasks, names = [], []
    ips = [i["value"] for i in iocs if i["type"] == "ip"]
    hashes = [i["value"] for i in iocs if i["type"] == "hash"]
    domains = [i["value"] for i in iocs if i["type"] == "domain"]
    cves = [i["value"] for i in iocs if i["type"] == "cve"]

    if "virustotal_ip" in path and ips:
        tasks.append(_enrich_vt_ip(incident_id, ips[0])); names.append("vt_ip")
    if "virustotal_hash" in path and hashes:
        tasks.append(_enrich_vt_hash(incident_id, hashes[0])); names.append("vt_hash")
    if "virustotal_domain" in path and domains:
        tasks.append(_enrich_vt_domain(incident_id, domains[0])); names.append("vt_domain")
    if "abuseipdb" in path and ips:
        tasks.append(_enrich_abuse(incident_id, ips[0])); names.append("abuseipdb")
    if "cve_lookup" in path and cves:
        tasks.append(_enrich_cve(incident_id, cves[0])); names.append("cve")
    if "threat_intel" in path:
        tasks.append(_enrich_intel(incident_id, iocs)); names.append("intel")

    results = await asyncio.gather(*tasks, return_exceptions=True)

    vt_results, abuse_results, cve_results, threat_intel = {}, {}, {}, {}
    errors = []

    for name, result in zip(names, results):
        if isinstance(result, Exception):
            errors.append(f"{name}: {result}")
            await broadcast_agent(incident_id, "enrichment", f"⚠️ {name} failed: {str(result)[:80]}")
        elif "vt" in name:
            vt_results[name] = result
        elif name == "abuseipdb":
            abuse_results = result
        elif name == "cve":
            cve_results = result
        elif name == "intel":
            threat_intel = result

    ok = len(tasks) - len(errors)
    await broadcast_agent(incident_id, "enrichment", f"✅ Enrichment done — {ok}/{len(tasks)} succeeded")
    await update_incident(incident_id, status="enriched")

    return {**state, "vt_results": vt_results or None, "abuse_results": abuse_results or None,
            "cve_results": cve_results or None, "threat_intel": threat_intel or None,
            "enrichment_errors": errors, "status": "enriched"}
