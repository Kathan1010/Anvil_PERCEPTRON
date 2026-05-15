"""
AEGIS SOC — VirusTotal API v3 Tool
Lookups: file hash, IP address, domain.
Rate limit: 4 req/min (free tier) — enforced via asyncio.sleep.
"""
import asyncio
import aiohttp
from backend.config import settings

BASE_URL = "https://www.virustotal.com/api/v3"
_last_request_time = 0
RATE_LIMIT_DELAY = 15  # seconds between requests (4/min)


async def _rate_limit():
    """Enforce VirusTotal rate limit."""
    global _last_request_time
    import time
    now = time.time()
    elapsed = now - _last_request_time
    if elapsed < RATE_LIMIT_DELAY:
        await asyncio.sleep(RATE_LIMIT_DELAY - elapsed)
    _last_request_time = time.time()


async def _vt_request(endpoint: str) -> dict:
    """Make a rate-limited GET request to VirusTotal API v3."""
    if not settings.virustotal_api_key:
        return {"error": "VIRUSTOTAL_API_KEY not configured", "positives": 0, "total": 0}

    await _rate_limit()
    headers = {"x-apikey": settings.virustotal_api_key}

    async with aiohttp.ClientSession() as session:
        async with session.get(f"{BASE_URL}{endpoint}", headers=headers, timeout=aiohttp.ClientTimeout(total=30)) as resp:
            if resp.status == 200:
                return await resp.json()
            elif resp.status == 404:
                return {"error": "Not found in VirusTotal database"}
            elif resp.status == 429:
                return {"error": "Rate limit exceeded — retry later"}
            else:
                return {"error": f"VT API error: HTTP {resp.status}"}


async def lookup_hash(file_hash: str) -> dict:
    """Look up a file hash (MD5/SHA-256) on VirusTotal."""
    raw = await _vt_request(f"/files/{file_hash}")
    if "error" in raw:
        return raw

    data = raw.get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    return {
        "positives": stats.get("malicious", 0),
        "total": sum(stats.values()) if stats else 0,
        "malware_family": data.get("popular_threat_classification", {}).get("suggested_threat_label", "unknown"),
        "scan_date": data.get("last_analysis_date", ""),
        "reputation": data.get("reputation", 0),
        "tags": data.get("tags", [])[:5],
        "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
    }


async def lookup_ip(ip: str) -> dict:
    """Look up an IP address on VirusTotal."""
    raw = await _vt_request(f"/ip_addresses/{ip}")
    if "error" in raw:
        return raw

    data = raw.get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    return {
        "malicious_count": stats.get("malicious", 0),
        "suspicious_count": stats.get("suspicious", 0),
        "reputation": data.get("reputation", 0),
        "country": data.get("country", "unknown"),
        "as_owner": data.get("as_owner", "unknown"),
        "asn": data.get("asn", 0),
        "permalink": f"https://www.virustotal.com/gui/ip-address/{ip}",
    }


async def lookup_domain(domain: str) -> dict:
    """Look up a domain on VirusTotal."""
    raw = await _vt_request(f"/domains/{domain}")
    if "error" in raw:
        return raw

    data = raw.get("data", {}).get("attributes", {})
    stats = data.get("last_analysis_stats", {})
    return {
        "malicious_count": stats.get("malicious", 0),
        "reputation": data.get("reputation", 0),
        "categories": data.get("categories", {}),
        "registrar": data.get("registrar", "unknown"),
        "creation_date": data.get("creation_date", ""),
        "permalink": f"https://www.virustotal.com/gui/domain/{domain}",
    }
