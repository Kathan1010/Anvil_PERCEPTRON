"""
AEGIS SOC — AbuseIPDB Tool
Check IP abuse history. Free tier: 1,000 checks/day.
"""
import aiohttp
from backend.config import settings

API_URL = "https://api.abuseipdb.com/api/v2/check"


async def check_ip(ip: str, max_age_days: int = 90) -> dict:
    """Check an IP address against AbuseIPDB."""
    if not settings.abuseipdb_api_key:
        return {"error": "ABUSEIPDB_API_KEY not configured",
                "abuse_confidence_score": 0, "total_reports": 0}

    headers = {
        "Key": settings.abuseipdb_api_key,
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": str(max_age_days),
    }

    async with aiohttp.ClientSession() as session:
        async with session.get(API_URL, headers=headers, params=params,
                               timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                result = await resp.json()
                data = result.get("data", {})
                return {
                    "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                    "total_reports": data.get("totalReports", 0),
                    "country": data.get("countryCode", "unknown"),
                    "isp": data.get("isp", "unknown"),
                    "usage_type": data.get("usageType", "unknown"),
                    "domain": data.get("domain", ""),
                    "is_tor": data.get("isTor", False),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "last_reported_at": data.get("lastReportedAt", ""),
                }
            elif resp.status == 429:
                return {"error": "AbuseIPDB rate limit exceeded",
                        "abuse_confidence_score": 0, "total_reports": 0}
            else:
                text = await resp.text()
                return {"error": f"AbuseIPDB API error: HTTP {resp.status} — {text[:100]}",
                        "abuse_confidence_score": 0, "total_reports": 0}
