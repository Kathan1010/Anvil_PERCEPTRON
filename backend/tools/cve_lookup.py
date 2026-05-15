"""
AEGIS SOC — CVE/NVD Lookup Tool
Uses the NVD API 2.0 (free, no API key required).
"""
import aiohttp

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


async def lookup_cve(cve_id: str) -> dict:
    """Look up a CVE by ID from the National Vulnerability Database."""
    params = {"cveId": cve_id}

    async with aiohttp.ClientSession() as session:
        async with session.get(NVD_URL, params=params,
                               timeout=aiohttp.ClientTimeout(total=15)) as resp:
            if resp.status == 200:
                data = await resp.json()
                vulns = data.get("vulnerabilities", [])
                if not vulns:
                    return {"error": f"CVE {cve_id} not found", "cvss_score": 0}

                cve_data = vulns[0].get("cve", {})

                # Extract CVSS score (try v3.1 first, then v3.0, then v2)
                cvss_score = 0
                severity = "unknown"
                metrics = cve_data.get("metrics", {})

                for version in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    metric_list = metrics.get(version, [])
                    if metric_list:
                        cvss_data = metric_list[0].get("cvssData", {})
                        cvss_score = cvss_data.get("baseScore", 0)
                        severity = cvss_data.get("baseSeverity", "unknown")
                        break

                # Extract description (English)
                descriptions = cve_data.get("descriptions", [])
                description = ""
                for desc in descriptions:
                    if desc.get("lang") == "en":
                        description = desc.get("value", "")
                        break

                # Extract references
                refs = cve_data.get("references", [])
                ref_urls = [r.get("url", "") for r in refs[:5]]

                return {
                    "id": cve_id,
                    "description": description[:500],
                    "cvss_score": cvss_score,
                    "severity": severity,
                    "references": ref_urls,
                    "published": cve_data.get("published", ""),
                    "last_modified": cve_data.get("lastModified", ""),
                }
            elif resp.status == 404:
                return {"error": f"CVE {cve_id} not found", "cvss_score": 0}
            else:
                return {"error": f"NVD API error: HTTP {resp.status}", "cvss_score": 0}
