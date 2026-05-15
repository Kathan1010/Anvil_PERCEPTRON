"""AEGIS SOC — Tavily Threat Intel Search"""
from backend.config import settings

async def search_threat_intel(query: str) -> dict:
    if not settings.tavily_api_key:
        return {"error": "TAVILY_API_KEY not configured", "results_count": 0, "results": []}
    try:
        from tavily import TavilyClient
        client = TavilyClient(api_key=settings.tavily_api_key)
        response = client.search(query=query, search_depth="basic", max_results=5)
        results = response.get("results", [])
        return {
            "results_count": len(results),
            "results": [{"title": r.get("title",""), "url": r.get("url",""),
                         "content": r.get("content","")[:300]} for r in results],
            "query": query,
        }
    except Exception as e:
        return {"error": str(e), "results_count": 0, "results": []}
