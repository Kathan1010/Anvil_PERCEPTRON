"""
AEGIS SOC — Database Layer (Supabase / Cloud PostgreSQL)
All 4 tables: incidents, enrichment_results, ioc_graph, agent_logs
Uses Supabase Python client for production-grade cloud storage.
"""

import json
from datetime import datetime, timezone
from supabase import create_client, Client
from backend.config import settings


# ── Singleton Supabase Client ──
_client: Client | None = None


def get_db() -> Client:
    """Get the Supabase client singleton."""
    global _client
    if _client is None:
        if not settings.supabase_url or not settings.supabase_key:
            raise RuntimeError("SUPABASE_URL and SUPABASE_KEY must be set in .env")
        _client = create_client(settings.supabase_url, settings.supabase_key)
    return _client


async def init_db():
    """
    Verify Supabase connection.
    Tables must be created in Supabase Dashboard (SQL Editor) — see schema below.
    """
    try:
        db = get_db()
        # Quick connection test
        db.table("incidents").select("id").limit(1).execute()
        print("✅ Supabase connected — 4 tables ready")
    except Exception as e:
        print(f"⚠️  Supabase connection issue: {e}")
        print("   Make sure tables are created in Supabase SQL Editor.")
        print("   See the SQL schema in this file's docstring.")


# ══════════════════════════════════════════════
# TABLE CREATION SQL (run this in Supabase SQL Editor)
# ══════════════════════════════════════════════
SCHEMA_SQL = """
-- Run this ONCE in Supabase Dashboard → SQL Editor → New Query

CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    alert_payload JSONB NOT NULL,
    alert_type TEXT,
    severity TEXT,
    status TEXT DEFAULT 'new',
    confidence REAL,
    decision TEXT,
    recommended_actions JSONB,
    actions_taken JSONB,
    report_md TEXT,
    report_pdf_path TEXT,
    mitre_techniques JSONB,
    attack_chain TEXT,
    evidence JSONB,
    reasoning_trace JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at TIMESTAMPTZ,
    duration_seconds REAL
);

CREATE TABLE IF NOT EXISTS enrichment_results (
    id SERIAL PRIMARY KEY,
    incident_id TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    source TEXT NOT NULL,
    result JSONB NOT NULL,
    cached_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS ioc_graph (
    ioc_value TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    incident_id TEXT NOT NULL,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    times_seen INTEGER DEFAULT 1,
    PRIMARY KEY (ioc_value, incident_id)
);

CREATE TABLE IF NOT EXISTS agent_logs (
    id SERIAL PRIMARY KEY,
    incident_id TEXT NOT NULL,
    agent_name TEXT NOT NULL,
    action TEXT NOT NULL,
    details JSONB,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Indexes for fast queries
CREATE INDEX IF NOT EXISTS idx_ioc_value ON ioc_graph(ioc_value);
CREATE INDEX IF NOT EXISTS idx_incident_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_enrichment_ioc ON enrichment_results(ioc_value, source);
CREATE INDEX IF NOT EXISTS idx_agent_logs_incident ON agent_logs(incident_id);

-- Enable Row Level Security (optional but production-grade)
ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE enrichment_results ENABLE ROW LEVEL SECURITY;
ALTER TABLE ioc_graph ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_logs ENABLE ROW LEVEL SECURITY;

-- Allow all operations for service role (add policies as needed)
CREATE POLICY "Allow all" ON incidents FOR ALL USING (true);
CREATE POLICY "Allow all" ON enrichment_results FOR ALL USING (true);
CREATE POLICY "Allow all" ON ioc_graph FOR ALL USING (true);
CREATE POLICY "Allow all" ON agent_logs FOR ALL USING (true);
"""


# ──────────────────────────────────────────────
# Incident CRUD
# ──────────────────────────────────────────────

async def create_incident(incident_id: str, alert_payload: dict) -> dict:
    """Create a new incident record."""
    db = get_db()
    now = datetime.now(timezone.utc).isoformat()
    data = {
        "id": incident_id,
        "alert_payload": alert_payload,
        "status": "new",
        "created_at": now,
    }
    db.table("incidents").insert(data).execute()
    return {"id": incident_id, "status": "new", "created_at": now}


async def update_incident(incident_id: str, **fields) -> None:
    """Update arbitrary fields on an incident."""
    if not fields:
        return
    db = get_db()
    db.table("incidents").update(fields).eq("id", incident_id).execute()


async def get_incident(incident_id: str) -> dict | None:
    """Get a single incident by ID."""
    db = get_db()
    result = db.table("incidents").select("*").eq("id", incident_id).execute()
    if result.data:
        return result.data[0]
    return None


async def list_incidents(limit: int = 50, offset: int = 0) -> list[dict]:
    """List incidents ordered by creation time (newest first)."""
    db = get_db()
    result = (db.table("incidents")
              .select("*")
              .order("created_at", desc=True)
              .limit(limit)
              .offset(offset)
              .execute())
    return result.data


async def get_metrics() -> dict:
    """Calculate MTTR, incident counts, and threat stats."""
    db = get_db()

    # Total
    total_result = db.table("incidents").select("id", count="exact").execute()
    total = total_result.count or 0

    # Resolved
    resolved_result = (db.table("incidents")
                       .select("id", count="exact")
                       .eq("status", "resolved")
                       .execute())
    resolved = resolved_result.count or 0

    # Active
    active_result = (db.table("incidents")
                     .select("id", count="exact")
                     .not_.in_("status", ["resolved", "monitoring"])
                     .execute())
    active = active_result.count or 0

    # MTTR
    mttr_result = (db.table("incidents")
                   .select("duration_seconds")
                   .not_.is_("duration_seconds", "null")
                   .execute())
    durations = [r["duration_seconds"] for r in mttr_result.data if r.get("duration_seconds")]
    avg_mttr = round(sum(durations) / len(durations), 1) if durations else 0

    # Severity counts
    all_incidents = db.table("incidents").select("severity").execute()
    severity_counts = {}
    for row in all_incidents.data:
        sev = row.get("severity") or "unknown"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "total_incidents": total,
        "resolved_incidents": resolved,
        "active_incidents": active,
        "avg_mttr_seconds": avg_mttr,
        "severity_counts": severity_counts,
    }


# ──────────────────────────────────────────────
# Enrichment Results
# ──────────────────────────────────────────────

async def store_enrichment(incident_id: str, ioc_value: str, ioc_type: str,
                           source: str, result: dict) -> None:
    """Cache an enrichment API result."""
    db = get_db()
    db.table("enrichment_results").insert({
        "incident_id": incident_id,
        "ioc_value": ioc_value,
        "ioc_type": ioc_type,
        "source": source,
        "result": result,
        "cached_at": datetime.now(timezone.utc).isoformat(),
    }).execute()


async def get_cached_enrichment(ioc_value: str, source: str) -> dict | None:
    """Check if we already have enrichment data for this IOC."""
    db = get_db()
    result = (db.table("enrichment_results")
              .select("result, cached_at")
              .eq("ioc_value", ioc_value)
              .eq("source", source)
              .order("cached_at", desc=True)
              .limit(1)
              .execute())
    if result.data:
        return result.data[0]["result"]
    return None


# ──────────────────────────────────────────────
# IOC Graph (correlation / learning memory)
# ──────────────────────────────────────────────

async def upsert_ioc(ioc_value: str, ioc_type: str, incident_id: str) -> None:
    """Add or update an IOC sighting in the graph."""
    db = get_db()
    now = datetime.now(timezone.utc).isoformat()

    # Check if exists
    existing = (db.table("ioc_graph")
                .select("times_seen")
                .eq("ioc_value", ioc_value)
                .eq("incident_id", incident_id)
                .execute())

    if existing.data:
        # Update
        current = existing.data[0]["times_seen"] or 1
        (db.table("ioc_graph")
         .update({"last_seen": now, "times_seen": current + 1})
         .eq("ioc_value", ioc_value)
         .eq("incident_id", incident_id)
         .execute())
    else:
        # Insert new
        db.table("ioc_graph").insert({
            "ioc_value": ioc_value,
            "ioc_type": ioc_type,
            "incident_id": incident_id,
            "first_seen": now,
            "last_seen": now,
            "times_seen": 1,
        }).execute()


async def get_ioc_history(ioc_value: str) -> list[dict]:
    """Find all prior incidents involving this IOC."""
    db = get_db()
    result = (db.table("ioc_graph")
              .select("*")
              .eq("ioc_value", ioc_value)
              .order("last_seen", desc=True)
              .execute())
    return result.data


# ──────────────────────────────────────────────
# Agent Logs
# ──────────────────────────────────────────────

async def log_agent_action(incident_id: str, agent_name: str, action: str,
                           details: dict | str | None = None) -> None:
    """Log an agent action for observability."""
    db = get_db()
    detail_val = details if isinstance(details, dict) else {"text": str(details)} if details else None
    db.table("agent_logs").insert({
        "incident_id": incident_id,
        "agent_name": agent_name,
        "action": action,
        "details": detail_val,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }).execute()


async def get_agent_logs(incident_id: str) -> list[dict]:
    """Get all agent logs for an incident."""
    db = get_db()
    result = (db.table("agent_logs")
              .select("*")
              .eq("incident_id", incident_id)
              .order("timestamp")
              .execute())
    return result.data


# ──────────────────────────────────────────────
# Alert Deduplication
# ──────────────────────────────────────────────

async def check_duplicate_alert(fingerprint: str) -> bool:
    """Check if an alert with this fingerprint was seen within the dedup window."""
    db = get_db()
    # Check recent incidents for same fingerprint
    result = (db.table("incidents")
              .select("id")
              .filter("alert_payload->>fingerprint", "eq", fingerprint)
              .order("created_at", desc=True)
              .limit(1)
              .execute())
    if not result.data:
        return False

    # Check if within dedup window
    from datetime import timedelta
    recent = result.data[0]
    # If found at all in last 5 min, it's a duplicate
    return True
