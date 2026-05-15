"""
AEGIS SOC — FastAPI Main Server
All endpoints, WebSocket, CORS, and pipeline orchestration.
"""
import uuid, hashlib, json, asyncio
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from backend.config import settings
from backend.database import (
    init_db, create_incident, get_incident, list_incidents,
    update_incident, get_metrics, get_agent_logs, check_duplicate_alert
)
from backend.models import AlertPayload, DemoTrigger, ApprovalAction, AlertResponse
from backend.websocket.manager import manager
from backend.agents.graph import get_graph
from backend.agents.state import SOCState
from backend.agents.llm import broadcast_agent, broadcast_status
from backend.agents.remediation import remediation_node
from backend.agents.reporting import reporting_node
from backend.monitoring.alert_simulator import get_demo_alert, list_scenarios


# ── Active pipelines (for approval flow) ──
_pending_approvals: dict[str, SOCState] = {}
_pipeline_lock = None  # Will be initialized in lifespan


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Startup/shutdown lifecycle."""
    await init_db()
    print("🛡️  AEGIS SOC — Server ready")
    print(f"   Dashboard: http://localhost:{settings.port}")
    print(f"   API docs:  http://localhost:{settings.port}/docs")
    global _pipeline_lock
    _pipeline_lock = asyncio.Semaphore(3)
    yield
    print("🛡️  AEGIS SOC — Shutting down")


app = FastAPI(
    title="AEGIS SOC",
    description="Autonomous AI SOC Tier-1 Responder",
    version="1.0.0",
    lifespan=lifespan,
)

# ── CORS ──
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────
# Health
# ──────────────────────────────────────────────

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "aegis-soc", "timestamp": datetime.now(timezone.utc).isoformat()}


# ──────────────────────────────────────────────
# Alert Ingestion (Webhook)
# ──────────────────────────────────────────────

@app.post("/api/alert", response_model=AlertResponse)
async def ingest_alert(alert: AlertPayload):
    """Webhook endpoint — receives alert, triggers full agent pipeline."""
    # Deduplication check
    fingerprint = hashlib.sha256(
        f"{alert.alert_type}:{alert.source_ip}:{alert.file_hash}:{alert.domain}:{alert.source}".encode()
    ).hexdigest()

    if await check_duplicate_alert(fingerprint):
        return AlertResponse(incident_id="", status="duplicate",
                             message="Alert deduplicated — same IOC seen within 5 minutes")

    # Create incident
    incident_id = str(uuid.uuid4())
    alert_dict = alert.model_dump()
    alert_dict["fingerprint"] = fingerprint
    await create_incident(incident_id, alert_dict)

    # Run pipeline in background
    asyncio.create_task(_run_pipeline(incident_id, alert_dict))

    return AlertResponse(incident_id=incident_id, status="accepted",
                         message="Alert accepted — pipeline started")


# ──────────────────────────────────────────────
# Demo Trigger
# ──────────────────────────────────────────────

@app.post("/api/demo/trigger", response_model=AlertResponse)
async def trigger_demo(trigger: DemoTrigger):
    """Fire a pre-built demo alert scenario."""
    alert_dict = get_demo_alert(trigger.scenario)
    incident_id = str(uuid.uuid4())
    fingerprint = hashlib.sha256(json.dumps(alert_dict, sort_keys=True).encode()).hexdigest()
    alert_dict["fingerprint"] = fingerprint
    await create_incident(incident_id, alert_dict)
    asyncio.create_task(_run_pipeline(incident_id, alert_dict))
    return AlertResponse(incident_id=incident_id, status="accepted",
                         message=f"Demo '{trigger.scenario}' triggered")


@app.get("/api/demo/scenarios")
async def get_scenarios():
    return {"scenarios": list_scenarios()}


# ──────────────────────────────────────────────
# Incidents CRUD
# ──────────────────────────────────────────────

@app.get("/api/incidents")
async def get_incidents(limit: int = 50, offset: int = 0):
    incidents = await list_incidents(limit, offset)
    return {"incidents": incidents, "count": len(incidents)}


@app.get("/api/incidents/{incident_id}")
async def get_incident_detail(incident_id: str):
    incident = await get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    logs = await get_agent_logs(incident_id)
    incident["agent_logs"] = logs
    return incident


# ──────────────────────────────────────────────
# Human Approval
# ──────────────────────────────────────────────

@app.post("/api/incidents/{incident_id}/approve")
async def approve_incident(incident_id: str, action: ApprovalAction):
    """Human approves or rejects a pending action."""
    if incident_id not in _pending_approvals:
        raise HTTPException(status_code=404, detail="No pending approval for this incident")

    state = _pending_approvals.pop(incident_id)

    if action.approved:
        await broadcast_agent(incident_id, "decision", "✅ Analyst APPROVED — proceeding with remediation")
        await update_incident(incident_id, status="approved")
        # Resume pipeline: remediation → reporting
        asyncio.create_task(_resume_after_approval(incident_id, state))
        return {"status": "approved", "message": "Remediation initiated"}
    else:
        await broadcast_agent(incident_id, "decision",
            f"❌ Analyst REJECTED — {action.analyst_notes or 'no reason given'}")
        # Skip remediation, go to reporting with monitor status
        state_monitor = {**state, "decision": "monitor", "recommended_actions": ["slack_alert"]}
        asyncio.create_task(_resume_reporting_only(incident_id, state_monitor))
        return {"status": "rejected", "message": "Action rejected — monitoring only"}


# ──────────────────────────────────────────────
# Reports
# ──────────────────────────────────────────────

@app.get("/api/incidents/{incident_id}/report")
async def download_report(incident_id: str):
    incident = await get_incident(incident_id)
    if not incident or not incident.get("report_pdf_path"):
        raise HTTPException(status_code=404, detail="Report not available")
    return FileResponse(incident["report_pdf_path"],
                        filename=f"aegis_report_{incident_id[:8]}.pdf",
                        media_type="application/pdf")


# ──────────────────────────────────────────────
# Metrics
# ──────────────────────────────────────────────

@app.get("/api/metrics")
async def get_dashboard_metrics():
    return await get_metrics()


# ──────────────────────────────────────────────
# WebSocket
# ──────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Client can send subscription messages
            try:
                msg = json.loads(data)
                if msg.get("type") == "subscribe" and msg.get("incident_id"):
                    manager.subscribe_to_incident(websocket, msg["incident_id"])
            except json.JSONDecodeError:
                pass
    except WebSocketDisconnect:
        manager.disconnect(websocket)


# ──────────────────────────────────────────────
# Pipeline Orchestration
# ──────────────────────────────────────────────

async def _run_pipeline(incident_id: str, alert_payload: dict):
    """Run the full agent pipeline for an incident."""
    if _pipeline_lock is None:
        raise RuntimeError("Pipeline lock is not initialized")
    async with _pipeline_lock:
        try:
            soul = settings.load_soul_constraints()
            initial_state: SOCState = {
                "incident_id": incident_id,
                "alert_payload": alert_payload,
                "alert_type": alert_payload.get("alert_type", "unknown"),
                "created_at": datetime.now(timezone.utc).isoformat(),
                "severity": "", "urgency": "", "enrichment_path": [],
                "extracted_iocs": [],
                "vt_results": None, "abuse_results": None,
                "cve_results": None, "threat_intel": None,
                "enrichment_errors": [],
                "mitre_techniques": [], "attack_chain": None,
                "ioc_correlations": [], "confidence": 0.0,
                "evidence": [], "reasoning_trace": [],
                "decision": "", "recommended_actions": [],
                "awaiting_approval": False,
                "actions_taken": [], "remediation_status": "",
                "report_md": None, "report_pdf_path": None,
                "memory_updated": False,
                "status": "new", "agent_logs": [],
                "soul_constraints": soul,
            }

            graph = get_graph()
            final_state = await graph.ainvoke(initial_state)

            # If pipeline ended at awaiting_approval, store state for resume
            if final_state.get("awaiting_approval"):
                _pending_approvals[incident_id] = final_state

            # Send updated metrics
            metrics = await get_metrics()
            await manager.send_metric_update(metrics)

        except Exception as e:
            await manager.send_error(incident_id, str(e))
            await update_incident(incident_id, status="error")
            import traceback
            traceback.print_exc()


async def _resume_after_approval(incident_id: str, state: SOCState):
    """Resume pipeline after human approval: remediation → reporting."""
    try:
        state = await remediation_node(state)
        state = await reporting_node(state)
        metrics = await get_metrics()
        await manager.send_metric_update(metrics)
    except Exception as e:
        await manager.send_error(incident_id, str(e))


async def _resume_reporting_only(incident_id: str, state: SOCState):
    """Resume pipeline for rejected/monitor: reporting only."""
    try:
        state = await reporting_node(state)
        metrics = await get_metrics()
        await manager.send_metric_update(metrics)
    except Exception as e:
        await manager.send_error(incident_id, str(e))
