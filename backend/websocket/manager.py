"""
AEGIS SOC — WebSocket Connection Manager
Handles real-time broadcasting of agent activity to the dashboard.
Supports per-incident channels and global broadcast.
"""

import json
from datetime import datetime, timezone
from fastapi import WebSocket
from typing import Optional


class ConnectionManager:
    """Manages WebSocket connections and broadcasts agent updates to the dashboard."""

    def __init__(self):
        # All active WebSocket connections
        self.active_connections: list[WebSocket] = []
        # Per-incident subscriptions: {incident_id: [websocket, ...]}
        self.incident_subscriptions: dict[str, list[WebSocket]] = {}

    async def connect(self, websocket: WebSocket):
        """Accept a new WebSocket connection."""
        await websocket.accept()
        self.active_connections.append(websocket)
        print(f"🔌 WebSocket connected. Total: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        """Remove a disconnected WebSocket."""
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
        # Remove from all incident subscriptions
        for incident_id in list(self.incident_subscriptions.keys()):
            if websocket in self.incident_subscriptions[incident_id]:
                self.incident_subscriptions[incident_id].remove(websocket)
            if not self.incident_subscriptions[incident_id]:
                del self.incident_subscriptions[incident_id]
        print(f"🔌 WebSocket disconnected. Total: {len(self.active_connections)}")

    def subscribe_to_incident(self, websocket: WebSocket, incident_id: str):
        """Subscribe a connection to updates for a specific incident."""
        if incident_id not in self.incident_subscriptions:
            self.incident_subscriptions[incident_id] = []
        if websocket not in self.incident_subscriptions[incident_id]:
            self.incident_subscriptions[incident_id].append(websocket)

    async def broadcast(self, message: dict):
        """Send a message to ALL connected clients."""
        dead_connections = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                dead_connections.append(connection)
        # Clean up dead connections
        for conn in dead_connections:
            self.disconnect(conn)

    async def broadcast_to_incident(self, incident_id: str, message: dict):
        """Send a message only to clients subscribed to a specific incident."""
        # Always include in global broadcast too
        await self.broadcast(message)

    async def send_agent_update(
        self,
        incident_id: str,
        agent_name: str,
        message: str,
        data: Optional[dict] = None
    ):
        """
        Convenience method: broadcast a formatted agent update.
        This is what agents call to stream their activity to the dashboard.
        """
        payload = {
            "type": "agent_update",
            "incident_id": incident_id,
            "agent": agent_name,
            "message": message,
            "data": data or {},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self.broadcast(payload)

    async def send_status_change(self, incident_id: str, new_status: str):
        """Broadcast an incident status change."""
        payload = {
            "type": "status_change",
            "incident_id": incident_id,
            "agent": "system",
            "message": f"Incident status → {new_status}",
            "data": {"status": new_status},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self.broadcast(payload)

    async def send_metric_update(self, metrics: dict):
        """Broadcast updated metrics to all dashboards."""
        payload = {
            "type": "metric_update",
            "incident_id": "global",
            "agent": "system",
            "message": "Metrics updated",
            "data": metrics,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self.broadcast(payload)

    async def send_error(self, incident_id: str, error_message: str):
        """Broadcast an error."""
        payload = {
            "type": "error",
            "incident_id": incident_id,
            "agent": "system",
            "message": f"❌ Error: {error_message}",
            "data": {"error": error_message},
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        await self.broadcast(payload)


# ── Singleton instance (imported by main.py and agents) ──
manager = ConnectionManager()
