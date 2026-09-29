"""
NetSentinel Real-Time WebSocket Hub
"""
import json
import logging
from typing import List, Dict, Any
from fastapi import WebSocket

logger = logging.getLogger("NetSentinel.WebSocketHub")

class WebSocketHub:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"Client connected. Active subscribers: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"Client disconnected. Active subscribers: {len(self.active_connections)}")

    async def broadcast(self, event_type: str, data: Dict[str, Any]):
        """
        Broadcasts a typed JSON security event to all active SOC dashboard clients.
        Event Types:
        - DEVICE_DISCOVERED
        - DEVICE_UPDATED
        - DEVICE_OFFLINE
        - ALERT_RAISED
        - RISK_UPDATED
        - AGENT_ACTIVITY
        - INCIDENT_UPDATED
        - BASELINE_UPDATED
        - SIMULATION_EVENT
        """
        if not self.active_connections:
            return

        payload = {
            "event_type": event_type,
            "data": data
        }
        raw_message = json.dumps(payload, default=str)
        
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(raw_message)
            except Exception as e:
                logger.warning(f"Failed to send to client: {e}")
                disconnected.append(connection)

        for conn in disconnected:
            self.disconnect(conn)

ws_hub = WebSocketHub()
