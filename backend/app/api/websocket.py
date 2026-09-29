"""
NetSentinel WebSocket Connection Route
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from app.core.websocket_hub import ws_hub

router = APIRouter(tags=["WebSocket"])

@router.websocket("/ws/events")
async def websocket_events_endpoint(websocket: WebSocket):
    """
    Subscribes client to live stream of security events, alerts, device updates,
    and agent telemetry.
    """
    await ws_hub.connect(websocket)
    try:
        while True:
            # Keep-alive ping/pong
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text('{"type": "pong"}')
    except WebSocketDisconnect:
        ws_hub.disconnect(websocket)
    except Exception:
        ws_hub.disconnect(websocket)
