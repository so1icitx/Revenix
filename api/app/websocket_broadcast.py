"""
WebSocket Broadcasting for Real-Time Updates
Replaces polling with instant push notifications to the dashboard.
"""
import socketio
import asyncio
import logging
from typing import Dict, Any, List
import json

logger = logging.getLogger(__name__)

# Create Socket.IO server
sio = socketio.AsyncServer(
    async_mode='asgi',
    cors_allowed_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    logger=False,
    engineio_logger=False
)

# Socket.IO ASGI app
socket_app = socketio.ASGIApp(sio)

# Connection tracking
connected_clients = set()

@sio.event
async def connect(sid, environ):
    """Client connected to WebSocket"""
    connected_clients.add(sid)
    logger.info(f"[WebSocket] Client connected: {sid} (Total: {len(connected_clients)})")
    await sio.emit('connected', {'status': 'connected', 'message': 'Real-time updates enabled'}, room=sid)

@sio.event
async def disconnect(sid):
    """Client disconnected from WebSocket"""
    connected_clients.discard(sid)
    logger.info(f"[WebSocket] Client disconnected: {sid} (Total: {len(connected_clients)})")

@sio.event
async def subscribe(sid, data):
    """Client subscribes to specific update channels"""
    channels = data.get('channels', [])
    for channel in channels:
        await sio.enter_room(sid, channel)
    logger.debug(f"[WebSocket] Client {sid} subscribed to: {channels}")
    await sio.emit('subscribed', {'channels': channels}, room=sid)

# ============================================================================
# Broadcasting Functions (called by API when data changes)
# ============================================================================

async def broadcast_alert(alert_data: Dict[str, Any]):
    """Broadcast new alert to all connected clients"""
    if not connected_clients:
        return
    
    try:
        await sio.emit('alert', alert_data, room='alerts')
        logger.debug(f"[WebSocket] Broadcasted alert: {alert_data.get('src_ip')}")
    except Exception as e:
        logger.error(f"[WebSocket] Error broadcasting alert: {e}")

async def broadcast_flow(flow_data: Dict[str, Any]):
    """Broadcast new flow to all connected clients"""
    if not connected_clients:
        return
    
    try:
        await sio.emit('flow', flow_data, room='flows')
        logger.debug(f"[WebSocket] Broadcasted flow: {flow_data.get('flow_id')}")
    except Exception as e:
        logger.error(f"[WebSocket] Error broadcasting flow: {e}")

async def broadcast_rule(rule_data: Dict[str, Any]):
    """Broadcast new AI decision/rule to all connected clients"""
    if not connected_clients:
        return
    
    try:
        await sio.emit('rule', rule_data, room='rules')
        logger.debug(f"[WebSocket] Broadcasted rule: {rule_data.get('rule_type')}")
    except Exception as e:
        logger.error(f"[WebSocket] Error broadcasting rule: {e}")

async def broadcast_system_health(health_data: Dict[str, Any]):
    """Broadcast system health update"""
    if not connected_clients:
        return
    
    try:
        await sio.emit('system_health', health_data)
        logger.debug(f"[WebSocket] Broadcasted system health update")
    except Exception as e:
        logger.error(f"[WebSocket] Error broadcasting system health: {e}")

async def broadcast_endpoint_update(endpoint_data: Dict[str, Any]):
    """Broadcast endpoint profile update"""
    if not connected_clients:
        return
    
    try:
        await sio.emit('endpoint_update', endpoint_data, room='endpoints')
        logger.debug(f"[WebSocket] Broadcasted endpoint update: {endpoint_data.get('hostname')}")
    except Exception as e:
        logger.error(f"[WebSocket] Error broadcasting endpoint update: {e}")

async def broadcast_threat_blocked(threat_data: Dict[str, Any]):
    """Broadcast threat blocked notification"""
    if not connected_clients:
        return
    
    try:
        await sio.emit('threat_blocked', threat_data)
        logger.info(f"[WebSocket] Broadcasted threat blocked: {threat_data.get('ip')}")
    except Exception as e:
        logger.error(f"[WebSocket] Error broadcasting threat blocked: {e}")

# ============================================================================
# Health Check & Status
# ============================================================================

@sio.event
async def ping(sid):
    """Heartbeat check"""
    await sio.emit('pong', {'timestamp': asyncio.get_event_loop().time()}, room=sid)

def get_stats() -> Dict[str, Any]:
    """Get WebSocket statistics"""
    return {
        'connected_clients': len(connected_clients),
        'active': len(connected_clients) > 0
    }
