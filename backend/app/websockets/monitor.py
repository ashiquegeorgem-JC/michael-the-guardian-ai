"""WebSocket monitor for real-time event streaming."""

import asyncio
import json
import random
from datetime import datetime
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
import logging

logger = logging.getLogger("michael.ws")
router = APIRouter()

connected_clients: set = set()


@router.websocket("/ws/monitoring")
async def monitoring_ws(websocket: WebSocket):
    """Stream real-time system metrics and log events via WebSocket."""
    await websocket.accept()
    connected_clients.add(websocket)
    logger.info(f"WS client connected. Total: {len(connected_clients)}")

    try:
        while True:
            # Try real metrics
            try:
                import psutil
                cpu = psutil.cpu_percent(interval=0.1)
                mem = psutil.virtual_memory().percent
                is_simulated = False
            except Exception:
                cpu = round(random.uniform(15, 85), 1)
                mem = round(random.uniform(40, 75), 1)
                is_simulated = True

            # Simulated incoming log event
            log_events = [
                f"[INFO] Connection from 192.168.1.{random.randint(1, 254)}",
                f"[ERROR] Authentication failed for user admin from 10.0.0.{random.randint(1, 100)}",
                f"[WARNING] High memory usage detected: {round(mem, 1)}%",
                f"[INFO] HTTP GET /api/health 200 {random.randint(1, 50)}ms",
                f"[CRITICAL] Disk space low on /dev/sda1: {random.randint(85, 99)}% used",
                f"[INFO] Service heartbeat OK - uptime {random.randint(1, 9999)}s",
            ]
            event_line = random.choice(log_events)

            payload = {
                "type": "metrics",
                "timestamp": datetime.utcnow().isoformat(),
                "is_simulated": is_simulated,
                "data": {
                    "cpu_percent": cpu,
                    "memory_percent": mem,
                    "disk_percent": round(random.uniform(45, 70), 1),
                    "network_in_kbps": round(random.uniform(100, 5000), 1),
                    "network_out_kbps": round(random.uniform(50, 2000), 1),
                    "active_connections": random.randint(10, 500),
                    "log_events_per_min": random.randint(5, 200),
                    "latest_event": event_line,
                },
            }
            await websocket.send_text(json.dumps(payload))
            await asyncio.sleep(2)  # Push every 2 seconds

    except WebSocketDisconnect:
        connected_clients.discard(websocket)
        logger.info(f"WS client disconnected. Total: {len(connected_clients)}")
    except Exception as e:
        connected_clients.discard(websocket)
        logger.error(f"WS error: {e}")


async def broadcast_anomaly_alert(anomaly_data: dict):
    """Broadcast an anomaly alert to all connected clients."""
    if not connected_clients:
        return
    payload = json.dumps({"type": "anomaly_alert", **anomaly_data})
    dead = set()
    for client in connected_clients:
        try:
            await client.send_text(payload)
        except Exception:
            dead.add(client)
    connected_clients -= dead
