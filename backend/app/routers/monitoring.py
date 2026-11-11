"""Monitoring router - system metrics."""

import random
import time
import platform
from fastapi import APIRouter
from pydantic import BaseModel
from typing import List
from datetime import datetime

router = APIRouter()


def _get_system_metrics() -> dict:
    """
    Attempt to collect real system metrics.
    Falls back to clearly-labelled simulated data if unavailable.
    """
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/") if platform.system() != "Windows" else psutil.disk_usage("C:\\")
        net = psutil.net_io_counters()
        return {
            "cpu_percent": cpu,
            "memory_percent": mem.percent,
            "memory_used_gb": round(mem.used / 1e9, 2),
            "memory_total_gb": round(mem.total / 1e9, 2),
            "disk_percent": disk.percent,
            "disk_used_gb": round(disk.used / 1e9, 2),
            "disk_total_gb": round(disk.total / 1e9, 2),
            "net_bytes_sent_mb": round(net.bytes_sent / 1e6, 2),
            "net_bytes_recv_mb": round(net.bytes_recv / 1e6, 2),
            "is_simulated": False,
            "timestamp": datetime.utcnow().isoformat(),
        }
    except Exception:
        # Clearly labelled simulation
        return {
            "cpu_percent": round(random.uniform(15, 85), 1),
            "memory_percent": round(random.uniform(40, 75), 1),
            "memory_used_gb": round(random.uniform(4, 12), 2),
            "memory_total_gb": 16.0,
            "disk_percent": round(random.uniform(45, 70), 1),
            "disk_used_gb": round(random.uniform(50, 200), 1),
            "disk_total_gb": 500.0,
            "net_bytes_sent_mb": round(random.uniform(100, 5000), 2),
            "net_bytes_recv_mb": round(random.uniform(200, 8000), 2),
            "is_simulated": True,
            "timestamp": datetime.utcnow().isoformat(),
        }


@router.get("/metrics")
async def get_metrics():
    """Get current system metrics (real if psutil available, else simulated)."""
    return _get_system_metrics()


@router.get("/history")
async def get_metric_history(points: int = 20):
    """Return simulated historical metric data for charting."""
    now = time.time()
    history = []
    for i in range(points):
        ts = datetime.utcfromtimestamp(now - (points - i) * 60).isoformat()
        history.append({
            "timestamp": ts,
            "cpu_percent": round(random.uniform(10, 90), 1),
            "memory_percent": round(random.uniform(35, 80), 1),
            "network_mbps": round(random.uniform(0.5, 50), 2),
            "is_simulated": True,
        })
    return {"history": history, "note": "Historical data is simulated for demonstration"}


@router.get("/dashboard")
async def dashboard_stats():
    """Aggregate stats for the Guardian Command Centre dashboard."""
    from app.services.store import store
    stats = store.get_dashboard_stats()
    metrics = _get_system_metrics()
    return {**stats, "system": metrics}
