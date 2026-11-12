"""
MICHAEL - The Guardian AI
FastAPI Backend - Main Application Entry Point
"""

from fastapi import FastAPI, Response, status
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import os
import logging

from app.config import settings
from app.routers import logs, analysis, incidents, copilot, monitoring, reports, temporal, attack_chains, iocs, threat_correlation
from app.websockets.monitor import router as ws_router
from app.persistence.database import db_manager
from app.services.threat_intel_service import threat_intel_service

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("michael")

# Dynamic PORT synchronization (for cloud providers like Render that inject PORT dynamically)
_runtime_port = int(os.getenv("PORT", str(settings.PORT)))
if _runtime_port != 8000:
    try:
        import gc
        import uvicorn
        for _obj in gc.get_objects():
            if isinstance(_obj, uvicorn.Config) and _obj.port == 8000:
                _obj.port = _runtime_port
                logger.info("Synchronized Uvicorn port with environment PORT: %d", _runtime_port)
    except Exception:
        pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown events."""
    logger.info("🚀 MICHAEL - The Guardian AI is starting up...")
    # Create uploads directory if needed
    os.makedirs(settings.UPLOAD_DIR, exist_ok=True)
    yield
    logger.info("🛑 MICHAEL - The Guardian AI is shutting down.")


app = FastAPI(
    title="MICHAEL – The Guardian AI",
    description="Intelligent Log Analysis and Anomaly Detection Platform",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# Root endpoint & documentation redirects
@app.get("/", tags=["Root"])
async def root():
    """Root health and discovery endpoint."""
    return {
        "status": "operational",
        "service": "MICHAEL – The Guardian AI",
        "version": "1.0.0",
        "docs": "/docs",
        "openapi": "/openapi.json",
    }


@app.get("/api/docs", include_in_schema=False)
async def api_docs_redirect():
    """Redirect /api/docs to /docs for backwards compatibility."""
    return RedirectResponse(url="/docs")


@app.get("/api/redoc", include_in_schema=False)
async def api_redoc_redirect():
    """Redirect /api/redoc to /redoc for backwards compatibility."""
    return RedirectResponse(url="/redoc")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
app.include_router(logs.router, prefix="/api/logs", tags=["Logs"])
app.include_router(analysis.router, prefix="/api/analysis", tags=["Analysis"])
app.include_router(incidents.router, prefix="/api/incidents", tags=["Incidents"])
app.include_router(copilot.router, prefix="/api/copilot", tags=["Copilot"])
app.include_router(monitoring.router, prefix="/api/monitoring", tags=["Monitoring"])
app.include_router(reports.router, prefix="/api/reports", tags=["Reports"])
app.include_router(temporal.router, prefix="/api/temporal", tags=["Temporal"])
app.include_router(attack_chains.router, prefix="/api/attack-chains", tags=["Attack Chains"])
app.include_router(iocs.router, prefix="/api/iocs", tags=["IOCs"])
app.include_router(threat_correlation.router, prefix="/api/threat-correlation", tags=["Threat Correlation"])
app.include_router(ws_router, tags=["WebSockets"])

# Serve uploaded files statically
if os.path.exists(settings.UPLOAD_DIR):
    app.mount("/uploads", StaticFiles(directory=settings.UPLOAD_DIR), name="uploads")


@app.get("/api/health", tags=["Health"])
async def health_check():
    """Health check endpoint."""
    return {
        "status": "operational",
        "app": "alive",
        "service": "MICHAEL – The Guardian AI",
        "version": "1.0.0",
    }


@app.get("/api/ready", tags=["Health"])
async def ready_check(response: Response):
    """Readiness probe checking database and threat intelligence provider."""
    db_health = db_manager.check_db_health()
    backend = getattr(settings, "PERSISTENCE_BACKEND", "memory").lower()

    provider_name = getattr(settings, "THREAT_INTEL_PROVIDER", "offline_mock")
    provider = threat_intel_service.get_provider(provider_name)
    provider_available = bool(provider.is_available) if provider else False

    is_ready = True
    if backend != "memory" and db_health.get("status") == "unhealthy":
        is_ready = False
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "status": "ready" if is_ready else "not_ready",
        "db_status": (
            "memory_only"
            if backend == "memory"
            else ("connected" if db_health.get("status") == "healthy" else "disconnected")
        ),
        "persistence_backend": backend,
        "threat_intel_provider": {
            "name": provider_name,
            "available": provider_available,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", str(settings.PORT)))
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=port,
        reload=settings.APP_ENV == "development",
        log_level="info",
    )
