"""FastAPI application for MCPath backend and observability.

CRITICAL ARCHITECTURAL BOUNDARY:
This backend is strictly in the read/write observability path.
Claude Desktop / MCP Host -> MCPath Proxy -> MCP Servers (LIVE ENFORCEMENT)
MCPath Proxy -> FastAPI Backend -> PostgreSQL -> Dashboard (OBSERVABILITY)
The backend and dashboard CANNOT influence live enforcement decisions.
"""

from contextlib import asynccontextmanager
import logging
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from mcpath.backend.persistence.database import init_db
from mcpath.backend.routes.events import router as events_router
from mcpath.backend.routes.hashes import router as hashes_router
from mcpath.backend.routes.overview import router as overview_router
from mcpath.backend.routes.servers import router as servers_router
from mcpath.backend.routes.stage_results import router as stage_results_router

logger = logging.getLogger("mcpath.backend")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: initialize database schemas."""
    logger.info("Initializing MCPath database tables...")
    try:
        await init_db()
        logger.info("Database tables initialized successfully")
    except Exception as e:
        logger.warning("Database table initialization skipped: %s", e)
    yield
    logger.info("MCPath backend shutting down")


app = FastAPI(
    title="MCPath Security Backend API",
    description="Observability and evidence API for MCPath Zero-Trust MCP Proxy",
    version="0.1.0",
    lifespan=lifespan
)

# Allow dashboard access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routes
app.include_router(overview_router)
app.include_router(events_router)
app.include_router(hashes_router)
app.include_router(stage_results_router)
app.include_router(servers_router)


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "ok", "service": "mcpath-backend", "version": "0.1.0"}
