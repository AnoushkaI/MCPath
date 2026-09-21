"""FastAPI routes package."""

from mcpath.backend.routes.overview import router as overview_router
from mcpath.backend.routes.events import router as events_router
from mcpath.backend.routes.servers import router as servers_router

__all__ = ["overview_router", "events_router", "servers_router"]
