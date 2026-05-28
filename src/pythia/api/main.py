"""FastAPI application entry point for Pythia."""

from __future__ import annotations

import pathlib
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from pythia import __version__
from pythia.api import (
    actors,
    ai_threats,
    analytics,
    feed,
    intel_feed,
    iocs,
    malware,
    parse,
    reports,
    rules,
    sync,
    threats,
    ttps,
    watchlist,
)
from pythia.core.config import get_settings
from pythia.core.db import init_db
from pythia.core.scheduling import start_scheduler, stop_scheduler


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    init_db()
    start_scheduler()
    yield
    stop_scheduler()


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title="Pythia",
        description="Oracle-grade threat intelligence, served as an API.",
        version=__version__,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    @app.get("/", include_in_schema=False)
    async def root() -> JSONResponse:
        return JSONResponse(
            {
                "name": "Pythia",
                "version": __version__,
                "environment": settings.env,
                "docs": "/docs",
            }
        )

    @app.get("/v1/health", tags=["meta"])
    async def health() -> dict[str, str]:
        return {"status": "ok", "version": __version__}

    app.include_router(threats.router, prefix="/v1/threats", tags=["threats"])
    app.include_router(actors.router, prefix="/v1/actors", tags=["actors"])
    app.include_router(ttps.router, prefix="/v1/ttps", tags=["ttps"])
    app.include_router(iocs.router, prefix="/v1/iocs", tags=["iocs"])
    app.include_router(rules.router, prefix="/v1/rules", tags=["rules"])
    app.include_router(reports.router, prefix="/v1/reports", tags=["reports"])
    app.include_router(parse.router, prefix="/v1/parse", tags=["parse"])
    app.include_router(ai_threats.router, prefix="/v1/ai-threats", tags=["ai-threats"])
    app.include_router(analytics.router, prefix="/v1/analytics", tags=["analytics"])
    app.include_router(watchlist.router, prefix="/v1/watchlist", tags=["watchlist"])
    app.include_router(feed.router, prefix="/v1", tags=["feed"])
    app.include_router(intel_feed.router, prefix="/v1/intel-feed", tags=["intel-feed"])
    app.include_router(malware.router, prefix="/v1/malware", tags=["malware"])
    app.include_router(sync.router, prefix="/v1/sync", tags=["sync"])

    # Serve built frontend — must be last so it doesn't shadow /v1/* or /docs
    _frontend_dist = pathlib.Path(__file__).resolve().parent.parent.parent.parent / "frontend" / "dist"
    if _frontend_dist.is_dir():
        app.mount("/", StaticFiles(directory=_frontend_dist, html=True), name="spa")

    return app


app = create_app()
