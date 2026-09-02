"""FastAPI application entrypoint for PIP Backend (Phase 0)."""

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import DATA_DIR, settings
from app.db.base import Base
from app.db.migrate import run_migrations
from app.db.session import engine


@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Create/update the local SQLite database and schema on startup."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    Base.metadata.create_all(bind=engine)
    run_migrations(engine)
    yield


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Phishing Intelligence Platform — Phase 0 foundation.",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix=settings.api_v1_prefix)
