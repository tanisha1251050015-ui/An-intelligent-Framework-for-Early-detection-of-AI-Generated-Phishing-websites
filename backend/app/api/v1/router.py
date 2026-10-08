"""Aggregates all version 1 API routers."""

from fastapi import APIRouter

from app.api.v1 import health, inspect, learning

api_router = APIRouter()
api_router.include_router(health.router, tags=["health"])
api_router.include_router(inspect.router, tags=["inspection"])
api_router.include_router(learning.router, tags=["learning"])
