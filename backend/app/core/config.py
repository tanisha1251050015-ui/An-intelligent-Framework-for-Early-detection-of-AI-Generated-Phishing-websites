"""Core application configuration.

Phase 0 deliberately uses plain Python settings — no environment variables
and no .env files. This project never reads, creates, or exposes secrets.
"""

from pathlib import Path

# backend/ directory (app/core/config.py -> parents[2])
BACKEND_DIR = Path(__file__).resolve().parents[2]
DATA_DIR = BACKEND_DIR / "data"


class Settings:
    """Static application settings for Phase 0."""

    app_name: str = "PIP Backend"
    app_version: str = "1.1.0"
    api_v1_prefix: str = "/api/v1"

    # SQLite database file, created on first startup inside the workspace.
    database_url: str = f"sqlite:///{DATA_DIR / 'pip.db'}"

    # Dashboard dev server origin (Vite proxies /api to the backend).
    cors_origins: list[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    # Retention config for Phase 2D post-work cleanup
    screenshot_retention_days: int = 7
    inspection_retention_days: int = 30


settings = Settings()
