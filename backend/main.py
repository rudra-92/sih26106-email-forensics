"""Main FastAPI application entrypoint for SIH26106 Email Forensics API."""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure root workspace directory is in python sys.path for production deployment
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

import logging
from typing import Any, Dict
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .api.admin import router as admin_router
from .api.analysis import router as analysis_router
from .api.auth import router as auth_router
from .api.cases import router as cases_router
from .config import (
    APP_TITLE,
    APP_VERSION,
    BOOTSTRAP_ADMIN_EMAIL,
    BOOTSTRAP_ADMIN_NAME,
    BOOTSTRAP_ADMIN_PASSWORD,
)
from .db import Base
from .db.session import SessionLocal, check_db_connection, engine
from .repositories.case_repository import ConcurrencyConflictError
from .repositories.user_repository import UserRepository
from .auth.security import hash_password

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title=APP_TITLE,
    description=(
        "Backend API for case management, email artifact preservation, "
        "evidence extraction, entity resolution, threat attribution, "
        "and role-based authorization."
    ),
    version=APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

# Enable CORS for frontend integration (environment-driven)
raw_cors = os.environ.get("CORS_ORIGINS", "").strip()
if raw_cors:
    allowed_origins = [origin.strip() for origin in raw_cors.split(",") if origin.strip()]
else:
    allowed_origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"^https://.*\.vercel\.app$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routes
app.include_router(auth_router)
app.include_router(admin_router)
app.include_router(cases_router)
app.include_router(analysis_router)


@app.on_event("startup")
def startup_bootstrap() -> None:
    """Optionally bootstrap initial admin from environment variables and ensure schema exists."""
    try:
        Base.metadata.create_all(bind=engine)
        # Ensure raw_eml_content column exists on existing databases
        from sqlalchemy import text
        with engine.connect() as conn:
            try:
                conn.execute(text("ALTER TABLE cases ADD COLUMN raw_eml_content TEXT"))
                conn.commit()
            except Exception:
                pass  # Column already exists
    except Exception as exc:
        logger.warning("Database schema creation check failed: %s", exc)

    if BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD:
        db = SessionLocal()
        try:
            repo = UserRepository(session=db)
            existing = repo.get_user_by_email(BOOTSTRAP_ADMIN_EMAIL)
            if not existing:
                import uuid
                pw_hash = hash_password(BOOTSTRAP_ADMIN_PASSWORD)
                repo.create_user(
                    user_id=str(uuid.uuid4()),
                    email=BOOTSTRAP_ADMIN_EMAIL,
                    password_hash=pw_hash,
                    full_name=BOOTSTRAP_ADMIN_NAME,
                    role="admin",
                    is_active=True,
                )
                logger.info(
                    "Bootstrapped initial admin user from environment: %s",
                    BOOTSTRAP_ADMIN_EMAIL,
                )
        except Exception as exc:
            logger.warning("Startup admin bootstrap skipped/failed: %s", exc)
        finally:
            db.close()


@app.exception_handler(ConcurrencyConflictError)
async def handle_concurrency_conflict(
    request: Request,
    exc: ConcurrencyConflictError,
) -> JSONResponse:
    """Handle concurrent analysis trigger on the same case with HTTP 409."""
    return JSONResponse(
        status_code=status.HTTP_409_CONFLICT,
        content={"detail": str(exc)},
    )


@app.get("/health", tags=["System"])
def health_check() -> Dict[str, Any]:
    """Health check endpoint confirming API and PostgreSQL availability."""
    db_ok = check_db_connection()
    return {
        "status": "ok" if db_ok else "degraded",
        "service": APP_TITLE,
        "version": APP_VERSION,
        "database": "connected" if db_ok else "disconnected",
    }


from fastapi.responses import FileResponse

FRONTEND_DIST = BASE_DIR / "frontend" / "dist"

if FRONTEND_DIST.is_dir():
    from fastapi.staticfiles import StaticFiles

    assets_dir = FRONTEND_DIST / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="frontend_assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_frontend_spa(full_path: str):
        if full_path.startswith(("api", "docs", "redoc", "health", "openapi.json")):
            return JSONResponse(status_code=404, content={"detail": "Not Found"})
        target_file = FRONTEND_DIST / full_path
        if target_file.is_file():
            return FileResponse(target_file)
        index_html = FRONTEND_DIST / "index.html"
        if index_html.is_file():
            return FileResponse(index_html)
        return JSONResponse(status_code=404, content={"detail": "Frontend not built"})
else:
    @app.get("/", tags=["System"])
    def root() -> Dict[str, Any]:
        """Root endpoint with service overview and link to documentation."""
        return {
            "name": APP_TITLE,
            "status": "active",
            "docs_url": "/docs",
            "health_url": "/health",
        }
