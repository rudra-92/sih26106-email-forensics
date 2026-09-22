"""Main FastAPI application entrypoint for SIH26106 Email Forensics API."""

from __future__ import annotations

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
from .db.session import SessionLocal, check_db_connection
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

# Enable CORS for frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
    """Optionally bootstrap initial admin from environment variables."""
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


@app.get("/", tags=["System"])
def root() -> Dict[str, Any]:
    """Root endpoint with service overview and link to documentation."""
    return {
        "name": APP_TITLE,
        "status": "active",
        "docs_url": "/docs",
        "health_url": "/health",
    }
