"""API package for SIH26106 Email Forensics backend."""

from .admin import router as admin_router
from .analysis import router as analysis_router
from .auth import router as auth_router
from .cases import router as cases_router

__all__ = [
    "admin_router",
    "analysis_router",
    "auth_router",
    "cases_router",
]
