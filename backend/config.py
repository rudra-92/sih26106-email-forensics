"""Backend configuration and environment settings."""

from __future__ import annotations

import os
from pathlib import Path
import secrets
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DEFAULT_STORAGE_DIR = BASE_DIR / "backend" / "storage" / "cases"

# Load local environment configuration (.env is excluded from git)
load_dotenv(BASE_DIR / ".env")
load_dotenv(BASE_DIR / "frontend" / ".env")

# PostgreSQL / SQLite Database Configuration
DEFAULT_DATABASE_URL = "sqlite:///./sih26106.db"
DEFAULT_TEST_DATABASE_URL = "sqlite:///./sih26106_test.db"

DATABASE_URL = os.environ.get("DATABASE_URL", DEFAULT_DATABASE_URL)
TEST_DATABASE_URL = os.environ.get(
    "TEST_DATABASE_URL", DEFAULT_TEST_DATABASE_URL
)

# JWT Authentication Settings (Legacy & Local fallback)
_raw_jwt_secret = os.environ.get("JWT_SECRET_KEY")
if not _raw_jwt_secret:
    _raw_jwt_secret = secrets.token_hex(32)
JWT_SECRET_KEY: str = _raw_jwt_secret

ACCESS_TOKEN_EXPIRE_MINUTES = int(
    os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "60")
)
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")

# Supabase Auth Configuration
SUPABASE_URL = (
    os.environ.get("SUPABASE_URL")
    or os.environ.get("VITE_SUPABASE_URL")
    or "https://xbaulrosqdphmuedhoyk.supabase.co"
)
SUPABASE_ANON_KEY = (
    os.environ.get("SUPABASE_ANON_KEY")
    or os.environ.get("VITE_SUPABASE_ANON_KEY")
    or "sb_publishable_aIM4zAeG2O2xM5_MINImkQ_QEryfxmc"
)
SUPABASE_JWT_SECRET = os.environ.get("SUPABASE_JWT_SECRET")

# Optional Admin Bootstrap Settings
BOOTSTRAP_ADMIN_EMAIL = os.environ.get("BOOTSTRAP_ADMIN_EMAIL")
BOOTSTRAP_ADMIN_PASSWORD = os.environ.get("BOOTSTRAP_ADMIN_PASSWORD")
BOOTSTRAP_ADMIN_NAME = os.environ.get(
    "BOOTSTRAP_ADMIN_NAME", "Administrator"
)

# File & Storage Settings
STORAGE_DIR = Path(
    os.environ.get("SIH_STORAGE_DIR", str(DEFAULT_STORAGE_DIR))
)
MAX_UPLOAD_SIZE_BYTES = int(
    os.environ.get("SIH_MAX_UPLOAD_SIZE", str(25 * 1024 * 1024))
)  # 25 MB
ALLOWED_EXTENSIONS = {".eml", ".msg", ".txt"}
APP_TITLE = "SIH26106 Email Forensics & Attribution Engine API"
APP_VERSION = "2.0.0"
