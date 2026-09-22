"""Pytest fixtures for backend API test suite.

Includes PostgreSQL and Authentication support.
"""

from __future__ import annotations

from pathlib import Path
import tempfile
from typing import Generator
from fastapi.testclient import TestClient
import pytest
from sqlalchemy import create_engine, delete
from sqlalchemy.orm import Session, sessionmaker

import backend.api.analysis as analysis_api
import backend.api.cases as cases_api
from backend.auth.security import create_access_token, hash_password
import backend.config as config
from backend.db import Base
from backend.db.models import (
    Case,
    CaseAnalysisData,
    CaseEntity,
    CaseEvidence,
    CaseHypothesis,
    CaseRelationship,
    User,
)
from backend.db.session import get_db
from backend.main import app
from backend.repositories.case_repository import CaseRepository
from backend.repositories.user_repository import UserRepository
from backend.services.analysis_service import AnalysisService
from backend.services.case_service import CaseService

# Dedicated test engine bound to TEST_DATABASE_URL
test_engine = create_engine(
    config.TEST_DATABASE_URL,
    pool_pre_ping=True,
    echo=False,
)

TestSessionLocal = sessionmaker(
    bind=test_engine,
    autocommit=False,
    autoflush=False,
    expire_on_commit=False,
)


@pytest.fixture(scope="session", autouse=True)
def setup_test_schema() -> None:
    """Ensure test database has all tables created before any test runs."""
    Base.metadata.create_all(bind=test_engine)


def clean_database(session: Session) -> None:
    """Clean all data between tests to ensure complete test isolation."""
    session.execute(delete(CaseAnalysisData))
    session.execute(delete(CaseHypothesis))
    session.execute(delete(CaseRelationship))
    session.execute(delete(CaseEntity))
    session.execute(delete(CaseEvidence))
    session.execute(delete(Case))
    session.execute(delete(User))
    session.commit()


@pytest.fixture
def temp_backend_env() -> Generator[dict, None, None]:
    """Provide isolated PostgreSQL session and storage paths for testing."""
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp_dir:
        tmp_path = Path(tmp_dir)
        test_storage = tmp_path / "storage"
        test_storage.mkdir(parents=True, exist_ok=True)

        orig_storage = config.STORAGE_DIR
        config.STORAGE_DIR = test_storage

        session = TestSessionLocal()
        clean_database(session)

        # Create default investigator user
        user_repo = UserRepository(session=session)
        investigator = user_repo.create_user(
            user_id="user-inv-001",
            email="investigator@forensics.local",
            password_hash=hash_password("Investigator123!"),
            full_name="Lead Investigator",
            role="investigator",
            is_active=True,
        )

        admin = user_repo.create_user(
            user_id="user-admin-001",
            email="admin@forensics.local",
            password_hash=hash_password("Admin12345!"),
            full_name="System Admin",
            role="admin",
            is_active=True,
        )

        inv_token = create_access_token(
            user_id=investigator.id, role=investigator.role
        )
        admin_token = create_access_token(user_id=admin.id, role=admin.role)

        inv_headers = {"Authorization": f"Bearer {inv_token}"}
        admin_headers = {"Authorization": f"Bearer {admin_token}"}

        repo = CaseRepository(session=session)
        case_svc = CaseService(repository=repo, storage_dir=test_storage)
        analysis_svc = AnalysisService(repository=repo)

        def override_get_db() -> Generator[Session, None, None]:
            db = TestSessionLocal()
            try:
                yield db
            finally:
                db.close()

        app.dependency_overrides[get_db] = override_get_db
        app.dependency_overrides[cases_api.get_case_repository] = (
            lambda: repo
        )
        app.dependency_overrides[cases_api.get_case_service] = (
            lambda: case_svc
        )
        app.dependency_overrides[analysis_api.get_analysis_service] = (
            lambda: analysis_svc
        )

        yield {
            "tmp_path": tmp_path,
            "storage_dir": test_storage,
            "session": session,
            "repo": repo,
            "case_svc": case_svc,
            "analysis_svc": analysis_svc,
            "investigator": investigator,
            "admin": admin,
            "inv_token": inv_token,
            "admin_token": admin_token,
            "inv_headers": inv_headers,
            "admin_headers": admin_headers,
        }

        app.dependency_overrides.clear()
        clean_database(session)
        session.close()
        config.STORAGE_DIR = orig_storage


@pytest.fixture
def client(temp_backend_env: dict) -> Generator[TestClient, None, None]:
    """Test client with isolated test database and default auth headers."""
    headers = temp_backend_env["inv_headers"]
    with TestClient(app, headers=headers) as test_client:
        yield test_client


@pytest.fixture
def unauthenticated_client(
    temp_backend_env: dict,
) -> Generator[TestClient, None, None]:
    """Test client without authentication headers."""
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture
def admin_client(temp_backend_env: dict) -> Generator[TestClient, None, None]:
    """Test client configured with admin auth headers."""
    headers = temp_backend_env["admin_headers"]
    with TestClient(app, headers=headers) as test_client:
        yield test_client
