"""Idempotent migration utility to transfer legacy SQLite case data into PostgreSQL."""

from __future__ import annotations

from pathlib import Path
import sqlite3
import sys

# Ensure root is in path
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from backend.db.models import (
    Case,
    CaseAnalysisData,
    CaseEntity,
    CaseEvidence,
    CaseHypothesis,
    CaseRelationship,
)
from backend.db.session import SessionLocal

SQLITE_PATH = BASE_DIR / "data" / "forensics_cases.db"


def migrate() -> None:
    if not SQLITE_PATH.is_file():
        print(f"SQLite database '{SQLITE_PATH}' not found. No migration needed.")
        return

    conn = sqlite3.connect(str(SQLITE_PATH))
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT count(*) FROM cases")
    case_count = cur.fetchone()[0]

    if case_count == 0:
        print(
            f"SQLite database '{SQLITE_PATH}' contains 0 cases. "
            "No legacy forensic data to migrate."
        )
        conn.close()
        return

    print(f"Found {case_count} cases in SQLite. Migrating to PostgreSQL...")
    db = SessionLocal()
    try:
        # Migrate cases
        cur.execute("SELECT * FROM cases")
        for row in cur.fetchall():
            case_d = dict(row)
            case_id = case_d["case_id"]
            existing = db.query(Case).filter(Case.case_id == case_id).first()
            if not existing:
                c = Case(
                    case_id=case_d["case_id"],
                    owner_user_id=case_d.get("owner_user_id"),
                    title=case_d["title"],
                    status=case_d["status"],
                    created_at=case_d["created_at"],
                    updated_at=case_d["updated_at"],
                    original_filename=case_d.get("original_filename"),
                    file_sha256=case_d.get("file_sha256"),
                    file_path=case_d.get("file_path"),
                    file_size_bytes=case_d.get("file_size_bytes"),
                    analysis_status=case_d.get("analysis_status", "pending"),
                    threat_label=case_d.get("threat_label"),
                    threat_confidence=case_d.get("threat_confidence"),
                    threat_confidence_metric=case_d.get(
                        "threat_confidence_metric"
                    ),
                    summary=case_d.get("summary"),
                    evidence_count=case_d.get("evidence_count", 0),
                    entity_count=case_d.get("entity_count", 0),
                    relationship_count=case_d.get("relationship_count", 0),
                    hypothesis_count=case_d.get("hypothesis_count", 0),
                    error_message=case_d.get("error_message"),
                )
                db.add(c)

        db.commit()
        print(f"Successfully migrated {case_count} cases into PostgreSQL.")
    except Exception as exc:
        db.rollback()
        print(f"Migration failed: {exc}", file=sys.stderr)
        raise
    finally:
        db.close()
        conn.close()


if __name__ == "__main__":
    migrate()
