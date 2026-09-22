"""Service layer for investigation case lifecycle and file management."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path
import re
from typing import Any, Dict, List, Optional
import uuid

from ..config import ALLOWED_EXTENSIONS, MAX_UPLOAD_SIZE_BYTES, STORAGE_DIR
from ..repositories.case_repository import CaseRepository

SAFE_CASE_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]+$")


class CaseService:
    """Manages case operations and safe, immutable email file storage."""

    def __init__(
        self,
        repository: CaseRepository,
        storage_dir: Optional[Any] = None,
    ) -> None:
        self.repository = repository
        self.storage_dir = Path(storage_dir) if storage_dir else STORAGE_DIR
        self.storage_dir.mkdir(parents=True, exist_ok=True)

    def create_case(
        self, title: str, owner_user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generate unique case_id and create a new case record."""
        clean_title = title.strip()
        if not clean_title:
            raise ValueError("Case title cannot be empty.")

        case_id = f"CASE-{uuid.uuid4().hex[:8].upper()}"
        return self.repository.create_case(
            case_id=case_id, title=clean_title, owner_user_id=owner_user_id
        )

    def get_case(self, case_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve case record by case_id."""
        if not SAFE_CASE_ID_PATTERN.match(case_id):
            return None
        return self.repository.get_case(case_id)

    def list_cases(
        self, owner_user_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """List cases, optionally filtered by owner_user_id."""
        return self.repository.list_cases(owner_user_id=owner_user_id)

    def upload_email(
        self,
        case_id: str,
        filename: str,
        content_bytes: bytes,
    ) -> Dict[str, Any]:
        """Safely store original, immutable .eml and associate with case."""
        # 1. Validate case existence
        case = self.get_case(case_id)
        if not case:
            raise KeyError(f"Case '{case_id}' not found.")

        # 2. Prevent path traversal & sanitize filename
        raw_basename = os.path.basename(filename).strip()
        is_traversal = (
            ".." in raw_basename or "/" in raw_basename or "\\" in raw_basename
        )
        if not raw_basename or is_traversal:
            raw_basename = "message.eml"

        # 3. Validate file extension
        ext = os.path.splitext(raw_basename)[1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            allowed_list = sorted(ALLOWED_EXTENSIONS)
            raise ValueError(
                f"Invalid file extension '{ext}'. Allowed: {allowed_list}"
            )

        # 4. Enforce upload size limit
        file_size = len(content_bytes)
        if file_size > MAX_UPLOAD_SIZE_BYTES:
            max_mb = MAX_UPLOAD_SIZE_BYTES // (1024 * 1024)
            raise ValueError(
                f"File size ({file_size} bytes) exceeds limit of {max_mb} MB."
            )

        if file_size == 0:
            raise ValueError("Uploaded email file cannot be empty.")

        # 5. Calculate SHA-256 on exact original bytes (immutable preservation)
        sha256_hash = hashlib.sha256(content_bytes).hexdigest()

        # 6. Save original bytes to case directory
        case_storage_dir = self.storage_dir / case_id
        case_storage_dir.mkdir(parents=True, exist_ok=True)
        safe_stored_filename = f"original_{sha256_hash[:12]}{ext}"
        stored_path = case_storage_dir / safe_stored_filename

        with open(stored_path, "wb") as f:
            f.write(content_bytes)

        # 7. Update repository with preserved file metadata
        updated_case = self.repository.update_case_file(
            case_id=case_id,
            original_filename=raw_basename,
            file_sha256=sha256_hash,
            file_path=str(stored_path.resolve()),
            file_size_bytes=file_size,
        )

        return {
            "case_id": case_id,
            "original_filename": raw_basename,
            "file_sha256": sha256_hash,
            "file_size_bytes": file_size,
            "message": "Email file preserved and attached to case.",
            "case": updated_case,
        }
