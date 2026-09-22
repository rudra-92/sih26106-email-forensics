"""CLI script to bootstrap or promote a platform administrator account."""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import uuid

from backend.auth.security import (
    hash_password,
    normalize_email,
    validate_password,
)
from backend.db.session import SessionLocal
from backend.repositories.user_repository import UserRepository


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Bootstrap or promote a platform administrator account."
    )
    parser.add_argument(
        "--email",
        type=str,
        default=os.environ.get("BOOTSTRAP_ADMIN_EMAIL"),
        help="Administrator email address (or env BOOTSTRAP_ADMIN_EMAIL)",
    )
    parser.add_argument(
        "--password",
        type=str,
        default=os.environ.get("BOOTSTRAP_ADMIN_PASSWORD"),
        help="Administrator password (or env BOOTSTRAP_ADMIN_PASSWORD)",
    )
    parser.add_argument(
        "--full-name",
        type=str,
        default=os.environ.get("BOOTSTRAP_ADMIN_NAME", "Administrator"),
        help="Administrator display name",
    )

    args = parser.parse_args()

    email = args.email
    if not email:
        email = input("Admin Email: ").strip()

    try:
        clean_email = normalize_email(email)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    password = args.password
    if not password:
        password = getpass.getpass("Admin Password: ")

    try:
        validate_password(password)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)

    full_name = args.full_name.strip()
    if not full_name:
        full_name = "Administrator"

    db = SessionLocal()
    try:
        repo = UserRepository(session=db)
        existing = repo.get_user_by_email(clean_email)
        pw_hash = hash_password(password)

        if existing:
            existing.role = "admin"
            existing.is_active = True
            existing.password_hash = pw_hash
            existing.full_name = full_name
            db.commit()
            print(
                f"SUCCESS: Promoted existing user '{clean_email}' "
                "to administrator (role=admin)."
            )
        else:
            user_id = str(uuid.uuid4())
            repo.create_user(
                user_id=user_id,
                email=clean_email,
                password_hash=pw_hash,
                full_name=full_name,
                role="admin",
                is_active=True,
            )
            print(
                f"SUCCESS: Created initial admin account for '{clean_email}' "
                "(role=admin)."
            )
    finally:
        db.close()


if __name__ == "__main__":
    main()
