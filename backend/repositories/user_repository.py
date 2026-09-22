"""PostgreSQL repository for user accounts and administrative operations."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db.models import User


class UserRepository:
    """Manages transactional PostgreSQL storage for user accounts."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def create_user(
        self,
        user_id: str,
        email: str,
        password_hash: str,
        full_name: str,
        role: str = "investigator",
        is_active: bool = True,
    ) -> User:
        """Create and persist a new user record."""
        now_ts = datetime.now(timezone.utc).isoformat()
        user = User(
            id=user_id,
            email=email.strip().lower(),
            password_hash=password_hash,
            full_name=full_name.strip(),
            role=role,
            is_active=is_active,
            created_at=now_ts,
            updated_at=now_ts,
            last_login_at=None,
        )
        self.session.add(user)
        self.session.commit()
        self.session.refresh(user)
        return user

    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Retrieve a user by their unique user_id."""
        stmt = select(User).where(User.id == user_id)
        return self.session.scalars(stmt).first()

    def get_user_by_email(self, email: str) -> Optional[User]:
        """Retrieve a user by normalized lowercase email."""
        stmt = select(User).where(User.email == email.strip().lower())
        return self.session.scalars(stmt).first()

    def list_users(self) -> List[User]:
        """List all registered users ordered by creation date."""
        stmt = select(User).order_by(User.created_at.desc())
        return list(self.session.scalars(stmt).all())

    def update_user_status(
        self, user_id: str, is_active: bool
    ) -> Optional[User]:
        """Update active status for a user."""
        user = self.get_user_by_id(user_id)
        if not user:
            return None
        now_ts = datetime.now(timezone.utc).isoformat()
        user.is_active = is_active
        user.updated_at = now_ts
        self.session.commit()
        self.session.refresh(user)
        return user

    def update_last_login(self, user_id: str) -> None:
        """Record the current timestamp as the user's last login."""
        user = self.get_user_by_id(user_id)
        if user:
            user.last_login_at = datetime.now(timezone.utc).isoformat()
            self.session.commit()
