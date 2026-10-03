"""
backend/app/auth.py — Custom JWT authentication with database-backed users.

No third-party auth provider (Firebase, Auth0) — this is a minimal, hand-rolled JWT flow.
Uses the `users` table from storage/postgres/schema.sql for persistence.
Includes user activity logging for audit trail.
"""

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

import bcrypt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel
from sqlalchemy import text
from sqlalchemy.orm import Session

from .db import get_db, is_available

_LOGGER = logging.getLogger(__name__)

# HS256 is symmetric: whoever knows this string can mint a token for any user,
# including one that never registered. The previous default was a literal
# committed to this repository, so every deployment that forgot to set
# JWT_SECRET_KEY shared one publicly-readable signing key — anyone who had seen
# the source could forge an investigator session. There is no safe default for
# this value, so there is no longer a default.
_DEV_PLACEHOLDER = "dev-only-secret-change-in-production"
_MIN_SECRET_LENGTH = 32

_secret_key: Optional[str] = None

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8  # 8-hour shift-length token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")


def get_secret_key() -> str:
    """
    The JWT signing key, resolved once per process.

    Raises unless JWT_SECRET_KEY is set to something that is not the old
    committed placeholder and is long enough to be worth attacking. Set
    ALLOW_DEV_JWT_SECRET=1 to run without one: that generates a random key per
    process, so tokens stop working across restarts (annoying, and intended)
    but remain unforgeable — which the shared constant never was.

    Resolved lazily rather than at import so that importing this module for
    tests or tooling does not require a configured secret; call it from startup
    (see main.py) to turn a misconfiguration into a boot failure instead of a
    surprise on the first login.
    """
    global _secret_key
    if _secret_key is not None:
        return _secret_key

    configured = os.environ.get("JWT_SECRET_KEY", "").strip()

    if configured and configured != _DEV_PLACEHOLDER and len(configured) >= _MIN_SECRET_LENGTH:
        _secret_key = configured
        return _secret_key

    if os.environ.get("ALLOW_DEV_JWT_SECRET", "").lower() not in ("1", "true", "yes"):
        if not configured:
            problem = "JWT_SECRET_KEY is not set"
        elif configured == _DEV_PLACEHOLDER:
            problem = "JWT_SECRET_KEY is still the placeholder committed to this repository"
        else:
            problem = (
                f"JWT_SECRET_KEY is only {len(configured)} characters "
                f"(minimum {_MIN_SECRET_LENGTH})"
            )
        raise RuntimeError(
            f"{problem}. Anyone who knows this value can forge a session for any "
            "user. Generate one with:\n"
            '    python -c "import secrets; print(secrets.token_urlsafe(48))"\n'
            "and put it in .env as JWT_SECRET_KEY, or set ALLOW_DEV_JWT_SECRET=1 "
            "to use a throwaway key that changes on every restart."
        )

    _secret_key = secrets.token_urlsafe(48)
    _LOGGER.warning(
        "ALLOW_DEV_JWT_SECRET is set — signing tokens with a random per-process key. "
        "Every restart invalidates all sessions, and multiple workers will reject "
        "each other's tokens. Never use this outside local development."
    )
    return _secret_key


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"


class LoginRequest(BaseModel):
    email: str
    password: str


class RegisterRequest(BaseModel):
    email: str
    password: str
    full_name: str
    department: Optional[str] = None


class TokenPayload(BaseModel):
    sub: str
    exp: datetime


class UserProfile(BaseModel):
    """Returned by GET /api/auth/me — this is what the frontend should
    render in the sidebar/header instead of hardcoded placeholder text."""
    email: str
    full_name: str
    department: str
    officer_id: str


class UserActivity(BaseModel):
    """User activity log entry."""
    id: int
    user_email: str
    activity_type: str
    details: Optional[str]
    ip_address: Optional[str]
    user_agent: Optional[str]
    created_at: datetime


def _hash_password(plain_password: str) -> str:
    return bcrypt.hashpw(plain_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))


def _log_activity(db: Session, email: str, activity_type: str, details: Optional[str] = None, 
                  ip_address: Optional[str] = None, user_agent: Optional[str] = None) -> None:
    """Log user activity to database for audit trail."""
    if not is_available():
        return
    try:
        db.execute(
            text("""
                INSERT INTO user_activity (user_email, activity_type, details, ip_address, user_agent, created_at)
                VALUES (:email, :activity_type, :details, :ip_address, :user_agent, :created_at)
            """),
            {
                "email": email,
                "activity_type": activity_type,
                "details": details,
                "ip_address": ip_address,
                "user_agent": user_agent,
                "created_at": datetime.now(timezone.utc),
            }
        )
        db.commit()
    except Exception:
        db.rollback()
        # Don't raise - activity logging shouldn't break auth flow


def get_user_by_email(db: Session, email: str) -> Optional[dict]:
    """Get user from database by email."""
    if not is_available():
        return None
    result = db.execute(
        text("SELECT id, email, hashed_password, full_name, department, created_at FROM users WHERE email = :email"),
        {"email": email}
    ).mappings().first()
    return dict(result) if result else None


def create_user(db: Session, email: str, password: str, full_name: str, department: Optional[str] = None) -> dict:
    """Create a new user in the database."""
    if not is_available():
        raise HTTPException(status_code=503, detail="Database unavailable")
    
    hashed_password = _hash_password(password)
    dept = department or email.split("@")[1] if "@" in email else "Unknown"
    
    result = db.execute(
        text("""
            INSERT INTO users (email, hashed_password, full_name, department, created_at)
            VALUES (:email, :hashed_password, :full_name, :department, :created_at)
            RETURNING id, email, full_name, department, created_at
        """),
        {
            "email": email,
            "hashed_password": hashed_password,
            "full_name": full_name,
            "department": dept,
            "created_at": datetime.now(timezone.utc),
        }
    ).mappings().first()
    db.commit()
    return dict(result)


def authenticate_user(db: Session, email: str, password: str) -> Optional[dict]:
    """Authenticate user against database."""
    user = get_user_by_email(db, email)
    if not user:
        return None
    if not verify_password(password, user["hashed_password"]):
        return None
    return user


def get_user_profile(db: Session, email: str) -> Optional[UserProfile]:
    """Get user profile from database for GET /api/auth/me."""
    user = get_user_by_email(db, email)
    if not user:
        return None
    
    # Generate officer_id from user id
    officer_id = f"OFC-{user['id']:04d}"
    
    return UserProfile(
        email=user["email"],
        full_name=user["full_name"],
        department=user["department"] or "Unknown",
        officer_id=officer_id,
    )


def create_access_token(subject: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = {"sub": subject, "exp": expire}
    return jwt.encode(to_encode, get_secret_key(), algorithm=ALGORITHM)


def get_current_user(token: str = Depends(oauth2_scheme)) -> str:
    """Dependency for protected routes: raises 401 if token invalid/expired."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, get_secret_key(), algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        return email
    except JWTError:
        raise credentials_exception


def get_current_user_with_db(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> str:
    """Dependency that validates token and ensures user exists in DB."""
    email = get_current_user(token)
    user = get_user_by_email(db, email)
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return email