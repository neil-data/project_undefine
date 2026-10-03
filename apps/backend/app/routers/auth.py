"""
backend/app/routers/auth.py — Login, Register + current-user profile endpoints.
"""

from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.orm import Session

from ..auth import (
    authenticate_user,
    create_access_token,
    create_user,
    get_current_user,
    get_current_user_with_db,
    get_user_by_email,
    get_user_profile,
    TokenResponse,
    UserProfile,
    RegisterRequest,
)
from ..db import get_db, is_available

router = APIRouter(prefix="/api/auth", tags=["auth"])


def get_client_ip(request: Request) -> str:
    """Extract client IP from request."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def get_user_agent(request: Request) -> str:
    """Extract user agent from request."""
    return request.headers.get("User-Agent", "unknown")


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
def register(
    request: Request,
    user_data: RegisterRequest,
    db: Session = Depends(get_db)
):
    """
    Register a new user account.
    Returns access token on successful registration.
    """
    if not is_available():
        raise HTTPException(status_code=503, detail="Database unavailable")
    
    # Check if user already exists
    existing = get_user_by_email(db, user_data.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create user
    user = create_user(
        db=db,
        email=user_data.email,
        password=user_data.password,
        full_name=user_data.full_name,
        department=user_data.department
    )
    
    # Log activity
    from ..auth import _log_activity
    _log_activity(
        db=db,
        email=user_data.email,
        activity_type="register",
        details=f"New user registered: {user_data.full_name}",
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request)
    )
    
    # Create access token
    access_token = create_access_token(subject=user_data.email)
    return TokenResponse(access_token=access_token)


@router.post("/login", response_model=TokenResponse)
def login(
    request: Request,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    OAuth2PasswordRequestForm expects 'username' and 'password' fields
    (form-encoded, not JSON) — this is what the FastAPI auto-docs
    "Authorize" button expects natively. Frontend should send
    email as 'username'.
    """
    if not is_available():
        raise HTTPException(status_code=503, detail="Database unavailable")
    
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
        )
    
    # Log activity
    from ..auth import _log_activity
    _log_activity(
        db=db,
        email=user["email"],
        activity_type="login",
        details="User logged in",
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request)
    )
    
    access_token = create_access_token(subject=user["email"])
    return TokenResponse(access_token=access_token)


@router.post("/logout")
def logout(
    request: Request,
    current_user_email: str = Depends(get_current_user_with_db),
    db: Session = Depends(get_db)
):
    """Log out user (client should discard token). Logs activity."""
    from ..auth import _log_activity
    _log_activity(
        db=db,
        email=current_user_email,
        activity_type="logout",
        details="User logged out",
        ip_address=get_client_ip(request),
        user_agent=get_user_agent(request)
    )
    return {"message": "Logged out successfully"}


@router.get("/me", response_model=UserProfile)
def read_current_user(
    current_user_email: str = Depends(get_current_user_with_db),
    db: Session = Depends(get_db)
):
    """
    Returns the real logged-in user's profile — name, department,
    officer ID. Frontend should call this right after login (and
    cache the result) instead of hardcoding placeholder text.
    """
    profile = get_user_profile(db, current_user_email)
    if not profile:
        raise HTTPException(status_code=404, detail="User profile not found")
    return profile


@router.get("/activity")
def get_user_activity(
    current_user_email: str = Depends(get_current_user_with_db),
    db: Session = Depends(get_db),
    limit: int = 50,
    offset: int = 0
):
    """Get user's activity log."""
    if not is_available():
        return {"activities": []}
    
    result = db.execute(
        text("""
            SELECT id, user_email, activity_type, details, ip_address, user_agent, created_at
            FROM user_activity
            WHERE user_email = :email
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """),
        {"email": current_user_email, "limit": limit, "offset": offset}
    ).mappings().all()
    
    return {"activities": [dict(row) for row in result]}