"""
Brain API Authentication Module
Validates JWT tokens from the main API for cross-service authentication.
"""

from fastapi import HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
import os
import secrets
from typing import Optional
from functools import wraps

# Configuration - shared with main API (must match API's JWT_SECRET_KEY)
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "revenix-secret-key-change-in-production")
ALGORITHM = "HS256"
INTERNAL_SERVICE_TOKEN = os.environ.get("INTERNAL_SERVICE_TOKEN", "").strip()

# Security scheme
security = HTTPBearer(auto_error=False)


class AuthError(Exception):
    """Authentication error"""
    def __init__(self, message: str, status_code: int = 401):
        self.message = message
        self.status_code = status_code


def decode_token(token: str) -> Optional[dict]:
    """Decode and validate JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise AuthError("Token has expired", 401)
    except jwt.InvalidTokenError as e:
        raise AuthError(f"Invalid token: {str(e)}", 401)


def _authenticate_internal_service(request: Optional[Request]) -> Optional[dict]:
    if request is None or not INTERNAL_SERVICE_TOKEN:
        return None
    provided_token = request.headers.get("x-internal-token", "").strip()
    if not provided_token:
        return None
    if not secrets.compare_digest(provided_token, INTERNAL_SERVICE_TOKEN):
        return None
    return {"sub": "internal-service", "role": "admin", "internal": True}


async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> dict:
    """
    Dependency to get current authenticated user from JWT token.
    Use as: user = Depends(get_current_user)
    """
    internal_user = _authenticate_internal_service(request)
    if internal_user is not None:
        return internal_user

    if credentials is None:
        raise HTTPException(status_code=401, detail="Missing authentication token")
    
    try:
        payload = decode_token(credentials.credentials)
        if payload is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return payload
    except AuthError as e:
        raise HTTPException(status_code=e.status_code, detail=e.message)


async def get_optional_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> Optional[dict]:
    """
    Dependency to optionally get current user (for endpoints that work with or without auth).
    """
    internal_user = _authenticate_internal_service(request)
    if internal_user is not None:
        return internal_user

    if credentials is None:
        return None
    
    try:
        return decode_token(credentials.credentials)
    except AuthError:
        return None


def require_auth(func):
    """
    Decorator to require authentication on an endpoint.
    Usage:
        @app.get("/protected")
        @require_auth
        async def protected_endpoint(user: dict = Depends(get_current_user)):
            return {"user": user}
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        return await func(*args, **kwargs)
    return wrapper


def require_role(required_role: str):
    """
    Dependency factory to require a specific role.
    Usage:
        @app.get("/admin-only")
        async def admin_endpoint(user: dict = Depends(require_role("admin"))):
            return {"user": user}
    """
    async def role_checker(
        request: Request,
        credentials: HTTPAuthorizationCredentials = Depends(security)
    ) -> dict:
        internal_user = _authenticate_internal_service(request)
        if internal_user is not None:
            return internal_user

        if credentials is None:
            raise HTTPException(status_code=401, detail="Missing authentication token")
        
        try:
            payload = decode_token(credentials.credentials)
            if payload is None:
                raise HTTPException(status_code=401, detail="Invalid token")
            
            user_role = payload.get("role", "user")
            if user_role != required_role and user_role != "admin":
                raise HTTPException(
                    status_code=403, 
                    detail=f"Insufficient permissions. Required role: {required_role}"
                )
            return payload
        except AuthError as e:
            raise HTTPException(status_code=e.status_code, detail=e.message)
    
    return role_checker


# List of endpoints that don't require authentication
PUBLIC_ENDPOINTS = {
    "/health",
    "/docs",
    "/openapi.json",
    "/redoc",
}


def is_public_endpoint(path: str) -> bool:
    """Check if an endpoint is public (no auth required)"""
    return path in PUBLIC_ENDPOINTS
