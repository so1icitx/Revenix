"""
Authentication with bcrypt password hashing and JWT tokens
"""

import os
import secrets
from pydantic import BaseModel
from sqlalchemy import text
import bcrypt
import jwt
from datetime import datetime, timedelta
from typing import Optional

SECRET_KEY = os.environ.get("JWT_SECRET_KEY") or secrets.token_urlsafe(64)
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

# Log warning if using generated secret (won't persist across restarts)
if not os.environ.get("JWT_SECRET_KEY"):
    import logging
    logging.warning("JWT_SECRET_KEY not set - using randomly generated key. Set JWT_SECRET_KEY environment variable for production.")

class SimpleUser(BaseModel):
    username: str
    password: str
    full_name: str
    email: str

class SimpleLogin(BaseModel):
    username: str
    password: str

async def check_user_count(session):
    """Check how many users exist"""
    result = await session.execute(text("SELECT COUNT(*) FROM users"))
    count = result.scalar()
    return count or 0

def hash_password(password: str) -> str:
    """Hash password using bcrypt"""
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against hash"""
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_access_token(token: str) -> Optional[dict]:
    """Decode JWT access token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

async def create_user(session, user: SimpleUser):
    """Create a new user with hashed password"""
    try:
        # Hash the password
        password_hash = hash_password(user.password)
        
        result = await session.execute(
            text("""
                INSERT INTO users (username, password_hash, full_name, email, role, is_active)
                VALUES (:username, :password, :full_name, :email, 'admin', TRUE)
                RETURNING id, username, email, full_name, role
            """),
            {
                "username": user.username,
                "password": password_hash,  # SECURE: Hashed password
                "full_name": user.full_name,
                "email": user.email
            }
        )
        await session.commit()
        new_user = result.fetchone()
        return {
            "id": new_user[0],
            "username": new_user[1],
            "email": new_user[2],
            "full_name": new_user[3],
            "role": new_user[4]
        }
    except Exception as e:
        await session.rollback()
        raise e

async def verify_user(session, credentials: SimpleLogin):
    """Verify user credentials with bcrypt"""
    result = await session.execute(
        text("""
            SELECT id, username, email, full_name, role, password_hash
            FROM users
            WHERE username = :username
        """),
        {"username": credentials.username}
    )
    user = result.fetchone()
    
    if user and verify_password(credentials.password, user[5]):  # user[5] is password_hash
        return {
            "id": user[0],
            "username": user[1],
            "email": user[2],
            "full_name": user[3],
            "role": user[4]
        }
    return None
