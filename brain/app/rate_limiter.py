"""
Rate limiter middleware for Brain API
"""

import time
from collections import defaultdict
from typing import Dict, Tuple
from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
import logging

logger = logging.getLogger(__name__)


class RateLimiter:
    """Simple in-memory rate limiter using sliding window."""
    
    def __init__(self, requests_per_minute: int = 60, requests_per_second: int = 10):
        self.requests_per_minute = requests_per_minute
        self.requests_per_second = requests_per_second
        self.minute_windows: Dict[str, list] = defaultdict(list)
        self.second_windows: Dict[str, list] = defaultdict(list)
    
    def _clean_old_requests(self, window: list, max_age: float) -> list:
        """Remove requests older than max_age seconds."""
        now = time.time()
        return [t for t in window if now - t < max_age]
    
    def is_allowed(self, client_ip: str) -> Tuple[bool, str]:
        """Check if request from client_ip is allowed."""
        now = time.time()
        
        # Clean and check per-second limit
        self.second_windows[client_ip] = self._clean_old_requests(
            self.second_windows[client_ip], 1.0
        )
        if len(self.second_windows[client_ip]) >= self.requests_per_second:
            return False, f"Rate limit exceeded: {self.requests_per_second}/second"
        
        # Clean and check per-minute limit
        self.minute_windows[client_ip] = self._clean_old_requests(
            self.minute_windows[client_ip], 60.0
        )
        if len(self.minute_windows[client_ip]) >= self.requests_per_minute:
            return False, f"Rate limit exceeded: {self.requests_per_minute}/minute"
        
        # Record this request
        self.second_windows[client_ip].append(now)
        self.minute_windows[client_ip].append(now)
        
        return True, ""
    
    def get_remaining(self, client_ip: str) -> Dict[str, int]:
        """Get remaining requests for client."""
        self.second_windows[client_ip] = self._clean_old_requests(
            self.second_windows[client_ip], 1.0
        )
        self.minute_windows[client_ip] = self._clean_old_requests(
            self.minute_windows[client_ip], 60.0
        )
        
        return {
            "remaining_per_second": max(0, self.requests_per_second - len(self.second_windows[client_ip])),
            "remaining_per_minute": max(0, self.requests_per_minute - len(self.minute_windows[client_ip]))
        }


# Global rate limiter instance
rate_limiter = RateLimiter(requests_per_minute=120, requests_per_second=20)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware for rate limiting."""
    
    # Endpoints exempt from rate limiting
    EXEMPT_PATHS = {"/health", "/docs", "/openapi.json", "/redoc"}
    
    async def dispatch(self, request: Request, call_next):
        # Skip rate limiting for exempt paths
        if request.url.path in self.EXEMPT_PATHS:
            return await call_next(request)
        
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # Check forwarded headers for real IP behind proxy
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            client_ip = forwarded_for.split(",")[0].strip()
        
        # Check rate limit
        allowed, message = rate_limiter.is_allowed(client_ip)
        
        if not allowed:
            logger.warning(f"Rate limit exceeded for {client_ip}: {message}")
            raise HTTPException(
                status_code=429,
                detail=message,
                headers={"Retry-After": "1"}
            )
        
        # Add rate limit headers to response
        response = await call_next(request)
        remaining = rate_limiter.get_remaining(client_ip)
        response.headers["X-RateLimit-Remaining-Second"] = str(remaining["remaining_per_second"])
        response.headers["X-RateLimit-Remaining-Minute"] = str(remaining["remaining_per_minute"])
        
        return response
