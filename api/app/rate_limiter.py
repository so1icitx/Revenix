"""
Rate Limiting Middleware for Revenix API
Implements token bucket algorithm with per-IP tracking and Redis backend support.
"""

from fastapi import Request, HTTPException
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse
import time
import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, Optional
import asyncio
import logging

logger = logging.getLogger(__name__)


@dataclass
class RateLimitBucket:
    """Token bucket for rate limiting"""
    tokens: float
    last_update: float
    
    
@dataclass
class RateLimitConfig:
    """Configuration for rate limiting"""
    requests_per_minute: int = 200
    burst_size: int = 50
    block_duration_seconds: int = 30
    whitelist: set = field(default_factory=lambda: {
        "127.0.0.1", 
        "::1", 
        "localhost",
        "172.18.0.1",  # Docker gateway
        "172.17.0.1",  # Docker default gateway
    })
    whitelist_cidrs: tuple[str, ...] = (
        "172.16.0.0/12",  # Docker bridge/container traffic
    )

    
class RateLimiter:
    """
    In-memory rate limiter using token bucket algorithm.
    For production, consider using Redis for distributed rate limiting.
    """
    
    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        self.buckets: Dict[str, RateLimitBucket] = {}
        self.blocked_ips: Dict[str, float] = {}  # IP -> unblock timestamp
        self._lock = asyncio.Lock()
        self.whitelist_networks = []
        for cidr in self.config.whitelist_cidrs:
            try:
                self.whitelist_networks.append(ipaddress.ip_network(cidr))
            except ValueError:
                logger.warning(f"[RateLimit] Invalid whitelist CIDR ignored: {cidr}")
        
        # Calculate refill rate (tokens per second)
        self.refill_rate = self.config.requests_per_minute / 60.0
        
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP from request, handling proxies"""
        # Check X-Forwarded-For header first (for proxied requests)
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            # Take the first IP (original client)
            return forwarded.split(",")[0].strip()
        
        # Check X-Real-IP header
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip.strip()
        
        # Fall back to direct client IP
        if request.client:
            return request.client.host
        
        return "unknown"
    
    def _is_whitelisted(self, ip: str) -> bool:
        """Check if IP is whitelisted"""
        if ip in self.config.whitelist:
            return True
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(ip_obj in network for network in self.whitelist_networks)
    
    def _is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked"""
        if ip not in self.blocked_ips:
            return False
        
        if time.time() > self.blocked_ips[ip]:
            # Block expired, remove it
            del self.blocked_ips[ip]
            return False
        
        return True
    
    def _get_remaining_block_time(self, ip: str) -> int:
        """Get remaining block time in seconds"""
        if ip not in self.blocked_ips:
            return 0
        remaining = self.blocked_ips[ip] - time.time()
        return max(0, int(remaining))
    
    async def check_rate_limit(self, request: Request) -> tuple[bool, dict]:
        """
        Check if request is within rate limit.
        Returns (allowed, info_dict)
        """
        ip = self._get_client_ip(request)
        
        # Skip rate limiting for whitelisted IPs
        if self._is_whitelisted(ip):
            return True, {"whitelisted": True}
        
        # Check if IP is blocked
        if self._is_blocked(ip):
            remaining = self._get_remaining_block_time(ip)
            return False, {
                "blocked": True,
                "retry_after": remaining,
                "reason": "Rate limit exceeded"
            }
        
        async with self._lock:
            now = time.time()
            
            # Get or create bucket for this IP
            if ip not in self.buckets:
                self.buckets[ip] = RateLimitBucket(
                    tokens=self.config.burst_size,
                    last_update=now
                )
            
            bucket = self.buckets[ip]
            
            # Refill tokens based on time elapsed
            time_elapsed = now - bucket.last_update
            tokens_to_add = time_elapsed * self.refill_rate
            bucket.tokens = min(
                self.config.burst_size,
                bucket.tokens + tokens_to_add
            )
            bucket.last_update = now
            
            # Check if we have enough tokens
            if bucket.tokens >= 1:
                bucket.tokens -= 1
                return True, {
                    "remaining": int(bucket.tokens),
                    "limit": self.config.requests_per_minute,
                    "reset": int(now + (self.config.burst_size - bucket.tokens) / self.refill_rate)
                }
            else:
                # Rate limit exceeded, block the IP
                self.blocked_ips[ip] = now + self.config.block_duration_seconds
                logger.warning(f"[RateLimit] IP {ip} blocked for {self.config.block_duration_seconds}s")
                
                return False, {
                    "blocked": True,
                    "retry_after": self.config.block_duration_seconds,
                    "reason": "Rate limit exceeded"
                }
    
    async def cleanup_old_buckets(self):
        """Cleanup old buckets to prevent memory leak"""
        async with self._lock:
            now = time.time()
            # Remove buckets that haven't been used in 5 minutes
            stale_threshold = 300
            stale_ips = [
                ip for ip, bucket in self.buckets.items()
                if now - bucket.last_update > stale_threshold
            ]
            for ip in stale_ips:
                del self.buckets[ip]
            
            if stale_ips:
                logger.debug(f"[RateLimit] Cleaned up {len(stale_ips)} stale buckets")


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware for rate limiting.
    """
    
    # Endpoints that skip rate limiting
    EXEMPT_PATHS = {
        "/health",
        "/docs",
        "/openapi.json",
        "/redoc",
        "/auth/login",
        "/auth/signup", 
        "/auth/check-users",
        "/auth/me",
    }
    
    EXEMPT_PREFIXES = [
        "/auth/",
    ]
    
    def __init__(self, app, config: Optional[RateLimitConfig] = None):
        super().__init__(app)
        self.limiter = RateLimiter(config)
        
        # Start cleanup task
        asyncio.create_task(self._cleanup_loop())
    
    async def _cleanup_loop(self):
        """Background task to cleanup old buckets"""
        while True:
            await asyncio.sleep(60)  # Run every minute
            await self.limiter.cleanup_old_buckets()
    
    def _is_exempt(self, path: str) -> bool:
        """Check if path is exempt from rate limiting"""
        if path in self.EXEMPT_PATHS:
            return True
        for prefix in self.EXEMPT_PREFIXES:
            if path.startswith(prefix):
                return True
        return False
    
    async def dispatch(self, request: Request, call_next):
        if self._is_exempt(request.url.path):
            return await call_next(request)
        
        # Check rate limit
        allowed, info = await self.limiter.check_rate_limit(request)
        
        if not allowed:
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too Many Requests",
                    "detail": info.get("reason", "Rate limit exceeded"),
                    "retry_after": info.get("retry_after", 60)
                },
                headers={
                    "Retry-After": str(info.get("retry_after", 60)),
                    "X-RateLimit-Limit": str(self.limiter.config.requests_per_minute),
                    "X-RateLimit-Remaining": "0",
                }
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers to response
        if not info.get("whitelisted"):
            response.headers["X-RateLimit-Limit"] = str(self.limiter.config.requests_per_minute)
            response.headers["X-RateLimit-Remaining"] = str(info.get("remaining", 0))
            if "reset" in info:
                response.headers["X-RateLimit-Reset"] = str(info["reset"])
        
        return response


# Convenience function to create rate limit config
def create_rate_limit_config(
    requests_per_minute: int = 200,
    burst_size: int = 50,
    block_duration: int = 30,
    whitelist: Optional[set] = None
) -> RateLimitConfig:
    """Create a rate limit configuration"""
    config = RateLimitConfig(
        requests_per_minute=requests_per_minute,
        burst_size=burst_size,
        block_duration_seconds=block_duration
    )
    if whitelist:
        config.whitelist.update(whitelist)
    return config
