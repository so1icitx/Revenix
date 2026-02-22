from fastapi import FastAPI, Depends, HTTPException, Request, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text, bindparam
from sqlalchemy.ext.asyncio import AsyncSession
from db import get_session
from pydantic import BaseModel, validator, constr
from datetime import datetime, timedelta
from contextlib import asynccontextmanager
import asyncio
import ipaddress
import time
import httpx
import subprocess
import platform
import json
import os
import secrets
from typing import Optional, Any
import aiohttp # Import aiohttp

from app.simple_auth import SimpleUser, SimpleLogin, check_user_count, create_user, verify_user, create_access_token, decode_access_token
from app.rate_limiter import RateLimitMiddleware, create_rate_limit_config

consumer_task = None
INTERNAL_SERVICE_TOKEN = os.environ.get("INTERNAL_SERVICE_TOKEN", "").strip()

PUBLIC_EXACT_PATHS = {
    "/health",
    "/healthz",
    "/auth/check-users",
    "/auth/signup",
    "/auth/login",
    "/openapi.json",
    "/redoc",
    "/docs",
}

PUBLIC_PREFIX_PATHS = (
    "/docs",
    "/redoc",
    "/openapi",
    "/socket.io",
)

class LearningState:
    def __init__(self):
        self.phase = "idle"  # idle, learning, active
        self.started_at: Optional[str] = None
        self._initialized = False
    
    async def init_from_db(self, session: AsyncSession):
        if self._initialized:
            return
        try:
            # Try to get from persistent storage
            result = await session.execute(
                text("SELECT config_value FROM model_config WHERE config_key = 'learning_phase'")
            )
            row = result.fetchone()
            if row:
                self.phase = row[0]
                
            # Get started_at
            result2 = await session.execute(
                text("SELECT config_value FROM model_config WHERE config_key = 'learning_started_at'")
            )
            row2 = result2.fetchone()
            if row2:
                self.started_at = row2[0]
                
            self._initialized = True
        except Exception as e:
            print(f"Error initializing learning state: {e}")
            self._initialized = True
    
    async def save_to_db(self, session: AsyncSession):
        try:
            # Upsert learning_phase
            await session.execute(
                text("""
                    INSERT INTO model_config (config_key, config_value, description)
                    VALUES ('learning_phase', :phase, 'Current learning phase')
                    ON CONFLICT (config_key) DO UPDATE SET config_value = :phase, updated_at = NOW()
                """),
                {"phase": self.phase}
            )
            
            # Upsert started_at
            if self.started_at:
                await session.execute(
                    text("""
                        INSERT INTO model_config (config_key, config_value, description)
                        VALUES ('learning_started_at', :started, 'When learning started')
                        ON CONFLICT (config_key) DO UPDATE SET config_value = :started, updated_at = NOW()
                    """),
                    {"started": self.started_at}
                )
            
            await session.commit()
        except Exception as e:
            print(f"Error saving learning state: {e}")

learning_state = LearningState()

PROTECTED_INFRA_IPS = {
    "127.0.0.1",
    "0.0.0.0",
    "172.17.0.1",
    "172.18.0.1",
    "192.168.65.1",
}

LOCAL_DISCOVERY_PORTS = {
    5353,  # mDNS
    5355,  # LLMNR
    1900,  # SSDP
    137,   # NetBIOS Name Service
    138,   # NetBIOS Datagram
}


def _is_protected_infrastructure_ip(ip_value: str) -> bool:
    """
    Return True when IP should never be blocked automatically/manual policy.
    Protect loopback/link-local/control-plane and likely default gateways.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_value)
    except ValueError:
        return False

    ip_str = str(ip_obj)
    if ip_str in PROTECTED_INFRA_IPS:
        return True

    if ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified:
        return True

    # Common LAN gateway endings (e.g. .1 / .254) are risky to block.
    if ip_obj.version == 4 and ip_obj.is_private:
        last_octet = ip_str.split(".")[-1]
        if last_octet in {"1", "254"}:
            return True

    return False


async def get_model_config_value(session: AsyncSession, key: str, default, cast_type: str | None = None):
    """
    Fetch typed configuration value from model_config table.
    Falls back to `default` when not found.
    """
    try:
        result = await session.execute(
            text("SELECT config_value, config_type FROM model_config WHERE config_key = :key"),
            {"key": key}
        )
        row = result.fetchone()
        if not row:
            return default
        
        value, config_type = row
        value_type = cast_type or config_type
        
        if value_type == 'integer':
            return int(value)
        if value_type == 'float':
            return float(value)
        if value_type == 'boolean':
            return str(value).lower() in ('true', '1', 'yes', 'on')
        return value
    except Exception as exc:
        print(f"[Config] Failed to fetch config '{key}': {exc}")
        return default


def _flow_row_to_dict(row: Any) -> dict:
    """Serialize a flows row to dashboard-friendly JSON."""
    return {
        "id": row[0],
        "flow_id": row[1],
        "hostname": row[2],
        "src_ip": row[3],
        "dst_ip": row[4],
        "src_port": row[5],
        "dst_port": row[6],
        "protocol": row[7],
        "bytes": row[8],
        "packets": row[9],
        "start_ts": row[10],
        "end_ts": row[11],
        "timestamp": row[12].isoformat() if row[12] else None,
        "verified_benign": row[13],
        "analyzed_at": row[14].isoformat() if row[14] else None,
        "analysis_version": row[15],
        "training_excluded": row[16],
        "flow_count": row[17],
        "last_seen": row[18].isoformat() if row[18] else None,
    }


def _is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def _ensure_alerting_schema(session: AsyncSession) -> None:
    """Ensure alerting tables/indexes exist for upgraded installs with old DB volumes."""
    await session.execute(
        text("""
            CREATE TABLE IF NOT EXISTS alerting_webhooks (
                id SERIAL PRIMARY KEY,
                name VARCHAR(100) NOT NULL,
                url TEXT NOT NULL,
                type VARCHAR(50) NOT NULL DEFAULT 'webhook',
                enabled BOOLEAN DEFAULT TRUE,
                events JSONB DEFAULT '["critical", "high"]',
                headers JSONB DEFAULT '{}',
                last_triggered_at TIMESTAMP,
                trigger_count INTEGER DEFAULT 0,
                last_error TEXT,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            )
        """)
    )
    await session.execute(
        text("CREATE INDEX IF NOT EXISTS idx_alerting_webhooks_enabled ON alerting_webhooks(enabled) WHERE enabled = TRUE")
    )
    await session.execute(
        text("""
            CREATE TABLE IF NOT EXISTS alert_notifications (
                id SERIAL PRIMARY KEY,
                alert_id INTEGER REFERENCES alerts(id),
                webhook_id INTEGER REFERENCES alerting_webhooks(id),
                status VARCHAR(20) NOT NULL,
                response_code INTEGER,
                error_message TEXT,
                sent_at TIMESTAMP DEFAULT NOW()
            )
        """)
    )
    await session.execute(
        text("CREATE INDEX IF NOT EXISTS idx_alert_notifications_alert ON alert_notifications(alert_id)")
    )
    await session.execute(
        text("CREATE INDEX IF NOT EXISTS idx_alert_notifications_sent ON alert_notifications(sent_at DESC)")
    )

@asynccontextmanager
async def lifespan(app: FastAPI):
    global consumer_task
    print("[API] ========================================")
    print("[API] Starting Redis consumer...")
    print("[API] ========================================")
    from redis_consumer import start_redis_consumer
    consumer_task = asyncio.create_task(start_redis_consumer())
    
    # Initialize learning state from DB on startup
    session_gen = get_session()
    session = await anext(session_gen)
    try:
        # Ensure agent schema is compatible with current API queries.
        await session.execute(
            text("ALTER TABLE agents ADD COLUMN IF NOT EXISTS ip VARCHAR(64) DEFAULT 'auto'")
        )
        await session.execute(
            text("CREATE INDEX IF NOT EXISTS idx_agents_ip ON agents(ip)")
        )
        await _ensure_alerting_schema(session)
        await session.commit()
        await learning_state.init_from_db(session)
    finally:
        try:
            await session_gen.aclose()
        except Exception:
            pass
    
    yield
    print("[API] Shutting down consumer...")
    if consumer_task:
        consumer_task.cancel()

from app.websocket_broadcast import socket_app, broadcast_alert, broadcast_flow, broadcast_rule, get_stats as ws_get_stats
from app.alerting_dispatch import dispatch_alert_notifications, send_alert_to_webhook, create_test_alert_payload

app = FastAPI(lifespan=lifespan)

rate_limit_config = create_rate_limit_config(
    requests_per_minute=200,
    burst_size=50,
    block_duration=30,
    whitelist={"127.0.0.1", "::1", "localhost"}
)
app.add_middleware(RateLimitMiddleware, config=rate_limit_config)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],  # Restrict to localhost for security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def _is_public_path(path: str) -> bool:
    if path in PUBLIC_EXACT_PATHS:
        return True
    return any(path.startswith(prefix) for prefix in PUBLIC_PREFIX_PATHS)


def _authenticate_jwt(request: Request) -> Optional[dict]:
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return None
    token = auth_header.split(" ", 1)[1].strip()
    if not token:
        return None
    return decode_access_token(token)


def _authenticate_internal_service(request: Request) -> Optional[dict]:
    if not INTERNAL_SERVICE_TOKEN:
        return None
    provided_token = request.headers.get("x-internal-token", "").strip()
    if not provided_token:
        return None
    if not secrets.compare_digest(provided_token, INTERNAL_SERVICE_TOKEN):
        return None
    return {"sub": "internal-service", "role": "admin", "internal": True}


def _internal_service_headers() -> dict[str, str]:
    if not INTERNAL_SERVICE_TOKEN:
        return {}
    return {"X-Internal-Token": INTERNAL_SERVICE_TOKEN}


@app.middleware("http")
async def enforce_api_authentication(request: Request, call_next):
    if request.method == "OPTIONS" or _is_public_path(request.url.path):
        return await call_next(request)

    user_payload = _authenticate_internal_service(request)
    if user_payload is None:
        user_payload = _authenticate_jwt(request)

    if user_payload is None:
        return JSONResponse(status_code=401, content={"detail": "Authentication required"})

    request.state.user = user_payload
    return await call_next(request)

# Mount Socket.IO for WebSocket support
app.mount("/socket.io", socket_app)

class DeviceRegistration(BaseModel):
    agent_id: constr(min_length=1, max_length=255)  # type: ignore
    hostname: constr(min_length=1, max_length=255)  # type: ignore
    ip: str | None = None
    
    @validator('ip')
    def validate_ip(cls, v):
        if v is not None and str(v).lower() != "auto":
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError('Invalid IP address format')
        return v

class AlertCreate(BaseModel):
    flow_id: constr(min_length=1, max_length=255)  # type: ignore
    hostname: constr(min_length=1, max_length=255)  # type: ignore
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    risk_score: float
    severity: str | None = None  # Auto-calculated if not provided
    reason: constr(min_length=1, max_length=5000)  # type: ignore
    threat_category: str | None = None  # Added threat category field
    
    @validator('src_ip', 'dst_ip')
    def validate_ip(cls, v):
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            raise ValueError(f'Invalid IP address format: {v}')
    
    @validator('src_port', 'dst_port')
    def validate_port(cls, v):
        if v is not None and (v < 0 or v > 65535):
            raise ValueError('Port must be between 0 and 65535')
        return v
    
    @validator('risk_score')
    def validate_risk_score(cls, v):
        if v < 0 or v > 1:
            raise ValueError('Risk score must be between 0 and 1')
        return v


class AlertDeleteBatch(BaseModel):
    alert_ids: list[int]


class RuleCreate(BaseModel):
    alert_id: int
    rule_type: constr(min_length=1, max_length=100)  # type: ignore
    action: constr(min_length=1, max_length=100)  # type: ignore
    target: str  # Can be IP, port, or other target
    reason: constr(min_length=1, max_length=2000)  # type: ignore
    confidence: float
    
    @validator('confidence')
    def validate_confidence(cls, v):
        if v < 0 or v > 1:
            raise ValueError('Confidence must be between 0 and 1')
        return v
    
    @validator('target')
    def validate_target(cls, v):
        # Try to parse as IP address first (most common)
        try:
            ipaddress.ip_address(v)
            return v
        except ValueError:
            # Not an IP, that's okay - could be a port range, hostname, etc.
            pass
        
        # Basic sanitation - ensure it's not empty and reasonable length
        if not v or len(v) > 500:
            raise ValueError('Target must be non-empty and less than 500 characters')
        return v


class RuleApplyRequest(BaseModel):
    expires_hours: int = 24

    @validator("expires_hours")
    def validate_expires_hours(cls, v):
        if v < 1 or v > 24 * 30:
            raise ValueError("expires_hours must be between 1 and 720")
        return v


def _is_benign_local_control_alert(alert: AlertCreate) -> bool:
    """
    Suppress expected local discovery/control-plane noise from alert creation.
    This is a defense-in-depth safeguard in addition to brain-side filtering.
    """
    protocol = (alert.protocol or "").upper()
    category = (alert.threat_category or "").lower()
    src_port = alert.src_port or 0
    dst_port = alert.dst_port or 0

    try:
        src_ip_obj = ipaddress.ip_address(alert.src_ip)
        dst_ip_obj = ipaddress.ip_address(alert.dst_ip)
    except ValueError:
        return False

    if protocol in {"ICMPV6", "ICMP"} and dst_ip_obj.is_multicast:
        if src_ip_obj.is_unspecified or src_ip_obj.is_link_local or src_ip_obj.is_private:
            return True

    if protocol == "UDP" and (src_port in LOCAL_DISCOVERY_PORTS or dst_port in LOCAL_DISCOVERY_PORTS):
        if dst_ip_obj.is_multicast and (src_ip_obj.is_private or src_ip_obj.is_link_local or src_ip_obj.is_loopback):
            return True

    if category == "anomalous_behavior":
        if dst_ip_obj.is_multicast and (src_ip_obj.is_unspecified or src_ip_obj.is_link_local or src_ip_obj.is_private):
            return True

    return False

@app.get("/healthz")
def healthz():
    return {"status": "Revenix API OK"}

@app.get("/health")
def health():
    return {"status": "Revenix API OK"}

# ============================================================================
# SIMPLE AUTHENTICATION (For School Competition)
# ============================================================================

@app.get("/auth/check-users")
async def check_users(session: AsyncSession = Depends(get_session)):
    """Check if any users exist in the database"""
    try:
        count = await check_user_count(session)
        return {"user_count": count}
    except Exception as e:
        return {"user_count": 0}

@app.post("/auth/signup")
async def signup(user: SimpleUser, session: AsyncSession = Depends(get_session)):
    """Register first admin user with JWT token"""
    try:
        # Check if users already exist
        count = await check_user_count(session)
        if count > 0:
            raise HTTPException(
                status_code=403,
                detail="Signup is disabled after initial setup. Please login.",
            )
        
        new_user = await create_user(session, user)
        if not new_user:
            raise HTTPException(
                status_code=403,
                detail="Signup is disabled after initial setup. Please login.",
            )
        
        # Create JWT token
        access_token = create_access_token(
            data={"sub": new_user["username"], "user_id": new_user["id"], "role": new_user.get("role", "user")}
        )
        
        return {
            "success": True, 
            "user": new_user,
            "access_token": access_token,
            "token_type": "bearer"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Signup failed: {str(e)}")

@app.post("/auth/login")
async def login(credentials: SimpleLogin, session: AsyncSession = Depends(get_session)):
    """Login with JWT token"""
    try:
        user = await verify_user(session, credentials)
        if not user:
            raise HTTPException(status_code=401, detail="Invalid username or password")
        
        # Create JWT token
        access_token = create_access_token(
            data={"sub": user["username"], "user_id": user["id"], "role": user.get("role", "user")}
        )
        
        return {
            "success": True, 
            "user": user,
            "access_token": access_token,
            "token_type": "bearer"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Login failed: {str(e)}")

# DEVICE REGISTRATION (NOW PROTECTED)
# ============================================================================

@app.post("/register")
async def register_device(device: DeviceRegistration, session: AsyncSession = Depends(get_session)):
    """Register a new device or update its last_seen timestamp"""
    await session.execute(
        text("""
            INSERT INTO agents (agent_id, hostname, ip, last_seen, status)
            VALUES (:agent_id, :hostname, :ip, NOW(), 'active')
            ON CONFLICT (agent_id)
            DO UPDATE SET
                hostname = EXCLUDED.hostname,
                ip = EXCLUDED.ip,
                last_seen = NOW(),
                status = 'active'
        """),
        {"agent_id": device.agent_id, "hostname": device.hostname, "ip": device.ip or "auto"}
    )
    await session.commit()
    return {"status": "registered", "agent_id": device.agent_id}

@app.get("/devices")
async def get_devices(session: AsyncSession = Depends(get_session)):
    """Get all registered devices"""
    result = await session.execute(
        text("SELECT agent_id, hostname, ip, last_seen, status, created_at FROM agents ORDER BY last_seen DESC")
    )
    rows = result.fetchall()

    devices = []
    for row in rows:
        devices.append({
            "agent_id": row[0],
            "hostname": row[1],
            "ip": row[2],
            "last_seen": row[3].isoformat() if row[3] else None,
            "status": row[4],
            "created_at": row[5].isoformat() if row[5] else None,
        })

    return devices

@app.get("/flows/recent")
async def get_recent_flows(
    limit: int = Query(default=250, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
):
    """Get flows from the last 24 hours with capped pagination."""
    try:
        configured_cap = await get_model_config_value(session, "max_flows_stored", 1000, "integer")
        max_flows = max(1, int(configured_cap))

        if offset >= max_flows:
            return []

        effective_limit = min(limit, max_flows - offset)

        result = await session.execute(
            text("""
                SELECT id, flow_id, hostname, src_ip, dst_ip, src_port, dst_port,
                       protocol, bytes, packets, start_ts, end_ts, timestamp,
                       verified_benign, analyzed_at, analysis_version, training_excluded,
                       flow_count, last_seen
                FROM flows
                WHERE timestamp > NOW() - INTERVAL '24 hours'
                ORDER BY end_ts DESC, id DESC
                LIMIT :limit
                OFFSET :offset
            """),
            {"limit": effective_limit, "offset": offset}
        )
        rows = result.fetchall()
        return [_flow_row_to_dict(row) for row in rows]
    except Exception as e:
        print(f"Error fetching flows: {e}")
        return []

@app.get("/flows/unanalyzed")
async def get_unanalyzed_flows(session: AsyncSession = Depends(get_session)):
    """Get flows that haven't been analyzed yet"""
    try:
        result = await session.execute(
            text("""
                SELECT id, flow_id, hostname, src_ip, dst_ip, src_port, dst_port,
                       protocol, bytes, packets, start_ts, end_ts, timestamp,
                       verified_benign, training_excluded
                FROM flows
                WHERE analyzed_at IS NULL
                ORDER BY end_ts DESC
                LIMIT 100
            """)
        )
        rows = result.fetchall()

        flows = []
        for row in rows:
            flows.append({
                "id": row[0],
                "flow_id": row[1],
                "hostname": row[2],
                "src_ip": row[3],
                "dst_ip": row[4],
                "src_port": row[5],
                "dst_port": row[6],
                "protocol": row[7],
                "bytes": row[8],
                "packets": row[9],
                "start_ts": row[10],
                "end_ts": row[11],
                "timestamp": row[12].isoformat() if row[12] else None,
                "verified_benign": row[13],
                "training_excluded": row[14],
            })

        return flows
    except Exception as e:
        print(f"Error fetching unanalyzed flows: {e}")
        import traceback
        traceback.print_exc()
        return []

@app.get("/flows/training-safe")
async def get_training_safe_flows(session: AsyncSession = Depends(get_session)):
    """Get flows safe for model training (verified benign or >24hrs old without alerts)"""
    try:
        result = await session.execute(
            text("""
                SELECT id, flow_id, hostname, src_ip, dst_ip, src_port, dst_port,
                       protocol, bytes, packets, start_ts, end_ts, timestamp,
                       verified_benign, training_excluded
                FROM flows
                WHERE (
                    verified_benign = TRUE
                    OR (
                        timestamp < NOW() - INTERVAL '24 hours'
                        AND training_excluded = FALSE
                    )
                )
                AND training_excluded = FALSE
                ORDER BY timestamp DESC
                LIMIT 1000
            """)
        )
        rows = result.fetchall()

        flows = []
        for row in rows:
            flows.append({
                "id": row[0],
                "flow_id": row[1],
                "hostname": row[2],
                "src_ip": row[3],
                "dst_ip": row[4],
                "src_port": row[5],
                "dst_port": row[6],
                "protocol": row[7],
                "bytes": row[8],
                "packets": row[9],
                "start_ts": row[10],
                "end_ts": row[11],
                "timestamp": row[12].isoformat() if row[12] else None,
                "verified_benign": row[13],
                "training_excluded": row[14],
            })

        return flows
    except Exception as e:
        print(f"Error fetching training-safe flows: {e}")
        import traceback
        traceback.print_exc()
        return []

@app.get("/flows/count-by-device")
async def get_flow_counts_by_device(session: AsyncSession = Depends(get_session)):
    """Return stored flow counts grouped by hostname."""
    try:
        result = await session.execute(
            text("""
                SELECT hostname, COUNT(*)
                FROM flows
                GROUP BY hostname
            """)
        )
        rows = result.fetchall()
        return {row[0]: row[1] for row in rows}
    except Exception as e:
        print(f"Error fetching flow counts: {e}")
        return {}


@app.get("/flows/live-stats")
async def get_live_flow_stats(
    window_seconds: int = Query(default=30, ge=5, le=3600),
    session: AsyncSession = Depends(get_session),
):
    """Get uncapped flow statistics for live dashboards."""
    try:
        now_epoch = int(time.time())
        window_start = now_epoch - int(window_seconds)

        result = await session.execute(
            text("""
                WITH recent AS (
                    SELECT
                        COUNT(*) AS active_flows,
                        COALESCE(SUM(packets), 0) AS total_packets,
                        COALESCE(SUM(bytes), 0) AS total_bytes
                    FROM flows
                    WHERE end_ts >= :window_start
                ),
                totals AS (
                    SELECT COUNT(*) AS total_flows
                    FROM flows
                )
                SELECT
                    totals.total_flows,
                    recent.active_flows,
                    ROUND(recent.total_packets::numeric / :window_seconds)::BIGINT AS packets_per_sec,
                    ROUND(recent.total_bytes::numeric / :window_seconds)::BIGINT AS bytes_per_sec
                FROM totals, recent
            """),
            {"window_start": window_start, "window_seconds": window_seconds},
        )
        row = result.fetchone()
        if not row:
            return {
                "window_seconds": window_seconds,
                "total_flows": 0,
                "active_flows": 0,
                "packets_per_sec": 0,
                "bytes_per_sec": 0,
            }

        return {
            "window_seconds": window_seconds,
            "total_flows": int(row[0] or 0),
            "active_flows": int(row[1] or 0),
            "packets_per_sec": int(row[2] or 0),
            "bytes_per_sec": int(row[3] or 0),
        }
    except Exception as e:
        print(f"Error fetching live flow stats: {e}")
        return {
            "window_seconds": window_seconds,
            "total_flows": 0,
            "active_flows": 0,
            "packets_per_sec": 0,
            "bytes_per_sec": 0,
        }

@app.get("/devices/profiles")
async def get_device_profiles_proxy():
    """Proxy endpoint to get device profiles from Brain API."""
    try:
        async with aiohttp.ClientSession() as client:
            async with client.get(
                "http://brain:8001/devices/profiles",
                headers=_internal_service_headers(),
                timeout=aiohttp.ClientTimeout(total=5),
            ) as resp:
                if resp.status == 200:
                    return await resp.json()
                elif resp.status == 401:
                    # Brain requires auth - return empty for now
                    return {"profiles": [], "total_devices": 0, "totalFlows": 0}
                else:
                    return {"profiles": [], "total_devices": 0, "totalFlows": 0}
    except Exception as e:
        print(f"Error fetching device profiles from Brain: {e}")
        return {"profiles": [], "total_devices": 0, "totalFlows": 0}

@app.get("/flows")
async def get_all_flows(
    limit: int = Query(default=250, ge=1, le=2000),
    offset: int = Query(default=0, ge=0),
    session: AsyncSession = Depends(get_session),
):
    """Get all flows with pagination."""
    try:
        result = await session.execute(
            text("""
                SELECT id, flow_id, hostname, src_ip, dst_ip, src_port, dst_port,
                       protocol, bytes, packets, start_ts, end_ts, timestamp,
                       verified_benign, analyzed_at, analysis_version, training_excluded,
                       flow_count, last_seen
                FROM flows
                ORDER BY timestamp DESC, id DESC
                LIMIT :limit
                OFFSET :offset
            """),
            {"limit": limit, "offset": offset}
        )
        rows = result.fetchall()
        return [_flow_row_to_dict(row) for row in rows]
    except Exception as e:
        print(f"Error fetching flows: {e}")
        import traceback
        traceback.print_exc()
        return []

@app.post("/flows/{flow_id}/mark-analyzed")
async def mark_flow_analyzed(flow_id: int, session: AsyncSession = Depends(get_session)):
    """Mark a flow as analyzed to prevent re-processing"""
    try:
        await session.execute(
            text("""
                UPDATE flows
                SET analyzed_at = NOW(), analysis_version = 1
                WHERE id = :flow_id
            """),
            {"flow_id": flow_id}
        )
        await session.commit()
        return {"status": "updated", "flow_id": flow_id}
    except Exception as e:
        print(f"Error marking flow analyzed: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/flows/{flow_id}/exclude-from-training")
async def exclude_flow_from_training(flow_id: int, session: AsyncSession = Depends(get_session)):
    """Mark a flow as excluded from training (triggered an alert)"""
    try:
        await session.execute(
            text("""
                UPDATE flows
                SET training_excluded = TRUE
                WHERE id = :flow_id
            """),
            {"flow_id": flow_id}
        )
        await session.commit()
        return {"status": "updated", "flow_id": flow_id}
    except Exception as e:
        print(f"Error excluding flow from training: {e}")
        return {"status": "error", "message": str(e)}

@app.get("/alerts/recent")
async def get_recent_alerts(
    limit: int = Query(default=100, ge=1, le=1000),
    session: AsyncSession = Depends(get_session),
):
    """Get recent alerts with configurable limit."""
    try:
        result = await session.execute(
            text("""
                SELECT id, flow_id, hostname, src_ip, dst_ip, src_port, dst_port,
                       protocol, risk_score, severity, reason, threat_category,
                       EXTRACT(EPOCH FROM timestamp) as timestamp_epoch
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT :limit
            """),
            {"limit": limit}
        )
        rows = result.fetchall()

        alerts = []
        for row in rows:
            alerts.append({
                "id": row[0],
                "flow_id": row[1],
                "hostname": row[2],
                "src_ip": row[3],
                "dst_ip": row[4],
                "src_port": row[5],
                "dst_port": row[6],
                "protocol": row[7],
                "risk_score": row[8],
                "severity": row[9],
                "reason": row[10],
                "threat_category": row[11],  # Include threat category
                "timestamp": row[12],  # Unix timestamp in seconds (UTC)
            })

        return alerts
    except Exception as e:
        print(f"[v0] Error fetching alerts: {e}")
        import traceback
        traceback.print_exc()
        return []


@app.delete("/alerts/{alert_id}")
async def delete_alert(alert_id: int, session: AsyncSession = Depends(get_session)):
    """Delete a single alert by ID."""
    try:
        result = await session.execute(
            text("DELETE FROM alerts WHERE id = :alert_id RETURNING id"),
            {"alert_id": alert_id},
        )
        row = result.fetchone()
        if not row:
            return {"status": "not_found", "alert_id": alert_id}
        await session.commit()
        return {"status": "deleted", "alert_id": alert_id}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete alert {alert_id}: {exc}")


@app.post("/alerts/delete-batch")
async def delete_alert_batch(payload: AlertDeleteBatch, session: AsyncSession = Depends(get_session)):
    """Delete multiple alerts by ID."""
    try:
        unique_ids = sorted({int(alert_id) for alert_id in payload.alert_ids if int(alert_id) > 0})
        if not unique_ids:
            return {"status": "skipped", "deleted_count": 0, "deleted_ids": []}

        stmt = text("DELETE FROM alerts WHERE id IN :ids RETURNING id").bindparams(
            bindparam("ids", expanding=True)
        )
        result = await session.execute(stmt, {"ids": unique_ids})
        deleted_ids = [int(row[0]) for row in result.fetchall()]
        await session.commit()
        return {
            "status": "deleted",
            "deleted_count": len(deleted_ids),
            "deleted_ids": deleted_ids,
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete alerts: {exc}")

@app.post("/alerts/create")
async def create_alert(alert: AlertCreate, session: AsyncSession = Depends(get_session)):
    """Create a new alert if risk_score exceeds threshold"""
    RISK_THRESHOLD = 0.75

    if alert.risk_score <= RISK_THRESHOLD:
        return {"status": "skipped", "reason": "risk_score below threshold", "threshold": RISK_THRESHOLD}

    if _is_benign_local_control_alert(alert):
        return {"status": "skipped", "reason": "benign local control-plane traffic"}

    if not alert.severity:
        if alert.risk_score >= 0.9:
            severity = "critical"
        elif alert.risk_score >= 0.8:
            severity = "high"
        elif alert.risk_score >= 0.7:
            severity = "medium"
        else:
            severity = "low"
    else:
        severity = alert.severity

    category_log = f"[{alert.threat_category}] " if alert.threat_category else ""
    print(f"[API] {category_log}Creating alert: {alert.hostname} - {alert.reason[:100]}... (risk: {alert.risk_score:.2f})")

    result = await session.execute(
        text("""
            INSERT INTO alerts (flow_id, hostname, src_ip, dst_ip, src_port, dst_port, protocol, risk_score, severity, reason, threat_category)
            VALUES (:flow_id, :hostname, :src_ip, :dst_ip, :src_port, :dst_port, :protocol, :risk_score, :severity, :reason, :threat_category)
            RETURNING id
        """),
        {
            "flow_id": alert.flow_id,
            "hostname": alert.hostname,
            "src_ip": alert.src_ip,
            "dst_ip": alert.dst_ip,
            "src_port": alert.src_port,
            "dst_port": alert.dst_port,
            "protocol": alert.protocol or "unknown",
            "risk_score": alert.risk_score,
            "severity": severity,
            "reason": alert.reason,
            "threat_category": alert.threat_category,  # Store threat category
        }
    )
    alert_id = result.fetchone()[0]
    await session.commit()

    alert_payload = {
        "id": alert_id,
        "flow_id": alert.flow_id,
        "hostname": alert.hostname,
        "src_ip": alert.src_ip,
        "dst_ip": alert.dst_ip,
        "src_port": alert.src_port,
        "dst_port": alert.dst_port,
        "protocol": alert.protocol or "unknown",
        "risk_score": alert.risk_score,
        "severity": severity,
        "reason": alert.reason,
        "threat_category": alert.threat_category,
        "timestamp": datetime.utcnow().isoformat() + "Z",
    }

    # Broadcast alert via WebSocket for real-time updates.
    await broadcast_alert({**alert_payload, "timestamp": datetime.utcnow().timestamp()})

    # Trigger alert integrations without impacting main alert creation path.
    try:
        await dispatch_alert_notifications(session, alert_payload)
    except Exception as exc:
        print(f"[Alerting] Failed auto-dispatch for alert {alert_id}: {exc}")

    return {"status": "created", "alert_id": alert_id, "severity": severity, "risk_score": alert.risk_score}

@app.post("/rules/create")
async def create_rule(rule: RuleCreate, session: AsyncSession = Depends(get_session)):
    """Create a new firewall rule recommendation"""
    await session.execute(
        text("""
            INSERT INTO rules (alert_id, rule_type, action, target, reason, confidence, status)
            VALUES (:alert_id, :rule_type, :action, :target, :reason, :confidence, 'pending')
        """),
        {
            "alert_id": rule.alert_id,
            "rule_type": rule.rule_type,
            "action": rule.action,
            "target": rule.target,
            "reason": rule.reason,
            "confidence": rule.confidence,
        }
    )
    await session.commit()
    
    # Broadcast rule via WebSocket for real-time updates
    await broadcast_rule({
        "alert_id": rule.alert_id,
        "rule_type": rule.rule_type,
        "action": rule.action,
        "target": rule.target,
        "reason": rule.reason,
        "confidence": rule.confidence,
        "timestamp": datetime.utcnow().timestamp()
    })
    
    return {"status": "created", "rule_type": rule.rule_type, "action": rule.action}

@app.get("/rules/recent")
async def get_recent_rules(
    limit: int = Query(default=100, ge=1, le=1000),
    session: AsyncSession = Depends(get_session),
):
    """Get recent rule recommendations with configurable limit."""
    try:
        result = await session.execute(
            text("""
                SELECT r.id, r.alert_id, r.rule_type, r.action, r.target,
                       r.reason, r.confidence, r.status,
                       EXTRACT(EPOCH FROM r.created_at) as created_at_epoch,
                       a.hostname, a.src_ip, a.severity, a.risk_score
                FROM rules r
                JOIN alerts a ON r.alert_id = a.id
                ORDER BY r.created_at DESC
                LIMIT :limit
            """),
            {"limit": limit}
        )
        rows = result.fetchall()

        rules = []
        for row in rows:
            rules.append({
                "id": row[0],
                "alert_id": row[1],
                "rule_type": row[2],
                "action": row[3],
                "target": row[4],
                "reason": row[5],
                "confidence": row[6],
                "status": row[7],
                "created_at": row[8],  # Unix timestamp in seconds (UTC)
                "hostname": row[9],
                "src_ip": row[10],
                "severity": row[11],
                "risk_score": row[12],
            })

        return rules
    except Exception as e:
        print(f"Error fetching rules: {e}")
        return []

@app.get("/rules/recommended")
async def get_recommended_rules(
    limit: int = Query(default=100, ge=1, le=1000),
    session: AsyncSession = Depends(get_session),
):
    """Alias for /rules/recent - get recommended firewall rules."""
    return await get_recent_rules(limit=limit, session=session)


@app.post("/rules/{rule_id}/apply")
async def apply_rule(
    rule_id: int,
    payload: RuleApplyRequest | None = None,
    session: AsyncSession = Depends(get_session),
):
    """Apply a pending firewall rule by enforcing block policy."""
    try:
        rule_result = await session.execute(
            text("""
                SELECT id, alert_id, rule_type, action, target, reason, confidence, status
                FROM rules
                WHERE id = :rule_id
            """),
            {"rule_id": rule_id}
        )
        row = rule_result.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

        action = (row[3] or "").upper()
        target = row[4]
        status = row[7]
        expires_hours = payload.expires_hours if payload else 24

        if status == "applied":
            return {
                "status": "already_applied",
                "rule_id": rule_id,
                "target": target,
            }

        if action != "BLOCK":
            raise HTTPException(
                status_code=400,
                detail=f"Only BLOCK rules can be auto-applied right now (got action={action})"
            )

        if not _is_ip_address(target):
            raise HTTPException(
                status_code=400,
                detail=f"Rule target '{target}' is not an IP address and cannot be blocked automatically"
            )

        if _is_protected_infrastructure_ip(target):
            raise HTTPException(
                status_code=400,
                detail=f"Refusing to block protected infrastructure IP {target}"
            )

        alert_meta = await session.execute(
            text("SELECT threat_category FROM alerts WHERE id = :alert_id"),
            {"alert_id": row[1]}
        )
        alert_row = alert_meta.fetchone()
        threat_category = alert_row[0] if alert_row else None

        await session.execute(
            text("""
                INSERT INTO blocked_ips (
                    ip, block_reason, confidence, expires_at, threat_category,
                    manual_override, alert_count, auto_blocked, added_by, notes, permanent
                )
                VALUES (
                    :ip, :block_reason, :confidence, NOW() + INTERVAL '1 hour' * :expires_hours,
                    :threat_category, TRUE, 1, FALSE, 'rule_engine', :notes, FALSE
                )
                ON CONFLICT (ip)
                DO UPDATE SET
                    block_reason = EXCLUDED.block_reason,
                    confidence = GREATEST(blocked_ips.confidence, EXCLUDED.confidence),
                    expires_at = GREATEST(blocked_ips.expires_at, EXCLUDED.expires_at),
                    threat_category = COALESCE(EXCLUDED.threat_category, blocked_ips.threat_category),
                    manual_override = TRUE,
                    auto_blocked = FALSE,
                    updated_at = NOW()
            """),
            {
                "ip": target,
                "block_reason": row[5] or f"Applied by rule {rule_id}",
                "confidence": max(0.0, min(1.0, float(row[6] or 0.0))),
                "expires_hours": expires_hours,
                "threat_category": threat_category,
                "notes": f"Applied from rule #{rule_id}",
            }
        )

        await session.execute(
            text("""
                INSERT INTO block_history (ip, blocked_at, reason, threat_category)
                VALUES (:ip, NOW(), :reason, :threat_category)
            """),
            {
                "ip": target,
                "reason": row[5] or f"Applied by rule {rule_id}",
                "threat_category": threat_category
            }
        )

        await session.execute(
            text("""
                UPDATE rules
                SET status = 'applied'
                WHERE id = :rule_id
            """),
            {"rule_id": rule_id}
        )

        await session.execute(
            text("""
                INSERT INTO firewall_sync_log (action, ip, success, error_message, execution_time_ms)
                VALUES ('block', :ip, TRUE, :message, 0)
            """),
            {
                "ip": target,
                "message": f"Queued by /rules/{rule_id}/apply and pending firewall sync"
            }
        )
        await session.commit()

        await broadcast_rule({
            "id": rule_id,
            "alert_id": row[1],
            "rule_type": row[2],
            "action": action,
            "target": target,
            "status": "applied",
            "timestamp": datetime.utcnow().timestamp()
        })

        return {
            "status": "applied",
            "rule_id": rule_id,
            "target": target,
            "expires_hours": expires_hours,
            "message": "Rule applied and queued for firewall synchronization",
        }
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error applying rule {rule_id}: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Failed to apply rule: {e}")


@app.post("/rules/{rule_id}/reject")
async def reject_rule(rule_id: int, session: AsyncSession = Depends(get_session)):
    """Reject a pending firewall rule recommendation."""
    try:
        result = await session.execute(
            text("""
                UPDATE rules
                SET status = 'rejected'
                WHERE id = :rule_id
                RETURNING id, alert_id, rule_type, action, target
            """),
            {"rule_id": rule_id}
        )
        row = result.fetchone()
        if not row:
            raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")

        await session.commit()

        await broadcast_rule({
            "id": row[0],
            "alert_id": row[1],
            "rule_type": row[2],
            "action": row[3],
            "target": row[4],
            "status": "rejected",
            "timestamp": datetime.utcnow().timestamp()
        })

        return {"status": "rejected", "rule_id": row[0]}
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error rejecting rule {rule_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to reject rule: {e}")

# ============================================================================
# SELF-HEALING ENDPOINTS
# Phase 1 Week 1: Persistent Self-Healing State
# ============================================================================

class TrustedIPCreate(BaseModel):
    ip: str
    confidence: float = 0.5
    auto_added: bool = True
    metadata: dict = {}

class BlockedIPCreate(BaseModel):
    ip: str
    block_reason: str
    confidence: float
    expires_hours: int = 24
    threat_category: str | None = None
    manual_override: bool = False

class AIFeedbackCreate(BaseModel):
    alert_id: int
    feedback_type: str  # 'false_positive', 'missed_threat', 'correct', 'severity_wrong', 'category_wrong'
    user_notes: str | None = None
    corrected_severity: str | None = None
    corrected_category: str | None = None
    corrected_by: str = "system"

@app.get("/self-healing/trusted-ips")
async def get_trusted_ips(session: AsyncSession = Depends(get_session)):
    """Get all trusted IPs from the database"""
    try:
        result = await session.execute(
            text("""
                SELECT ip, first_seen, last_verified, good_flows, total_flows,
                       avg_risk_score, auto_added, confidence, destinations_count,
                       last_seen, metadata, created_at, permanent, added_by, notes
                FROM trusted_ips
                ORDER BY confidence DESC, last_seen DESC
            """)
        )
        rows = result.fetchall()
        
        trusted_ips = []
        for row in rows:
            trusted_ips.append({
                "ip": row[0],
                "first_seen": row[1].isoformat() if row[1] else None,
                "last_verified": row[2].isoformat() if row[2] else None,
                "good_flows": row[3],
                "total_flows": row[4],
                "avg_risk_score": row[5],
                "auto_added": row[6],
                "confidence": row[7],
                "destinations_count": row[8],
                "last_seen": row[9].isoformat() if row[9] else None,
                "metadata": row[10],
                "created_at": row[11].isoformat() if row[11] else None,
                "permanent": row[12],
                "added_by": row[13],
                "notes": row[14],
            })
        
        return trusted_ips
    except Exception as e:
        print(f"Error fetching trusted IPs: {e}")
        import traceback
        traceback.print_exc()
        return []

@app.get("/policies/trusted")
async def get_policies_trusted(session: AsyncSession = Depends(get_session)):
    """Alias for self-healing trusted IPs (UI compatibility)."""
    return await get_trusted_ips(session)

@app.post("/self-healing/trusted-ips/add")
async def add_trusted_ip(trusted_ip: TrustedIPCreate, session: AsyncSession = Depends(get_session)):
    """Add or update a trusted IP"""
    try:
        await session.execute(
            text("""
                INSERT INTO trusted_ips (ip, confidence, auto_added, metadata, good_flows, total_flows)
                VALUES (:ip, :confidence, :auto_added, :metadata::jsonb, 1, 1)
                ON CONFLICT (ip)
                DO UPDATE SET
                    confidence = EXCLUDED.confidence,
                    last_verified = NOW(),
                    last_seen = NOW(),
                    updated_at = NOW()
            """),
            {
                "ip": trusted_ip.ip,
                "confidence": trusted_ip.confidence,
                "auto_added": trusted_ip.auto_added,
                "metadata": trusted_ip.metadata or {}
            }
        )
        await session.commit()
        print(f"[SelfHealing] ✓ Added trusted IP: {trusted_ip.ip} (confidence: {trusted_ip.confidence:.2f})")
        return {"status": "added", "ip": trusted_ip.ip}
    except Exception as e:
        print(f"Error adding trusted IP: {e}")
        return {"status": "error", "message": str(e)}

@app.get("/self-healing/blocked-ips")
async def get_blocked_ips(session: AsyncSession = Depends(get_session)):
    """Get all currently blocked IPs"""
    try:
        result = await session.execute(
            text("""
                SELECT ip, blocked_at, expires_at, block_reason, confidence,
                       alert_count, manual_override, threat_category, auto_blocked,
                       EXTRACT(EPOCH FROM (expires_at - NOW()))/3600 as hours_remaining,
                       permanent, added_by, notes
                FROM blocked_ips
                WHERE expires_at > NOW() OR manual_override = TRUE OR permanent = TRUE
                ORDER BY blocked_at DESC
            """)
        )
        rows = result.fetchall()
        
        blocked_ips = []
        for row in rows:
            blocked_ips.append({
                "ip": row[0],
                "blocked_at": row[1].isoformat() if row[1] else None,
                "expires_at": row[2].isoformat() if row[2] else None,
                "block_reason": row[3],
                "confidence": row[4],
                "alert_count": row[5],
                "manual_override": row[6],
                "threat_category": row[7],
                "auto_blocked": row[8],
                "hours_remaining": max(0, row[9]) if row[9] is not None else None,
                "permanent": row[10],
                "added_by": row[11],
                "notes": row[12],
            })
        
        return blocked_ips
    except Exception as e:
        print(f"Error fetching blocked IPs: {e}")
        import traceback
        traceback.print_exc()
        return []

@app.get("/policies/blocked")
async def get_policies_blocked(session: AsyncSession = Depends(get_session)):
    """Alias for self-healing blocked IPs (UI compatibility)."""
    return await get_blocked_ips(session)

@app.post("/policies/block")
async def block_ip_policy(blocked_ip: BlockedIPCreate, session: AsyncSession = Depends(get_session)):
    """Block an IP address (policy endpoint alias)"""
    return await add_blocked_ip(blocked_ip, session)

@app.post("/self-healing/blocked-ips/add")
async def add_blocked_ip(blocked_ip: BlockedIPCreate, session: AsyncSession = Depends(get_session)):
    """Block an IP address"""
    try:
        if _is_protected_infrastructure_ip(blocked_ip.ip):
            msg = (
                f"Refusing to block protected infrastructure IP {blocked_ip.ip}. "
                "Blocking this can disconnect monitoring or network access."
            )
            print(f"[SelfHealing] ⚠️ {msg}")
            return {"status": "rejected", "ip": blocked_ip.ip, "message": msg}

        await session.execute(
            text("""
                INSERT INTO blocked_ips (ip, block_reason, confidence, expires_at, 
                                        threat_category, manual_override, alert_count, auto_blocked)
                VALUES (:ip, :block_reason, :confidence, 
                        NOW() + INTERVAL '1 hour' * :expires_hours,
                        :threat_category, :manual_override, 1, :auto_blocked)
                ON CONFLICT (ip)
                DO UPDATE SET
                    block_reason = EXCLUDED.block_reason,
                    confidence = EXCLUDED.confidence,
                    expires_at = EXCLUDED.expires_at,
                    alert_count = blocked_ips.alert_count + 1,
                    updated_at = NOW()
            """),
            {
                "ip": blocked_ip.ip,
                "block_reason": blocked_ip.block_reason,
                "confidence": blocked_ip.confidence,
                "expires_hours": blocked_ip.expires_hours,
                "threat_category": blocked_ip.threat_category,
                "manual_override": blocked_ip.manual_override,
                "auto_blocked": not blocked_ip.manual_override # Assuming auto_blocked is true if not manual
            }
        )
        await session.commit()
        
        # Log to block history
        await session.execute(
            text("""
                INSERT INTO block_history (ip, blocked_at, reason, threat_category)
                VALUES (:ip, NOW(), :reason, :threat_category)
            """),
            {
                "ip": blocked_ip.ip,
                "reason": blocked_ip.block_reason,
                "threat_category": blocked_ip.threat_category
            }
        )
        await session.commit()
        
        print(f"[SelfHealing] 🚫 Blocked IP: {blocked_ip.ip} for {blocked_ip.expires_hours}h - {blocked_ip.block_reason}")
        return {"status": "blocked", "ip": blocked_ip.ip, "expires_hours": blocked_ip.expires_hours}
    except Exception as e:
        print(f"Error blocking IP: {e}")
        import traceback
        traceback.print_exc()
        return {"status": "error", "message": str(e)}

@app.delete("/self-healing/blocked-ips/{ip}/unblock")
async def unblock_ip(ip: str, session: AsyncSession = Depends(get_session)):
    """Manually unblock an IP address"""
    try:
        # Update block history
        await session.execute(
            text("""
                UPDATE block_history
                SET unblocked_at = NOW(),
                    duration_seconds = EXTRACT(EPOCH FROM (NOW() - blocked_at))
                WHERE ip = :ip AND unblocked_at IS NULL
            """),
            {"ip": ip}
        )
        
        # Remove from blocked_ips
        await session.execute(
            text("DELETE FROM blocked_ips WHERE ip = :ip"),
            {"ip": ip}
        )
        await session.commit()
        
        print(f"[SelfHealing] ✓ Unblocked IP: {ip}")
        return {"status": "unblocked", "ip": ip}
    except Exception as e:
        print(f"Error unblocking IP: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/self-healing/feedback")
async def submit_ai_feedback(feedback: AIFeedbackCreate, session: AsyncSession = Depends(get_session)):
    """Submit feedback on AI decision for continuous learning"""
    try:
        # Get alert details for context
        alert_result = await session.execute(
            text("SELECT src_ip, threat_category FROM alerts WHERE id = :alert_id"),
            {"alert_id": feedback.alert_id}
        )
        alert_row = alert_result.fetchone()
        
        if not alert_row:
            return {"status": "error", "message": "Alert not found"}
        
        src_ip, threat_category = alert_row
        
        # Insert feedback
        await session.execute(
            text("""
                INSERT INTO ai_feedback (alert_id, feedback_type, user_notes, 
                                        corrected_severity, corrected_category, 
                                        corrected_by, ip_affected)
                VALUES (:alert_id, :feedback_type, :user_notes, 
                        :corrected_severity, :corrected_category, 
                        :corrected_by, :ip_affected)
            """),
            {
                "alert_id": feedback.alert_id,
                "feedback_type": feedback.feedback_type,
                "user_notes": feedback.user_notes,
                "corrected_severity": feedback.corrected_severity,
                "corrected_category": feedback.corrected_category,
                "corrected_by": feedback.corrected_by,
                "ip_affected": src_ip
            }
        )
        await session.commit()
        
        print(f"[SelfHealing] 📝 Received feedback: {feedback.feedback_type} for alert {feedback.alert_id}")
        return {"status": "feedback_recorded", "alert_id": feedback.alert_id}
    except Exception as e:
        print(f"Error submitting feedback: {e}")
        import traceback
        traceback.print_exc()
        return {"status": "error", "message": str(e)}

@app.get("/self-healing/stats")
async def get_self_healing_stats(session: AsyncSession = Depends(get_session)):
    """Get self-healing system statistics"""
    try:
        # Count trusted IPs
        trusted_result = await session.execute(
            text("SELECT COUNT(*) FROM trusted_ips")
        )
        trusted_count = trusted_result.scalar()
        
        # Count active blocks
        blocked_result = await session.execute(
            text("SELECT COUNT(*) FROM blocked_ips WHERE expires_at > NOW() OR manual_override = TRUE OR permanent = TRUE")
        )
        blocked_count = blocked_result.scalar()
        
        # Count feedback entries
        feedback_result = await session.execute(
            text("SELECT COUNT(*) FROM ai_feedback WHERE corrected_at > NOW() - INTERVAL '7 days'")
        )
        recent_feedback = feedback_result.scalar()
        
        # Get false positive rate
        fp_result = await session.execute(
            text("""
                SELECT COUNT(*) 
                FROM ai_feedback 
                WHERE feedback_type = 'false_positive' 
                AND corrected_at > NOW() - INTERVAL '7 days'
            """)
        )
        false_positives = fp_result.scalar()
        
        return {
            "trusted_ips": trusted_count,
            "blocked_ips": blocked_count,
            "recent_feedback_7d": recent_feedback,
            "false_positives_7d": false_positives,
            "false_positive_rate": false_positives / max(recent_feedback, 1) if recent_feedback > 0 else 0.0
        }
    except Exception as e:
        print(f"Error fetching self-healing stats: {e}")
        return {
            "trusted_ips": 0,
            "blocked_ips": 0,
            "recent_feedback_7d": 0,
            "false_positives_7d": 0,
            "false_positive_rate": 0.0
        }

@app.get("/self-healing/model-config")
async def get_model_config(session: AsyncSession = Depends(get_session)):
    """Get dynamic model configuration"""
    try:
        result = await session.execute(
            text("""
                SELECT config_key, config_value, config_type, description, updated_at
                FROM model_config
                ORDER BY config_key
            """)
        )
        rows = result.fetchall()
        
        config = {}
        for row in rows:
            key, value, type_str, description, updated_at = row
            
            # Parse value based on type
            if type_str == 'float':
                parsed_value = float(value)
            elif type_str == 'integer':
                parsed_value = int(value)
            elif type_str == 'boolean':
                parsed_value = value.lower() in ('true', '1', 'yes')
            elif type_str == 'json':
                import json
                parsed_value = json.loads(value)
            else:
                parsed_value = value
            
            config[key] = {
                "value": parsed_value,
                "description": description,
                "updated_at": updated_at.isoformat() if updated_at else None
            }
        
        return config
    except Exception as e:
        print(f"Error fetching model config: {e}")
        import traceback
        traceback.print_exc()
        return {}

@app.post("/self-healing/model-config/{config_key}")
async def update_model_config(config_key: str, new_value: str, updated_by: str = "api", session: AsyncSession = Depends(get_session)):
    """Update a model configuration value"""
    try:
        # Store previous value
        result = await session.execute(
            text("SELECT config_value FROM model_config WHERE config_key = :key"),
            {"key": config_key}
        )
        row = result.fetchone()
        previous_value = row[0] if row else None

        # Infer value type if new key
        def infer_type(value: str) -> str:
            lowered = value.lower()
            if lowered in ("true", "false"):
                return "boolean"
            try:
                int(value)
                return "integer"
            except ValueError:
                try:
                    float(value)
                    return "float"
                except ValueError:
                    return "string"

        if previous_value is None:
            config_type = infer_type(new_value)
            await session.execute(
                text("""
                    INSERT INTO model_config (config_key, config_value, config_type, description, updated_at, updated_by)
                    VALUES (:key, :value, :type, 'Created via API', NOW(), :updated_by)
                    ON CONFLICT (config_key) DO UPDATE SET
                        config_value = EXCLUDED.config_value,
                        config_type = EXCLUDED.config_type,
                        previous_value = model_config.config_value,
                        updated_at = NOW(),
                        updated_by = :updated_by
                """),
                {
                    "key": config_key,
                    "value": new_value,
                    "type": config_type,
                    "updated_by": updated_by
                }
            )
            await session.commit()
            print(f"[SelfHealing] ⚙️ Created config {config_key} = {new_value}")
            
            # Immediately notify brain service to reload config
            try:
                async with httpx.AsyncClient() as client:
                    brain_response = await client.post(
                        "http://brain:8001/admin/reload-config",
                        headers=_internal_service_headers(),
                        timeout=5.0,
                    )
                    if brain_response.status_code == 200:
                        print(f"[SelfHealing] ✓ Brain service reloaded config for {config_key}")
            except Exception as reload_error:
                print(f"[SelfHealing] ⚠ Could not notify brain service: {reload_error}")
            
            return {"status": "created", "config_key": config_key, "new_value": new_value}
        
        # Update config
        await session.execute(
            text("""
                UPDATE model_config
                SET config_value = :value,
                    previous_value = :previous,
                    updated_at = NOW(),
                    updated_by = :updated_by
                WHERE config_key = :key
            """),
            {
                "key": config_key,
                "value": new_value,
                "previous": previous_value,
                "updated_by": updated_by
            }
        )
        await session.commit()
        
        print(f"[SelfHealing] ⚙️ Updated config {config_key}: {previous_value} -> {new_value}")
        
        # Immediately notify brain service to reload config
        try:
            async with httpx.AsyncClient() as client:
                brain_response = await client.post(
                    "http://brain:8001/admin/reload-config",
                    headers=_internal_service_headers(),
                    timeout=5.0,
                )
                if brain_response.status_code == 200:
                    print(f"[SelfHealing] ✓ Brain service reloaded config for {config_key}")
                else:
                    print(f"[SelfHealing] ⚠ Brain reload returned {brain_response.status_code}")
        except Exception as reload_error:
            print(f"[SelfHealing] ⚠ Could not notify brain service: {reload_error}")
        
        return {"status": "updated", "config_key": config_key, "previous_value": previous_value, "new_value": new_value}
    except Exception as e:
        print(f"Error updating model config: {e}")
        return {"status": "error", "message": str(e)}

class PermanentIPAction(BaseModel):
    ip: str
    notes: str | None = None
    added_by: str = "admin"

@app.post("/self-healing/trusted-ips/permanent")
async def add_permanent_whitelist(data: PermanentIPAction, session: AsyncSession = Depends(get_session)):
    """Permanently whitelist an IP (never expires)"""
    try:
        await session.execute(
            text("""
                INSERT INTO trusted_ips (ip, confidence, auto_added, permanent, added_by, notes, good_flows, total_flows)
                VALUES (:ip, 1.0, FALSE, TRUE, :notes, :added_by, 0, 0)
                ON CONFLICT (ip)
                DO UPDATE SET
                    permanent = TRUE,
                    auto_added = FALSE,
                    confidence = 1.0,
                    added_by = EXCLUDED.added_by,
                    notes = EXCLUDED.notes,
                    last_verified = NOW(),
                    updated_at = NOW()
            """),
            {"ip": data.ip, "added_by": data.added_by, "notes": data.notes}
        )
        await session.commit()
        print(f"[SelfHealing] ✅ PERMANENTLY whitelisted: {data.ip} by {data.added_by}")
        return {"status": "whitelisted", "ip": data.ip, "permanent": True}
    except Exception as e:
        print(f"Error adding permanent whitelist: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/self-healing/blocked-ips/permanent")
async def add_permanent_block(data: PermanentIPAction, session: AsyncSession = Depends(get_session)):
    """Permanently block an IP (never expires)"""
    try:
        if _is_protected_infrastructure_ip(data.ip):
            msg = (
                f"Refusing to permanently block protected infrastructure IP {data.ip}. "
                "This may break connectivity."
            )
            print(f"[SelfHealing] ⚠️ {msg}")
            return {"status": "rejected", "ip": data.ip, "message": msg}

        await session.execute(
            text("""
                INSERT INTO blocked_ips (ip, block_reason, confidence, expires_at, permanent, manual_override, added_by, notes)
                VALUES (:ip, :notes, 1.0, '9999-12-31'::timestamp, TRUE, TRUE, :added_by, :notes)
                ON CONFLICT (ip)
                DO UPDATE SET
                    permanent = TRUE,
                    manual_override = TRUE,
                    expires_at = '9999-12-31'::timestamp,
                    confidence = 1.0,
                    added_by = EXCLUDED.added_by,
                    notes = EXCLUDED.notes,
                    updated_at = NOW()
            """),
            {"ip": data.ip, "added_by": data.added_by, "notes": data.notes or "Manually blocked"}
        )
        await session.commit()
        print(f"[SelfHealing] 🚫 PERMANENTLY blocked: {data.ip} by {data.added_by}")
        return {"status": "blocked", "ip": data.ip, "permanent": True}
    except Exception as e:
        print(f"Error adding permanent block: {e}")
        return {"status": "error", "message": str(e)}

@app.delete("/self-healing/trusted-ips/{ip}")
async def remove_from_whitelist(ip: str, session: AsyncSession = Depends(get_session)):
    """Remove an IP from the whitelist"""
    try:
        await session.execute(
            text("DELETE FROM trusted_ips WHERE ip = :ip"),
            {"ip": ip}
        )
        await session.commit()
        print(f"[SelfHealing] Removed from whitelist: {ip}")
        return {"status": "removed", "ip": ip}
    except Exception as e:
        print(f"Error removing from whitelist: {e}")
        return {"status": "error", "message": str(e)}

@app.get("/self-healing/firewall-status")
async def get_firewall_status(session: AsyncSession = Depends(get_session)):
    """Get firewall sync status and recent activity"""
    try:
        # Recent sync actions
        result = await session.execute(
            text("""
                SELECT action, ip, success, error_message, execution_time_ms, created_at
                FROM firewall_sync_log
                ORDER BY created_at DESC
                LIMIT 50
            """)
        )
        rows = result.fetchall()
        
        logs = [
            {
                "action": r[0],
                "ip": r[1],
                "success": r[2],
                "error": r[3],
                "execution_time_ms": r[4],
                "timestamp": r[5].isoformat() if r[5] else None
            }
            for r in rows
        ]
        
        # Stats
        stats_result = await session.execute(
            text("""
                SELECT 
                    COUNT(*) FILTER (WHERE success = TRUE AND created_at > NOW() - INTERVAL '1 hour') as successful_last_hour,
                    COUNT(*) FILTER (WHERE success = FALSE AND created_at > NOW() - INTERVAL '1 hour') as failed_last_hour,
                    AVG(execution_time_ms) FILTER (WHERE created_at > NOW() - INTERVAL '1 hour') as avg_execution_time
                FROM firewall_sync_log
            """)
        )
        stats = stats_result.fetchone()
        
        return {
            "status": "operational",
            "recent_logs": logs,
            "stats": {
                "successful_last_hour": stats[0] or 0,
                "failed_last_hour": stats[1] or 0,
                "avg_execution_time_ms": round(stats[2] or 0, 2)
            }
        }
    except Exception as e:
        print(f"Error getting firewall status: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/self-healing/firewall-sync-log")
async def log_firewall_sync(
    action: str,
    ip: str,
    success: bool,
    error_message: str | None = None,
    execution_time_ms: int = 0,
    session: AsyncSession = Depends(get_session)
):
    """Log a firewall sync action"""
    try:
        await session.execute(
            text("""
                INSERT INTO firewall_sync_log (action, ip, success, error_message, execution_time_ms)
                VALUES (:action, :ip, :success, :error_message, :execution_time_ms)
            """),
            {
                "action": action,
                "ip": ip,
                "success": success,
                "error_message": error_message,
                "execution_time_ms": execution_time_ms
            }
        )
        await session.commit()
        return {"status": "logged"}
    except Exception as e:
        print(f"Error logging firewall sync: {e}")
        return {"status": "error", "message": str(e)}

# ============================================================================
# FEEDBACK LOOP ENDPOINTS
# Phase 1 Week 1 Day 5-7: Learning from User Feedback
# ============================================================================

@app.get("/self-healing/feedback/recent")
async def get_recent_feedback(hours: int = 24, session: AsyncSession = Depends(get_session)):
    """Get recent feedback entries for analysis"""
    try:
        result = await session.execute(
            text("""
                SELECT id, alert_id, rule_id, feedback_type, user_notes,
                       corrected_severity, corrected_category, corrected_by,
                       corrected_at, features_at_time, model_version, ip_affected
                FROM ai_feedback
                WHERE corrected_at > NOW() - INTERVAL '1 hour' * :hours
                ORDER BY corrected_at DESC
            """),
            {"hours": hours}
        )
        rows = result.fetchall()
        
        feedback_entries = []
        for row in rows:
            feedback_entries.append({
                "id": row[0],
                "alert_id": row[1],
                "rule_id": row[2],
                "feedback_type": row[3],
                "user_notes": row[4],
                "corrected_severity": row[5],
                "corrected_category": row[6],
                "corrected_by": row[7],
                "corrected_at": row[8].isoformat() if row[8] else None,
                "features_at_time": row[9],
                "model_version": row[10],
                "ip_affected": row[11]
            })
        
        return feedback_entries
    except Exception as e:
        print(f"Error fetching feedback: {e}")
        import traceback
        traceback.print_exc()
        return []

@app.get("/self-healing/rule-effectiveness")
async def get_rule_effectiveness(session: AsyncSession = Depends(get_session)):
    """Get rule effectiveness data for all rules"""
    try:
        result = await session.execute(
            text("""
                SELECT rule_id, times_triggered, successful_blocks, false_blocks,
                       last_triggered, effectiveness_score, status, a_b_test_group, a_b_test_active
                FROM rule_effectiveness
                ORDER BY effectiveness_score DESC
            """)
        )
        rows = result.fetchall()
        
        effectiveness_data = []
        for row in rows:
            effectiveness_data.append({
                "rule_id": row[0],
                "times_triggered": row[1],
                "successful_blocks": row[2],
                "false_blocks": row[3],
                "last_triggered": row[4].isoformat() if row[4] else None,
                "effectiveness_score": row[5],
                "status": row[6],
                "a_b_test_group": row[7],
                "a_b_test_active": row[8]
            })
        
        return effectiveness_data
    except Exception as e:
        print(f"Error fetching rule effectiveness: {e}")
        return []

@app.post("/self-healing/rules/{rule_id}/deprecate")
async def deprecate_rule(rule_id: int, session: AsyncSession = Depends(get_session)):
    """Mark a rule as deprecated due to poor performance"""
    try:
        await session.execute(
            text("""
                UPDATE rule_effectiveness
                SET status = 'deprecated'
                WHERE rule_id = :rule_id
            """),
            {"rule_id": rule_id}
        )
        
        # Also update the rule status in the rules table
        await session.execute(
            text("""
                UPDATE rules
                SET status = 'deprecated'
                WHERE id = :rule_id
            """),
            {"rule_id": rule_id}
        )
        
        await session.commit()
        
        print(f"[FeedbackLoop] Deprecated rule #{rule_id}")
        return {"status": "deprecated", "rule_id": rule_id}
    except Exception as e:
        print(f"Error deprecating rule: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/self-healing/rules/{rule_id}/record-trigger")
async def record_rule_trigger(
    rule_id: int,
    outcome: str,  # 'blocked', 'allowed', 'false_positive', 'rate_limited'
    flow_id: str = None,
    alert_id: int = None,
    ip_affected: str = None,
    session: AsyncSession = Depends(get_session)
):
    """Record a rule trigger event for effectiveness tracking"""
    try:
        # Log the trigger
        await session.execute(
            text("""
                INSERT INTO rule_trigger_log (rule_id, flow_id, alert_id, outcome, ip_affected)
                VALUES (:rule_id, :flow_id, :alert_id, :outcome, :ip_affected)
            """),
            {
                "rule_id": rule_id,
                "flow_id": flow_id,
                "alert_id": alert_id,
                "outcome": outcome,
                "ip_affected": ip_affected
            }
        )
        
        # Update rule effectiveness
        # Check if record exists
        result = await session.execute(
            text("SELECT rule_id FROM rule_effectiveness WHERE rule_id = :rule_id"),
            {"rule_id": rule_id}
        )
        exists = result.fetchone() is not None
        
        if not exists:
            # Create new record
            await session.execute(
                text("""
                    INSERT INTO rule_effectiveness (rule_id, times_triggered, successful_blocks, false_blocks, last_triggered)
                    VALUES (:rule_id, 1, :successful, :false_pos, NOW())
                """),
                {
                    "rule_id": rule_id,
                    "successful": 1 if outcome == 'blocked' else 0,
                    "false_pos": 1 if outcome == 'false_positive' else 0
                }
            )
        else:
            # Update existing record
            if outcome == 'blocked':
                await session.execute(
                    text("""
                        UPDATE rule_effectiveness
                        SET times_triggered = times_triggered + 1,
                            successful_blocks = successful_blocks + 1,
                            last_triggered = NOW()
                        WHERE rule_id = :rule_id
                    """),
                    {"rule_id": rule_id}
                )
            elif outcome == 'false_positive':
                await session.execute(
                    text("""
                        UPDATE rule_effectiveness
                        SET times_triggered = times_triggered + 1,
                            false_blocks = false_blocks + 1,
                            last_triggered = NOW()
                        WHERE rule_id = :rule_id
                    """),
                    {"rule_id": rule_id}
                )
            else:
                await session.execute(
                    text("""
                        UPDATE rule_effectiveness
                        SET times_triggered = times_triggered + 1,
                            last_triggered = NOW()
                        WHERE rule_id = :rule_id
                    """),
                    {"rule_id": rule_id}
                )
            
            # Recalculate effectiveness score
            await session.execute(
                text("""
                    UPDATE rule_effectiveness
                    SET effectiveness_score = CASE
                        WHEN times_triggered = 0 THEN 0.5
                        ELSE GREATEST(0.0, LEAST(1.0, (successful_blocks - false_blocks)::float / times_triggered::float))
                    END
                    WHERE rule_id = :rule_id
                """),
                {"rule_id": rule_id}
            )
        
        await session.commit()
        
        return {"status": "recorded", "rule_id": rule_id, "outcome": outcome}
    except Exception as e:
        print(f"Error recording rule trigger: {e}")
        import traceback
        traceback.print_exc()
        return {"status": "error", "message": str(e)}

class FeatureFeedbackUpdate(BaseModel):
    feature_name: str
    false_positive_count: int = 0
    true_positive_count: int = 0
    false_negative_count: int = 0

@app.post("/self-healing/feature-feedback/update")
async def update_feature_feedback(update: FeatureFeedbackUpdate, session: AsyncSession = Depends(get_session)):
    """Update feature feedback statistics"""
    try:
        # Check if feature exists
        result = await session.execute(
            text("SELECT feature_name FROM feature_feedback WHERE feature_name = :name"),
            {"name": update.feature_name}
        )
        exists = result.fetchone() is not None
        
        if not exists:
            # Create new record
            await session.execute(
                text("""
                    INSERT INTO feature_feedback (feature_name, false_positive_count, true_positive_count, false_negative_count)
                    VALUES (:name, :fp, :tp, :fn)
                """),
                {
                    "name": update.feature_name,
                    "fp": update.false_positive_count,
                    "tp": update.true_positive_count,
                    "fn": update.false_negative_count
                }
            )
        else:
            # Update existing record
            await session.execute(
                text("""
                    UPDATE feature_feedback
                    SET false_positive_count = false_positive_count + :fp,
                        true_positive_count = true_positive_count + :tp,
                        false_negative_count = false_negative_count + :fn,
                        last_updated = NOW()
                    WHERE feature_name = :name
                """),
                {
                    "name": update.feature_name,
                    "fp": update.false_positive_count,
                    "tp": update.true_positive_count,
                    "fn": update.false_negative_count
                }
            )
            
            # Recalculate importance score
            await session.execute(
                text("""
                    UPDATE feature_feedback
                    SET importance_score = CASE
                        WHEN (true_positive_count + false_positive_count) = 0 THEN 1.0
                        ELSE true_positive_count::float / (true_positive_count + false_positive_count)::float
                    END
                    WHERE feature_name = :name
                """),
                {"name": update.feature_name}
            )
        
        await session.commit()
        return {"status": "updated", "feature_name": update.feature_name}
    except Exception as e:
        print(f"Error updating feature feedback: {e}")
        return {"status": "error", "message": str(e)}

# ============================================================================
# WEEK 2: ONLINE LEARNING & DRIFT DETECTION ENDPOINTS
# Phase 1 Week 2: Advanced ML & Intelligent Rules
# ============================================================================

class ModelVersionRegister(BaseModel):
    version_id: str
    model_type: str
    hyperparameters: dict
    training_samples: int
    file_path: str
    file_size_bytes: int = 0
    validation_accuracy: float | None = None
    false_positive_rate: float | None = None
    false_negative_rate: float | None = None
    f1_score: float | None = None

@app.post("/self-healing/model-versions/register")
async def register_model_version(version: ModelVersionRegister, session: AsyncSession = Depends(get_session)):
    """Register a new model version"""
    try:
        await session.execute(
            text("""
                INSERT INTO model_versions (
                    version_id, model_type, hyperparameters, training_samples,
                    file_path, file_size_bytes, validation_accuracy,
                    false_positive_rate, false_negative_rate, f1_score,
                    online_learning_enabled
                )
                VALUES (
                    :version_id, :model_type, :hyperparameters::jsonb, :training_samples,
                    :file_path, :file_size_bytes, :validation_accuracy,
                    :false_positive_rate, :false_negative_rate, :f1_score, TRUE
                )
                ON CONFLICT (version_id) DO UPDATE SET
                    validation_accuracy = EXCLUDED.validation_accuracy,
                    false_positive_rate = EXCLUDED.false_positive_rate,
                    false_negative_rate = EXCLUDED.false_negative_rate,
                    f1_score = EXCLUDED.f1_score
            """),
            {
                "version_id": version.version_id,
                "model_type": version.model_type,
                "hyperparameters": version.hyperparameters,
                "training_samples": version.training_samples,
                "file_path": version.file_path,
                "file_size_bytes": version.file_size_bytes,
                "validation_accuracy": version.validation_accuracy,
                "false_positive_rate": version.false_positive_rate,
                "false_negative_rate": version.false_negative_rate,
                "f1_score": version.f1_score
            }
        )
        await session.commit()
        print(f"[ModelVersioner] Registered version: {version.version_id}")
        return {"status": "registered", "version_id": version.version_id}
    except Exception as e:
        print(f"Error registering model version: {e}")
        import traceback
        traceback.print_exc()
        return {"status": "error", "message": str(e)}

@app.get("/self-healing/model-versions")
async def get_model_versions(model_type: str | None = None, session: AsyncSession = Depends(get_session)):
    """Get all model versions"""
    try:
        if model_type:
            result = await session.execute(
                text("""
                    SELECT version_id, model_type, created_at, validation_accuracy,
                           false_positive_rate, f1_score, is_active, online_updates_count
                    FROM model_versions
                    WHERE model_type = :model_type
                    ORDER BY created_at DESC
                """),
                {"model_type": model_type}
            )
        else:
            result = await session.execute(
                text("""
                    SELECT version_id, model_type, created_at, validation_accuracy,
                           false_positive_rate, f1_score, is_active, online_updates_count
                    FROM model_versions
                    ORDER BY created_at DESC
                """)
            )
        
        rows = result.fetchall()
        versions = []
        for row in rows:
            versions.append({
                "version_id": row[0],
                "model_type": row[1],
                "created_at": row[2].isoformat() if row[2] else None,
                "validation_accuracy": row[3],
                "false_positive_rate": row[4],
                "f1_score": row[5],
                "is_active": row[6],
                "online_updates_count": row[7]
            })
        
        return versions
    except Exception as e:
        print(f"Error fetching model versions: {e}")
        return []

class ModelPredictionLog(BaseModel):
    version_id: str
    prediction: int
    confidence: float
    actual_label: int | None = None
    flow_id: str | None = None
    flow_info: dict = {}

@app.post("/self-healing/model-predictions/log")
async def log_model_prediction(pred: ModelPredictionLog, session: AsyncSession = Depends(get_session)):
    """Log a model prediction"""
    try:
        await session.execute(
            text("""
                INSERT INTO model_predictions (
                    version_id, prediction, confidence, actual_label, flow_id, flow_info
                )
                VALUES (:version_id, :prediction, :confidence, :actual_label, :flow_id, :flow_info::jsonb)
            """),
            {
                "version_id": pred.version_id,
                "prediction": pred.prediction,
                "confidence": pred.confidence,
                "actual_label": pred.actual_label,
                "flow_id": pred.flow_id,
                "flow_info": pred.flow_info
            }
        )
        await session.commit()
        return {"status": "logged"}
    except Exception as e:
        print(f"Error logging prediction: {e}")
        return {"status": "error", "message": str(e)}

class DriftEventLog(BaseModel):
    detector_type: str
    drift_reasons: list = []
    error_rate_before: float | None = None
    error_rate_after: float | None = None
    samples_since_last_drift: int = 0
    model_version_affected: str | None = None
    action_taken: str = "pending"
    metadata: dict = {}

@app.post("/self-healing/drift-events/log")
async def log_drift_event(drift: DriftEventLog, session: AsyncSession = Depends(get_session)):
    """Log a concept drift detection event"""
    try:
        await session.execute(
            text("""
                INSERT INTO drift_events (
                    detector_type, drift_reasons, error_rate_before, error_rate_after,
                    samples_since_last_drift, model_version_affected, action_taken, metadata
                )
                VALUES (
                    :detector_type, :drift_reasons::jsonb, :error_rate_before, :error_rate_after,
                    :samples_since_last_drift, :model_version_affected, :action_taken, :metadata::jsonb
                )
            """),
            {
                "detector_type": drift.detector_type,
                "drift_reasons": drift.drift_reasons,
                "error_rate_before": drift.error_rate_before,
                "error_rate_after": drift.error_rate_after,
                "samples_since_last_drift": drift.samples_since_last_drift,
                "model_version_affected": drift.model_version_affected,
                "action_taken": drift.action_taken,
                "metadata": drift.metadata
            }
        )
        await session.commit()
        print(f"[DriftDetector] Logged drift event: {drift.detector_type}")
        return {"status": "logged"}
    except Exception as e:
        print(f"Error logging drift event: {e}")
        return {"status": "error", "message": str(e)}

@app.get("/self-healing/drift-events")
async def get_drift_events(limit: int = 100, session: AsyncSession = Depends(get_session)):
    """Get recent drift events"""
    try:
        result = await session.execute(
            text("""
                SELECT id, detected_at, detector_type, drift_reasons, error_rate_before,
                       error_rate_after, model_version_affected, action_taken
                FROM drift_events
                ORDER BY detected_at DESC
                LIMIT :limit
            """),
            {"limit": limit}
        )
        rows = result.fetchall()
        
        events = []
        for row in rows:
            events.append({
                "id": row[0],
                "detected_at": row[1].isoformat() if row[1] else None,
                "detector_type": row[2],
                "drift_reasons": row[3],
                "error_rate_before": row[4],
                "error_rate_after": row[5],
                "model_version_affected": row[6],
                "action_taken": row[7]
            })
        
        return events
    except Exception as e:
        print(f"Error fetching drift events: {e}")
        return []

@app.post("/self-healing/model-versions/{version_id}/update-metrics")
async def update_model_metrics(version_id: str, metrics: dict, session: AsyncSession = Depends(get_session)):
    """Update metrics for a model version"""
    try:
        await session.execute(
            text("""
                UPDATE model_versions
                SET validation_accuracy = :accuracy,
                    false_positive_rate = :fpr,
                    false_negative_rate = :fnr,
                    f1_score = :f1
                WHERE version_id = :version_id
            """),
            {
                "version_id": version_id,
                "accuracy": metrics.get("validation_accuracy", 0.0),
                "fpr": metrics.get("false_positive_rate", 0.0),
                "fnr": metrics.get("false_negative_rate", 0.0),
                "f1": metrics.get("f1_score", 0.0)
            }
        )
        await session.commit()
        return {"status": "updated"}
    except Exception as e:
        print(f"Error updating metrics: {e}")
        return {"status": "error", "message": str(e)}

@app.post("/self-healing/model-versions/{version_id}/set-active")
async def set_model_active(version_id: str, session: AsyncSession = Depends(get_session)):
    """Mark a model version as active"""
    try:
        # Deactivate all versions of same type
        result = await session.execute(
            text("SELECT model_type FROM model_versions WHERE version_id = :version_id"),
            {"version_id": version_id}
        )
        row = result.fetchone()
        if not row:
            return {"status": "error", "message": "Version not found"}
        
        model_type = row[0]
        
        # Deactivate all versions of this type
        await session.execute(
            text("UPDATE model_versions SET is_active = FALSE WHERE model_type = :model_type"),
            {"model_type": model_type}
        )
        
        # Activate the specified version
        await session.execute(
            text("UPDATE model_versions SET is_active = TRUE WHERE version_id = :version_id"),
            {"version_id": version_id}
        )
        
        await session.commit()
        print(f"[ModelVersioner] Set active: {version_id}")
        return {"status": "activated", "version_id": version_id}
    except Exception as e:
        print(f"Error setting active version: {e}")
        return {"status": "error", "message": str(e)}

@app.get("/self-healing/model-performance/{version_id}")
async def get_model_performance(version_id: str, hours: int = 24, session: AsyncSession = Depends(get_session)):
    """Get performance history for a model version"""
    try:
        result = await session.execute(
            text("""
                SELECT logged_at, accuracy, f1_score, false_positive_rate,
                       false_negative_rate, predictions_count
                FROM model_performance_log
                WHERE version_id = :version_id
                AND logged_at > NOW() - INTERVAL '1 hour' * :hours
                ORDER BY logged_at DESC
            """),
            {"version_id": version_id, "hours": hours}
        )
        rows = result.fetchall()
        
        history = []
        for row in rows:
            history.append({
                "logged_at": row[0].isoformat() if row[0] else None,
                "accuracy": row[1],
                "f1_score": row[2],
                "false_positive_rate": row[3],
                "false_negative_rate": row[4],
                "predictions_count": row[5]
            })
        
        return history
    except Exception as e:
        print(f"Error fetching performance history: {e}")
        return []

# ============================================================================
# ============================================================================

@app.get("/system/learning-status")
async def get_learning_status(session: AsyncSession = Depends(get_session)):
    """Get current learning phase status"""
    # Initialize from DB if not already done
    await learning_state.init_from_db(session)
    
    try:
        # Prefer Brain-provided ML flow count for accurate training progress.
        flows_collected = None
        try:
            async with aiohttp.ClientSession() as client:
                async with client.get(
                    "http://brain:8001/devices/profiles",
                    headers=_internal_service_headers(),
                    timeout=aiohttp.ClientTimeout(total=2),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        total_flows = data.get("totalFlows", 0) if isinstance(data, dict) else 0
                        flows_collected = int(total_flows) if total_flows is not None else 0
        except Exception:
            flows_collected = None

        # Fallback to DB count if Brain is unavailable.
        if flows_collected is None:
            result = await session.execute(text("SELECT COUNT(*) FROM flows"))
            flows_collected = result.scalar() or 0
        
        # Get training threshold from config
        config_result = await session.execute(
            text("SELECT config_value FROM model_config WHERE config_key = 'training_threshold'")
        )
        row = config_result.fetchone()
        training_threshold = int(row[0]) if row else 200
        
        # Check if models are trained
        is_trained = flows_collected >= training_threshold and learning_state.phase != "idle"
        
        # Auto-transition to active if trained
        if learning_state.phase == "learning" and flows_collected >= training_threshold:
            learning_state.phase = "active"
            await learning_state.save_to_db(session)
        
        return {
            "learning_phase": learning_state.phase,
            "flows_collected": flows_collected,
            "training_threshold": training_threshold,
            "is_trained": is_trained or learning_state.phase == "active",
            "started_at": learning_state.started_at
        }
    except Exception as e:
        print(f"Error getting learning status: {e}")
        return {
            "learning_phase": learning_state.phase,
            "flows_collected": 0,
            "training_threshold": 200,
            "is_trained": False
        }

# Add new endpoints for controlling learning phase
@app.post("/system/start-learning")
async def start_learning(session: AsyncSession = Depends(get_session)):
    """Start the learning phase"""
    await learning_state.init_from_db(session)
    
    if learning_state.phase == "learning":
        return {"status": "already_learning", "message": "Learning phase already active"}
    
    learning_state.phase = "learning"
    learning_state.started_at = datetime.utcnow().isoformat()
    
    await learning_state.save_to_db(session)
    
    return {
        "status": "started",
        "message": "Learning phase started",
        "started_at": learning_state.started_at
    }

@app.post("/system/stop-learning")
async def stop_learning(session: AsyncSession = Depends(get_session)):
    """Stop learning and transition to active mode"""
    await learning_state.init_from_db(session)
    
    learning_state.phase = "active"
    
    await learning_state.save_to_db(session)
    
    return {"status": "stopped", "message": "Transitioned to active monitoring mode"}

# </CHANGE> Add learning_phase field to /system/state response for Core compatibility
@app.get("/system/state")
async def get_system_state(session: AsyncSession = Depends(get_session)):
    """Get current system state including learning phase - used by Core agent"""
    # Initialize from DB if not already done
    await learning_state.init_from_db(session)
    
    try:
        # Refresh from database
        result = await session.execute(
            text("SELECT config_value FROM model_config WHERE config_key = 'learning_phase'")
        )
        row = result.fetchone()
        if row:
            learning_state.phase = row[0]
        
        return {
            "learning_phase": learning_state.phase,
            "phase": learning_state.phase,
            "started_at": learning_state.started_at
        }
    except Exception as e:
        print(f"Error getting system state: {e}")
        return {
            "learning_phase": learning_state.phase,
            "phase": learning_state.phase,
            "started_at": None
        }

@app.get("/system/health")
async def get_system_health_proxy():
    """Provide lightweight system-health data for dashboard widgets."""
    try:
        async with aiohttp.ClientSession() as client:
            async with client.get(
                "http://brain:8001/health",
                headers=_internal_service_headers(),
                timeout=aiohttp.ClientTimeout(total=2),
            ) as resp:
                if resp.status == 200:
                    brain = await resp.json()
                    model_trained = bool(brain.get("model_trained", False))
                    return {
                        "status": "ok",
                        "statistics": {
                            "health_score": {
                                "overall_score": 100 if model_trained else 92,
                                "model_trained": model_trained
                            }
                        }
                    }
    except Exception:
        pass

    return {
        "status": "degraded",
        "statistics": {
            "health_score": {
                "overall_score": 80,
                "model_trained": False
            }
        }
    }

# ============================================================================
# ============================================================================

class AlertingWebhook(BaseModel):
    name: str
    url: str
    type: str  # slack, discord, email, webhook, pagerduty
    enabled: bool = True
    events: list[str] = ["critical", "high"]  # severity levels to trigger
    headers: dict = {}


def _parse_json_array(value: Any, default: list[str]) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, list):
                return [str(item) for item in parsed]
        except Exception:
            pass
    return default


def _parse_json_object(value: Any) -> dict:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            pass
    return {}


@app.get("/alerting/webhooks")
async def get_alerting_webhooks(session: AsyncSession = Depends(get_session)):
    """Get all configured alerting webhooks"""
    try:
        result = await session.execute(
            text("SELECT id, name, url, type, enabled, events, headers, created_at FROM alerting_webhooks ORDER BY created_at DESC")
        )
        rows = result.fetchall()
        return [
            {
                "id": row[0],
                "name": row[1],
                "url": row[2],
                "type": row[3],
                "enabled": row[4],
                "events": _parse_json_array(row[5], ["critical", "high"]),
                "headers": _parse_json_object(row[6]),
                "created_at": row[7].isoformat() if row[7] else None
            }
            for row in rows
        ]
    except Exception as e:
        print(f"Error fetching webhooks: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to fetch alerting webhooks: {e}")

@app.post("/alerting/webhooks")
async def create_alerting_webhook(webhook: AlertingWebhook, session: AsyncSession = Depends(get_session)):
    """Create a new alerting webhook"""
    try:
        events = webhook.events or ["critical", "high"]
        headers = webhook.headers or {}

        await session.execute(
            text("""
                INSERT INTO alerting_webhooks (name, url, type, enabled, events, headers)
                VALUES (:name, :url, :type, :enabled, :events::jsonb, :headers::jsonb)
            """),
            {
                "name": webhook.name,
                "url": webhook.url,
                "type": webhook.type,
                "enabled": webhook.enabled,
                "events": json.dumps(events),
                "headers": json.dumps(headers)
            }
        )
        await session.commit()
        return {"status": "created", "name": webhook.name}
    except Exception as e:
        print(f"Error creating webhook: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to create alerting webhook: {e}")

@app.delete("/alerting/webhooks/{webhook_id}")
async def delete_alerting_webhook(webhook_id: int, session: AsyncSession = Depends(get_session)):
    """Delete an alerting webhook"""
    try:
        await session.execute(
            text("DELETE FROM alerting_webhooks WHERE id = :id"),
            {"id": webhook_id}
        )
        await session.commit()
        return {"status": "deleted"}
    except Exception as e:
        return {"status": "error", "message": str(e)}

@app.post("/alerting/webhooks/{webhook_id}/test")
async def test_alerting_webhook(webhook_id: int, session: AsyncSession = Depends(get_session)):
    """Test an alerting webhook"""
    try:
        result = await session.execute(
            text("SELECT url, type, headers FROM alerting_webhooks WHERE id = :id"),
            {"id": webhook_id}
        )
        row = result.fetchone()
        if not row:
            return {"status": "error", "message": "Webhook not found"}
        
        url, webhook_type, headers = row
        success, response_code, error_message = await send_alert_to_webhook(
            str(url),
            str(webhook_type),
            headers or {},
            create_test_alert_payload(),
        )

        return {
            "status": "sent" if success else "error",
            "response_code": response_code,
            "success": success,
            "message": error_message
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ============================================================================
# ============================================================================

_geo_cache: dict[str, tuple[float, dict]] = {}
_GEO_CACHE_TTL_SECONDS = 1800
_MAX_GEO_CACHE_SIZE = 4000


def _trim_geo_cache(now: float) -> None:
    if len(_geo_cache) <= _MAX_GEO_CACHE_SIZE:
        return
    stale_keys = [
        ip for ip, (cached_at, _) in _geo_cache.items()
        if now - cached_at > _GEO_CACHE_TTL_SECONDS
    ]
    for key in stale_keys:
        _geo_cache.pop(key, None)

    if len(_geo_cache) <= _MAX_GEO_CACHE_SIZE:
        return

    # Drop oldest entries if still over cap.
    oldest = sorted(_geo_cache.items(), key=lambda item: item[1][0])[:len(_geo_cache) - _MAX_GEO_CACHE_SIZE]
    for key, _ in oldest:
        _geo_cache.pop(key, None)


async def _lookup_ip_geolocation(ip_address: str) -> dict:
    """Lookup IP geolocation and ASN information (cached)."""
    now = time.time()
    cached = _geo_cache.get(ip_address)
    if cached and now - cached[0] <= _GEO_CACHE_TTL_SECONDS:
        return cached[1]

    private_prefixes = (
        "10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
        "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
        "127.", "169.254."
    )
    if ip_address.startswith(private_prefixes):
        result = {"ip": ip_address, "is_private": True, "country": "Private/Local", "country_code": "PRV"}
        _geo_cache[ip_address] = (now, result)
        return result

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"http://ip-api.com/json/{ip_address}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query",
                timeout=5.0
            )

        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success":
                result = {
                    "ip": data.get("query"),
                    "country": data.get("country"),
                    "country_code": data.get("countryCode"),
                    "region": data.get("regionName"),
                    "city": data.get("city"),
                    "zip": data.get("zip"),
                    "lat": data.get("lat"),
                    "lon": data.get("lon"),
                    "timezone": data.get("timezone"),
                    "isp": data.get("isp"),
                    "org": data.get("org"),
                    "asn": data.get("as"),
                    "asn_name": data.get("asname"),
                    "is_private": False,
                }
                _geo_cache[ip_address] = (now, result)
                _trim_geo_cache(now)
                return result

            result = {
                "ip": ip_address,
                "error": data.get("message", "Unknown error"),
                "is_private": True,
                "country": "Unknown",
                "country_code": "UNK",
            }
            _geo_cache[ip_address] = (now, result)
            return result

        result = {"ip": ip_address, "error": "Lookup failed", "country": "Unknown", "country_code": "UNK"}
        _geo_cache[ip_address] = (now, result)
        return result
    except Exception as e:
        result = {"ip": ip_address, "error": str(e), "country": "Unknown", "country_code": "UNK"}
        _geo_cache[ip_address] = (now, result)
        return result


@app.get("/ip/lookup/{ip_address}")
async def lookup_ip_geolocation(ip_address: str):
    """Lookup IP geolocation and ASN information."""
    return await _lookup_ip_geolocation(ip_address)


@app.get("/threats/top-countries")
async def get_top_threat_countries(
    limit: int = Query(default=10, ge=1, le=50),
    lookback_hours: int = Query(default=24, ge=1, le=168),
    sample_size: int = Query(default=300, ge=10, le=2000),
    session: AsyncSession = Depends(get_session),
):
    """Aggregate top source countries for recent threat alerts."""
    try:
        result = await session.execute(
            text("""
                SELECT src_ip, severity, threat_category
                FROM alerts
                WHERE timestamp > NOW() - INTERVAL '1 hour' * :lookback_hours
                ORDER BY timestamp DESC
                LIMIT :sample_size
            """),
            {
                "lookback_hours": lookback_hours,
                "sample_size": sample_size,
            }
        )
        rows = result.fetchall()

        unique_ips = {row[0] for row in rows if row[0]}
        ip_geo: dict[str, dict] = {}

        semaphore = asyncio.Semaphore(20)

        async def _resolve_geo(ip: str):
            async with semaphore:
                ip_geo[ip] = await _lookup_ip_geolocation(ip)

        if unique_ips:
            await asyncio.gather(*[_resolve_geo(ip) for ip in unique_ips])

        aggregated: dict[str, dict] = {}
        for row in rows:
            src_ip = row[0]
            severity = (row[1] or "").lower()
            category = row[2] or "uncategorized"

            geo = ip_geo.get(src_ip) or {"country": "Unknown", "country_code": "UNK"}
            country = geo.get("country") or ("Private/Local" if geo.get("is_private") else "Unknown")
            country_code = geo.get("country_code") or ("PRV" if geo.get("is_private") else "UNK")

            if country not in aggregated:
                aggregated[country] = {
                    "country": country,
                    "country_code": country_code,
                    "count": 0,
                    "critical": 0,
                    "high": 0,
                    "medium": 0,
                    "low": 0,
                    "top_categories": {},
                    "example_ips": [],
                }

            entry = aggregated[country]
            entry["count"] += 1
            if severity in {"critical", "high", "medium", "low"}:
                entry[severity] += 1

            entry["top_categories"][category] = entry["top_categories"].get(category, 0) + 1
            if len(entry["example_ips"]) < 3 and src_ip not in entry["example_ips"]:
                entry["example_ips"].append(src_ip)

        countries = sorted(aggregated.values(), key=lambda item: item["count"], reverse=True)
        for item in countries:
            item["top_categories"] = sorted(
                item["top_categories"].items(),
                key=lambda pair: pair[1],
                reverse=True
            )[:3]

        return {
            "generated_at": datetime.utcnow().isoformat(),
            "lookback_hours": lookback_hours,
            "sampled_alerts": len(rows),
            "countries": countries[:limit],
        }
    except Exception as e:
        print(f"Error aggregating top threat countries: {e}")
        return {
            "generated_at": datetime.utcnow().isoformat(),
            "lookback_hours": lookback_hours,
            "sampled_alerts": 0,
            "countries": [],
            "error": str(e),
        }

# ============================================================================
# ============================================================================

@app.post("/firewall/verify")
async def verify_firewall_rules(session: AsyncSession = Depends(get_session)):
    """
    Verify firewall enforcement using sync logs from agents/brain.
    Note: platform refers to API host container OS, not endpoint OS.
    """

    results = {
        "platform": platform.system(),
        "verification_mode": "sync_log",
        "platform_note": "Platform is API host OS; enforcement may run on remote agents.",
        "verified_blocks": [],
        "missing_blocks": [],
        "errors": [],
    }

    try:
        # Get currently blocked IPs expected to be enforced.
        result = await session.execute(
            text("""
                SELECT ip FROM blocked_ips 
                WHERE (expires_at > NOW() OR permanent = TRUE)
                AND (manual_override = TRUE OR confidence >= 0.9)
            """)
        )
        blocked_ips = [row[0] for row in result.fetchall()]
        blocked_ips_set = set(blocked_ips)

        if not blocked_ips:
            results["missing_blocks"] = []
            results["total_blocked"] = 0
            results["verification_rate"] = 100
            results["recent_sync_failures"] = []
            return results

        ip_activity_result = await session.execute(
            text("""
                SELECT
                    ip,
                    MAX(CASE WHEN action = 'block' AND success = TRUE THEN created_at END) AS last_block_at,
                    MAX(CASE WHEN action = 'unblock' AND success = TRUE THEN created_at END) AS last_unblock_at
                FROM firewall_sync_log
                WHERE ip IN :ips
                GROUP BY ip
            """).bindparams(bindparam("ips", expanding=True)),
            {"ips": blocked_ips},
        )
        ip_activity_rows = ip_activity_result.fetchall()
        ip_activity_map = {row[0]: {"last_block_at": row[1], "last_unblock_at": row[2]} for row in ip_activity_rows}

        for ip in blocked_ips:
            activity = ip_activity_map.get(ip)
            if not activity:
                continue
            last_block_at = activity["last_block_at"]
            last_unblock_at = activity["last_unblock_at"]
            if last_block_at and (not last_unblock_at or last_block_at > last_unblock_at):
                results["verified_blocks"].append(ip)

        verified_set = set(results["verified_blocks"])
        missing_ips = blocked_ips_set - verified_set
        results["missing_blocks"] = sorted(list(missing_ips))

        failures_result = await session.execute(
            text("""
                SELECT ip, error_message, created_at
                FROM firewall_sync_log
                WHERE success = FALSE
                AND ip IN :ips
                ORDER BY created_at DESC
                LIMIT 20
            """).bindparams(bindparam("ips", expanding=True)),
            {"ips": blocked_ips},
        )
        failure_rows = failures_result.fetchall()
        results["recent_sync_failures"] = [
            {
                "ip": row[0],
                "error": row[1] or "unknown error",
                "created_at": row[2].isoformat() if row[2] else None,
            }
            for row in failure_rows
        ]
        results["errors"] = [f"{entry['ip']}: {entry['error']}" for entry in results["recent_sync_failures"][:5]]

        results["verified_blocks"] = sorted(list(set(results["verified_blocks"])))
        results["total_blocked"] = len(blocked_ips)
        results["verification_rate"] = len(results["verified_blocks"]) / len(blocked_ips) * 100 if blocked_ips else 100

        return results
    except Exception as e:
        return {"error": str(e), "verified_blocks": [], "missing_blocks": []}

# ============================================================================
# ============================================================================

class BulkIPOperation(BaseModel):
    ips: list[str]
    action: str  # whitelist, block, unblock
    permanent: bool = False
    notes: str = ""
    added_by: str = "admin"
    expires_hours: int = 24

@app.post("/self-healing/bulk-operation")
async def bulk_ip_operation(operation: BulkIPOperation, session: AsyncSession = Depends(get_session)):
    """Perform bulk operations on multiple IPs"""
    results = {"success": [], "failed": []}
    
    for ip in operation.ips:
        try:
            if operation.action == "whitelist":
                await session.execute(
                    text("""
                        INSERT INTO trusted_ips (ip, confidence, permanent, auto_added, notes, added_by, good_flows)
                        VALUES (:ip, 1.0, :permanent, FALSE, :notes, :added_by, 0)
                        ON CONFLICT (ip) DO UPDATE SET
                            permanent = EXCLUDED.permanent,
                            notes = EXCLUDED.notes,
                            updated_at = NOW()
                    """),
                    {"ip": ip, "permanent": operation.permanent, "notes": operation.notes, "added_by": operation.added_by}
                )
                results["success"].append(ip)
                
            elif operation.action == "block":
                if operation.permanent:
                    await session.execute(
                        text("""
                            INSERT INTO blocked_ips (ip, block_reason, confidence, permanent, manual_override, expires_at, added_by, notes)
                            VALUES (:ip, :notes, 1.0, TRUE, TRUE, NULL, :added_by, :notes)
                            ON CONFLICT (ip)
                            DO UPDATE SET
                                permanent = TRUE,
                                notes = EXCLUDED.notes,
                                expires_at = NULL,
                                blocked_at = NOW()
                        """),
                        {"ip": ip, "notes": operation.notes or "Bulk blocked", "added_by": operation.added_by}
                    )
                else:
                    await session.execute(
                        text("""
                            INSERT INTO blocked_ips (ip, block_reason, confidence, permanent, manual_override, expires_at, added_by, notes)
                            VALUES (:ip, :notes, 1.0, FALSE, TRUE, NOW() + INTERVAL '1 hour' * :hours, :added_by, :notes)
                            ON CONFLICT (ip)
                            DO UPDATE SET
                                permanent = FALSE,
                                notes = EXCLUDED.notes,
                                expires_at = NOW() + INTERVAL '1 hour' * :hours,
                                blocked_at = NOW()
                        """),
                        {"ip": ip, "notes": operation.notes or "Bulk blocked", "added_by": operation.added_by, "hours": operation.expires_hours}
                    )
                results["success"].append(ip)
                
            elif operation.action == "unblock":
                await session.execute(
                    text("DELETE FROM blocked_ips WHERE ip = :ip"),
                    {"ip": ip}
                )
                results["success"].append(ip)
                
        except Exception as e:
            results["failed"].append({"ip": ip, "error": str(e)})
    
    await session.commit()
    return {
        "status": "completed",
        "action": operation.action,
        "total": len(operation.ips),
        "success_count": len(results["success"]),
        "failed_count": len(results["failed"]),
        "results": results
    }
