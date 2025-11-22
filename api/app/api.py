from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from db import get_session
from pydantic import BaseModel
from datetime import datetime
from contextlib import asynccontextmanager
import asyncio

consumer_task = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    global consumer_task
    print("[API] ========================================")
    print("[API] Starting Redis consumer...")
    print("[API] ========================================")
    from redis_consumer import start_redis_consumer
    consumer_task = asyncio.create_task(start_redis_consumer())
    yield
    print("[API] Shutting down consumer...")
    if consumer_task:
        consumer_task.cancel()

app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class DeviceRegistration(BaseModel):
    agent_id: str
    hostname: str
    ip: str | None = None

class AlertCreate(BaseModel):
    flow_id: str
    hostname: str
    src_ip: str
    dst_ip: str
    src_port: int | None = None
    dst_port: int | None = None
    protocol: str | None = None
    risk_score: float
    severity: str | None = None  # Auto-calculated if not provided
    reason: str

class RuleCreate(BaseModel):
    alert_id: int
    rule_type: str
    action: str
    target: str
    reason: str
    confidence: float

@app.get("/healthz")
def healthz():
    return {"status": "Revenix API OK"}

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
async def get_recent_flows(session: AsyncSession = Depends(get_session)):
    """Get the most recent flows"""
    try:
        result = await session.execute(
            text("SELECT id, flow_id, hostname, src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets, start_ts, end_ts FROM flows ORDER BY end_ts DESC LIMIT 50")
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
            })

        return flows
    except Exception as e:
        print(f"Error fetching flows: {e}")
        return []

@app.get("/alerts/recent")
async def get_recent_alerts(session: AsyncSession = Depends(get_session)):
    """Get the most recent alerts"""
    try:
        print("[v0] Fetching alerts from database...")
        result = await session.execute(
            text("""
                SELECT id, flow_id, hostname, src_ip, dst_ip, src_port, dst_port,
                       protocol, risk_score, severity, reason, timestamp
                FROM alerts
                ORDER BY timestamp DESC
                LIMIT 100
            """)
        )
        rows = result.fetchall()
        print(f"[v0] Found {len(rows)} alerts")

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
                "created_at": row[11].isoformat() if row[11] else None,
            })

        print(f"[v0] Returning {len(alerts)} alerts")
        return alerts
    except Exception as e:
        print(f"[v0] Error fetching alerts: {e}")
        import traceback
        traceback.print_exc()
        return []

@app.post("/alerts/create")
async def create_alert(alert: AlertCreate, session: AsyncSession = Depends(get_session)):
    """Create a new alert if risk_score exceeds threshold"""
    RISK_THRESHOLD = 0.75  # Raised from 0.6 to 0.75 to match Brain threshold and reduce false positives

    if alert.risk_score <= RISK_THRESHOLD:
        return {"status": "skipped", "reason": "risk_score below threshold", "threshold": RISK_THRESHOLD}

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

    print(f"[API] Creating alert: {alert.hostname} - {alert.reason} (risk: {alert.risk_score:.2f})")

    result = await session.execute(
        text("""
            INSERT INTO alerts (flow_id, hostname, src_ip, dst_ip, src_port, dst_port, protocol, risk_score, severity, reason)
            VALUES (:flow_id, :hostname, :src_ip, :dst_ip, :src_port, :dst_port, :protocol, :risk_score, :severity, :reason)
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
        }
    )
    await session.commit()

    alert_id = result.fetchone()[0]
    print(f"[API] Alert created with ID: {alert_id}")

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
    return {"status": "created", "rule_type": rule.rule_type, "action": rule.action}

@app.get("/rules/recent")
async def get_recent_rules(session: AsyncSession = Depends(get_session)):
    """Get the most recent rule recommendations"""
    try:
        result = await session.execute(
            text("""
                SELECT r.id, r.alert_id, r.rule_type, r.action, r.target,
                       r.reason, r.confidence, r.status, r.created_at,
                       a.hostname, a.src_ip, a.severity, a.risk_score
                FROM rules r
                JOIN alerts a ON r.alert_id = a.id
                ORDER BY r.created_at DESC
                LIMIT 100
            """)
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
                "created_at": row[8].isoformat() if row[8] else None,
                "hostname": row[9],
                "src_ip": row[10],
                "severity": row[11],
                "risk_score": row[12],
            })

        return rules
    except Exception as e:
        print(f"Error fetching rules: {e}")
        return []
