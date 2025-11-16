from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from db import get_session
from pydantic import BaseModel
from datetime import datetime

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins for development
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

@app.post("/alerts/create")
async def create_alert(alert: AlertCreate, session: AsyncSession = Depends(get_session)):
    """Create a new alert if risk_score exceeds threshold"""
    RISK_THRESHOLD = 0.6  # Only create alerts for risk_score > 0.6

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

    await session.execute(
        text("""
            INSERT INTO alerts (flow_id, hostname, src_ip, dst_ip, src_port, dst_port, protocol, risk_score, severity, reason)
            VALUES (:flow_id, :hostname, :src_ip, :dst_ip, :src_port, :dst_port, :protocol, :risk_score, :severity, :reason)
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
    return {"status": "created", "severity": severity, "risk_score": alert.risk_score}

@app.get("/alerts/recent")
async def get_recent_alerts(session: AsyncSession = Depends(get_session)):
    """Get the most recent alerts"""
    try:
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
                "timestamp": row[11].isoformat() if row[11] else None,
            })

        return alerts
    except Exception as e:
        print(f"Error fetching alerts: {e}")
        return []
