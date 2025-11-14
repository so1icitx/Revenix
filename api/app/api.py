from fastapi import FastAPI, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from db import get_session
from pydantic import BaseModel
from datetime import datetime

app = FastAPI()

class DeviceRegistration(BaseModel):
    agent_id: str
    hostname: str
    ip: str | None = None

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
