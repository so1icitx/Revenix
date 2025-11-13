from fastapi import FastAPI, Depends
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from db import get_session

app = FastAPI()

@app.get("/healthz")
def healthz():
    return {"status": "Revenix API OK"}

@app.get("/flows/recent")
async def get_recent_flows(session: AsyncSession = Depends(get_session)):
    result = await session.execute(
        text("SELECT * FROM flows ORDER BY end_ts DESC LIMIT 50")
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
