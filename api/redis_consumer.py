import asyncio
import json
import redis.asyncio as aioredis
from sqlalchemy import text
from db import SessionLocal

async def start_redis_consumer():
    print("[Production] Redis consumer starting with batch processing...")
    redis = await aioredis.from_url("redis://redis:6379")
    print("[Production] Connected to Redis")

    last_id = "0"
    batch_size = 100  # Process 100 flows per batch
    batch = []

    while True:
        try:
            messages = await redis.xread(
                {"flows": last_id},
                count=100,
                block=5000
            )

            if messages:
                for stream_name, stream_messages in messages:
                    for message_id, data in stream_messages:
                        flow_json = data.get(b"flow", b"{}")
                        flow = json.loads(flow_json.decode("utf-8"))
                        batch.append(flow)
                        last_id = message_id.decode("utf-8")

                        if len(batch) >= batch_size:
                            await process_batch(batch)
                            batch = []

            if batch:
                await process_batch(batch)
                batch = []

        except Exception as e:
            print(f"[Production] Redis consumer error: {e}")
            await asyncio.sleep(5)

async def process_batch(batch):
    """Process multiple flows in a single database transaction"""
    if not batch:
        return

    try:
        async with SessionLocal() as session:
            for flow in batch:
                await session.execute(
                    text("""
                        INSERT INTO flows (flow_id, hostname, src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets, start_ts, end_ts)
                        VALUES (:flow_id, :hostname, :src_ip, :dst_ip, :src_port, :dst_port, :protocol, :bytes, :packets, :start_ts, :end_ts)
                    """),
                    {
                        "flow_id": flow.get("flow_id", ""),
                        "hostname": flow.get("hostname", ""),
                        "src_ip": flow.get("src_ip", ""),
                        "dst_ip": flow.get("dst_ip", ""),
                        "src_port": flow.get("src_port"),
                        "dst_port": flow.get("dst_port"),
                        "protocol": flow.get("protocol", ""),
                        "bytes": flow.get("bytes", 0),
                        "packets": flow.get("packets", 0),
                        "start_ts": flow.get("start_ts", 0),
                        "end_ts": flow.get("end_ts", 0),
                    }
                )
            await session.commit()
            print(f"[Production] Batch inserted {len(batch)} flows into Postgres")
    except Exception as e:
        print(f"[Production] Batch insert error: {e}")
        await asyncio.sleep(1)
