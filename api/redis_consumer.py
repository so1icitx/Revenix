import asyncio
import json
import aioredis
from sqlalchemy import text
from db import SessionLocal

async def start_redis_consumer():
    # Connect to Redis
    redis = await aioredis.from_url("redis://redis:6379")

    last_id = "0"

    while True:
        try:
            # Read from stream
            messages = await redis.xread(
                {"revenix:flows": last_id},
                count=10,
                block=1000
            )

            if messages:
                for stream_name, stream_messages in messages:
                    for message_id, data in stream_messages:
                        # Parse the flow JSON
                        flow_json = data.get(b"flow", b"{}")
                        flow = json.loads(flow_json.decode("utf-8"))

                        # Insert into Postgres
                        async with SessionLocal() as session:
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

                        last_id = message_id.decode("utf-8")

        except Exception as e:
            print(f"Redis consumer error: {e}")
            await asyncio.sleep(1)
s
