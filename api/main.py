import asyncio
import uvicorn
from app.api import app
from redis_consumer import start_redis_consumer

@app.on_event("startup")
async def startup_event():
    asyncio.create_task(start_redis_consumer())

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
