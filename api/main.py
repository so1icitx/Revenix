import asyncio
import uvicorn
from app.api import app
from redis_consumer import start_redis_consumer

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app):
    # Startup
    print("[Main] Starting application...")
    task = asyncio.create_task(start_redis_consumer())
    print("[Main] Redis consumer task created")
    yield
    # Shutdown
    task.cancel()

app.router.lifespan_context = lifespan

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
