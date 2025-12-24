import uvicorn
from app.api import app
from app.database import init_database
import logging
import asyncio
from redis_consumer import start_redis_consumer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.on_event("startup")
async def startup_event():
    """Initialize database only. Redis consumer starts in api.py lifespan."""
    logger.info("Initializing database...")
    try:
        init_database()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization error: {e}")
    
    # NOTE: Redis consumer is started in app/api.py lifespan context
    # Do NOT start it here to avoid duplicate processing

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
