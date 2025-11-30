import uvicorn
from app.api import app
from app.database import init_database

@app.on_event("startup")
async def startup_event():
    """Initialize database with required columns."""
    init_database()

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=8000)
