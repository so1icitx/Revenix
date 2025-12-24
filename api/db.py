from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
import os

# Use environment variable for database URL (never hardcode credentials!)
DATABASE_URL = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://revenix:revenix@postgres:5432/revenix_db"
)

# Create async engine (echo=False for production - don't log SQL)
engine = create_async_engine(
    DATABASE_URL,
    echo=False,  # Disable SQL logging in production for security + performance
)

# Create async session factory
SessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)

# Session dependency
async def get_session():
    async with SessionLocal() as session:
        yield session
