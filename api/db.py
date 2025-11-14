from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker

# Create async engine
engine = create_async_engine(
    "postgresql+asyncpg://revenix:revenix@postgres:5432/revenix_db",
    echo=True,
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
