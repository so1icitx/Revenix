from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import Column, Integer, String, Float, DateTime, BigInteger, Text
import os

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://revenix:revenix123@postgres:5432/revenix_db")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def init_database():
    """Initialize database schema with all required columns."""
    from sqlalchemy import text

    with engine.connect() as conn:
        # Add threat_category column if it doesn't exist
        conn.execute(text("""
            ALTER TABLE alerts
            ADD COLUMN IF NOT EXISTS threat_category TEXT DEFAULT 'ANOMALOUS BEHAVIOR';
        """))
        conn.commit()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
