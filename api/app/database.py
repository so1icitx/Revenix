from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import Column, Integer, String, Float, DateTime, BigInteger, Text
import os
import logging

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://revenix:revenix123@postgres:5432/revenix_db")

engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def init_database():
    """Initialize database schema with all required columns."""
    from sqlalchemy import text

    try:
        with engine.connect() as conn:
            logger.info("Adding threat_category column to alerts table...")
            result = conn.execute(text("""
                ALTER TABLE alerts
                ADD COLUMN IF NOT EXISTS threat_category TEXT DEFAULT 'ANOMALOUS BEHAVIOR';
            """))
            conn.commit()
            logger.info("threat_category column added successfully")
    except Exception as e:
        logger.error(f"Database init error: {e}")
        raise

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
