"""
Database transaction utilities for safe operations.
Provides context managers that ensure proper commit/rollback handling.
"""

from contextlib import asynccontextmanager
from sqlalchemy.ext.asyncio import AsyncSession
import logging

logger = logging.getLogger(__name__)


@asynccontextmanager
async def safe_transaction(session: AsyncSession):
    """
    Context manager that ensures database transactions are properly handled.
    
    - Commits on success
    - Rolls back on any exception
    - Re-raises the original exception
    
    Usage:
        async with safe_transaction(session):
            await session.execute(text("INSERT INTO ..."))
            await session.execute(text("UPDATE ..."))
        # Auto-commits if no exception, auto-rollbacks if exception
    """
    try:
        yield session
        await session.commit()
    except Exception as e:
        logger.error(f"[DB] Transaction failed, rolling back: {e}")
        await session.rollback()
        raise


@asynccontextmanager
async def safe_batch_transaction(session: AsyncSession, batch_name: str = "batch"):
    """
    Context manager for batch operations with logging.
    
    Usage:
        async with safe_batch_transaction(session, "block_ips"):
            for ip in ips:
                await session.execute(...)
    """
    try:
        yield session
        await session.commit()
        logger.debug(f"[DB] {batch_name} committed successfully")
    except Exception as e:
        logger.error(f"[DB] {batch_name} failed, rolling back: {e}")
        await session.rollback()
        raise
