from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import Column, Integer, String, Float, DateTime, BigInteger, Text
import os
import logging

logger = logging.getLogger(__name__)

DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://revenix:revenix123@postgres:5432/revenix_db")

# Configure proper connection pooling for production readiness
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,          # Test connections before using them
    pool_size=20,                # Maximum number of connections in the pool
    max_overflow=40,             # Additional connections beyond pool_size
    pool_timeout=30,             # Seconds to wait before giving up on getting a connection
    pool_recycle=3600,           # Recycle connections after 1 hour
    echo=False                   # Set to True for SQL logging during debugging
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

def init_database():
    """Initialize database schema with all required columns."""
    from sqlalchemy import text
    import os

    try:
        with engine.connect() as conn:
            logger.info("Adding threat_category column to alerts table...")
            result = conn.execute(text("""
                ALTER TABLE alerts
                ADD COLUMN IF NOT EXISTS threat_category TEXT DEFAULT 'ANOMALOUS BEHAVIOR';
            """))
            conn.commit()
            logger.info("threat_category column added successfully")

            logger.info("Adding training safety columns to flows table...")
            conn.execute(text("""
                ALTER TABLE flows
                ADD COLUMN IF NOT EXISTS verified_benign BOOLEAN DEFAULT NULL;
            """))
            conn.execute(text("""
                ALTER TABLE flows
                ADD COLUMN IF NOT EXISTS analyzed_at TIMESTAMP DEFAULT NULL;
            """))
            conn.execute(text("""
                ALTER TABLE flows
                ADD COLUMN IF NOT EXISTS analysis_version INTEGER DEFAULT 1;
            """))
            conn.execute(text("""
                ALTER TABLE flows
                ADD COLUMN IF NOT EXISTS training_excluded BOOLEAN DEFAULT FALSE;
            """))
            conn.execute(text("""
                ALTER TABLE flows
                ADD COLUMN IF NOT EXISTS flow_count INTEGER DEFAULT 1;
            """))
            conn.execute(text("""
                ALTER TABLE flows
                ADD COLUMN IF NOT EXISTS last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
            """))
            conn.commit()
            logger.info("Training safety and aggregation columns added successfully")

            logger.info("Ensuring agents table has IP column...")
            conn.execute(text("""
                ALTER TABLE agents
                ADD COLUMN IF NOT EXISTS ip VARCHAR(64) DEFAULT 'auto';
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_agents_ip ON agents(ip);
            """))
            conn.commit()
            logger.info("Agents IP column verified successfully")

            logger.info("Adding indexes for training queries...")
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_flows_analyzed
                ON flows(analyzed_at) WHERE analyzed_at IS NULL;
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_flows_verified_benign
                ON flows(verified_benign) WHERE verified_benign = TRUE;
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_flows_training_safe
                ON flows(timestamp, training_excluded) WHERE training_excluded = FALSE;
            """))
            conn.execute(text("""
                CREATE INDEX IF NOT EXISTS idx_flows_aggregation
                ON flows(src_ip, dst_ip, protocol, timestamp DESC);
            """))
            conn.commit()
            logger.info("Indexes created successfully")

            # ============================================================================
            # USERS & AUTH SCHEMA INITIALIZATION (FIRST!)
            # ============================================================================
            logger.info("[Auth] Initializing users database schema...")
            
            # Try multiple paths
            possible_paths = [
                "/app/../deploy/sql/users.sql",
                "/app/deploy/sql/users.sql",
                "/deploy/sql/users.sql",
                "./deploy/sql/users.sql"
            ]
            
            users_sql_path = None
            for path in possible_paths:
                if os.path.exists(path):
                    users_sql_path = path
                    break
            
            if users_sql_path:
                logger.info(f"[Auth] Loading users schema from {users_sql_path}")
                with open(users_sql_path, 'r') as f:
                    users_schema_sql = f.read()
                
                # Execute the schema (it's idempotent with IF NOT EXISTS)
                conn.execute(text(users_schema_sql))
                conn.commit()
                logger.info("[Auth] ✅ Users schema initialized successfully!")
            else:
                logger.error(f"[Auth] ❌ Users schema file not found! Tried: {possible_paths}")
                # Create table manually as fallback
                logger.info("[Auth] Creating users table manually as fallback...")
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS users (
                        id SERIAL PRIMARY KEY,
                        username VARCHAR(50) UNIQUE NOT NULL,
                        email VARCHAR(255) UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        full_name VARCHAR(255) NOT NULL,
                        organization VARCHAR(255),
                        role VARCHAR(20) DEFAULT 'user',
                        is_active BOOLEAN DEFAULT TRUE,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        last_login TIMESTAMP,
                        failed_login_attempts INTEGER DEFAULT 0,
                        locked_until TIMESTAMP,
                        metadata JSONB DEFAULT '{}'::jsonb
                    );
                    CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
                    CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
                """))
                conn.commit()
                logger.info("[Auth] ✅ Users table created manually!")
            
            # ============================================================================
            # PHASE 1 WEEK 1: SELF-HEALING SCHEMA INITIALIZATION
            # ============================================================================
            logger.info("[Phase 1 Week 1] Initializing self-healing database schema...")
            
            # Read and execute self_healing.sql
            sql_file_path = "/app/../deploy/sql/self_healing.sql"
            if os.path.exists(sql_file_path):
                logger.info(f"[Phase 1 Week 1] Loading self-healing schema from {sql_file_path}")
                with open(sql_file_path, 'r') as f:
                    schema_sql = f.read()
                
                # Execute the schema (it's idempotent with IF NOT EXISTS)
                conn.execute(text(schema_sql))
                conn.commit()
                logger.info("[Phase 1 Week 1] ✅ Self-healing schema initialized successfully!")
            else:
                logger.warning(f"[Phase 1 Week 1] Self-healing schema file not found at {sql_file_path}")
            
            
            # ============================================================================
            # PHASE 1 WEEK 2: ONLINE LEARNING SCHEMA INITIALIZATION
            # ============================================================================
            logger.info("[Phase 1 Week 2] Initializing online learning database schema...")
            
            # Read and execute week2_online_learning.sql
            week2_sql_path = "/app/../deploy/sql/week2_online_learning.sql"
            if os.path.exists(week2_sql_path):
                logger.info(f"[Phase 1 Week 2] Loading online learning schema from {week2_sql_path}")
                with open(week2_sql_path, 'r') as f:
                    week2_schema_sql = f.read()
                
                # Execute the schema (it's idempotent with IF NOT EXISTS)
                conn.execute(text(week2_schema_sql))
                conn.commit()
                logger.info("[Phase 1 Week 2] ✅ Online learning schema initialized successfully!")
            else:
                logger.warning(f"[Phase 1 Week 2] Online learning schema file not found at {week2_sql_path}")

    except Exception as e:
        logger.error(f"Database init error: {e}")
        raise

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_flows(limit=100):
    """Get all flows with Day 22 and Day 23 columns."""
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT
                    id,
                    flow_id,
                    hostname,
                    src_ip,
                    dst_ip,
                    src_port,
                    dst_port,
                    protocol,
                    bytes,
                    packets,
                    start_ts,
                    end_ts,
                    timestamp,
                    verified_benign,
                    analyzed_at,
                    analysis_version,
                    training_excluded,
                    flow_count,
                    last_seen
                FROM flows
                ORDER BY timestamp DESC
                LIMIT :limit
            """), {"limit": limit})

            flows = []
            for row in result:
                flows.append({
                    "id": row[0],
                    "flow_id": row[1],
                    "hostname": row[2],
                    "src_ip": row[3],
                    "dst_ip": row[4],
                    "src_port": row[5],
                    "dst_port": row[6],
                    "protocol": row[7],
                    "bytes": row[8],
                    "packets": row[9],
                    "start_ts": row[10],
                    "end_ts": row[11],
                    "timestamp": row[12].isoformat() if row[12] else None,
                    "verified_benign": row[13],
                    "analyzed_at": row[14].isoformat() if row[14] else None,
                    "analysis_version": row[15],
                    "training_excluded": row[16],
                    "flow_count": row[17],
                    "last_seen": row[18].isoformat() if row[18] else None
                })
            return flows
    except Exception as e:
        logger.error(f"Error fetching flows: {e}")
        return []

def get_unanalyzed_flows(limit=100):
    """Get flows that haven't been analyzed yet."""
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT
                    id, flow_id, hostname, src_ip, dst_ip,
                    src_port, dst_port, protocol, bytes, packets,
                    start_ts, end_ts, timestamp,
                    verified_benign, analyzed_at, analysis_version, training_excluded,
                    flow_count, last_seen
                FROM flows
                WHERE analyzed_at IS NULL
                ORDER BY timestamp ASC
                LIMIT :limit
            """), {"limit": limit})

            flows = []
            for row in result:
                flows.append({
                    "id": row[0],
                    "flow_id": row[1],
                    "hostname": row[2],
                    "src_ip": row[3],
                    "dst_ip": row[4],
                    "src_port": row[5],
                    "dst_port": row[6],
                    "protocol": row[7],
                    "bytes": row[8],
                    "packets": row[9],
                    "start_ts": row[10],
                    "end_ts": row[11],
                    "timestamp": row[12].isoformat() if row[12] else None,
                    "verified_benign": row[13],
                    "analyzed_at": row[14].isoformat() if row[14] else None,
                    "analysis_version": row[15],
                    "training_excluded": row[16],
                    "flow_count": row[17],
                    "last_seen": row[18].isoformat() if row[18] else None
                })
            return flows
    except Exception as e:
        logger.error(f"Error fetching unanalyzed flows: {e}")
        return []

def get_training_safe_flows(limit=1000):
    """Get flows that are safe for training (verified benign or >24hrs old without alerts)."""
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            result = conn.execute(text("""
                SELECT
                    id, flow_id, timestamp, hostname, src_ip, dst_ip,
                    src_port, dst_port, protocol, packets, bytes,
                    start_ts, end_ts
                FROM flows
                WHERE training_excluded = FALSE
                AND (
                    verified_benign = TRUE
                    OR (timestamp < NOW() - INTERVAL '24 hours' AND analyzed_at IS NOT NULL)
                )
                ORDER BY timestamp DESC
                LIMIT :limit
            """), {"limit": limit})

            flows = []
            for row in result:
                flows.append({
                    "id": row[0],
                    "flow_id": row[1],
                    "timestamp": row[2].isoformat() if row[2] else None,
                    "hostname": row[3],
                    "src_ip": row[4],
                    "dst_ip": row[5],
                    "src_port": row[6],
                    "dst_port": row[7],
                    "protocol": row[8],
                    "packets": row[9],
                    "bytes": row[10],
                    "start_ts": row[11],
                    "end_ts": row[12]
                })
            return flows
    except Exception as e:
        logger.error(f"Error fetching training-safe flows: {e}")
        return []

def mark_flow_analyzed(flow_id: int, analysis_version: int = 1):
    """Mark a flow as analyzed."""
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            conn.execute(text("""
                UPDATE flows
                SET analyzed_at = NOW(), analysis_version = :version
                WHERE id = :flow_id
            """), {"flow_id": flow_id, "version": analysis_version})
            conn.commit()
            return True
    except Exception as e:
        logger.error(f"Error marking flow analyzed: {e}")
        return False

def exclude_flow_from_training(flow_id: int):
    """Exclude a flow from training (used when flow triggers alert)."""
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            conn.execute(text("""
                UPDATE flows
                SET training_excluded = TRUE
                WHERE id = :flow_id
            """), {"flow_id": flow_id})
            conn.commit()
            return True
    except Exception as e:
        logger.error(f"Error excluding flow from training: {e}")
        return False

def check_and_aggregate_flow(src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                             protocol: str, packets: int, bytes: int) -> dict:
    """
    Check if similar flow exists in recent time window and aggregate.
    Returns: {"is_duplicate": bool, "flow_id": int or None, "aggregated": bool}
    """
    from sqlalchemy import text
    try:
        with engine.connect() as conn:
            # Look for matching flow in last 5 seconds
            result = conn.execute(text("""
                SELECT id, flow_count, packets, bytes
                FROM flows
                WHERE src_ip = :src_ip
                AND dst_ip = :dst_ip
                AND src_port = :src_port
                AND dst_port = :dst_port
                AND protocol = :protocol
                AND timestamp > NOW() - INTERVAL '5 seconds'
                ORDER BY timestamp DESC
                LIMIT 1
            """), {
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol
            })

            row = result.fetchone()
            if row:
                # Aggregate into existing flow
                flow_id = row[0]
                new_flow_count = row[1] + 1
                new_packet_count = row[2] + packets
                new_byte_count = row[3] + bytes

                conn.execute(text("""
                    UPDATE flows
                    SET flow_count = :flow_count,
                        packets = :packet_count,
                        bytes = :byte_count,
                        last_seen = NOW()
                    WHERE id = :flow_id
                """), {
                    "flow_id": flow_id,
                    "flow_count": new_flow_count,
                    "packet_count": new_packet_count,
                    "byte_count": new_byte_count
                })
                conn.commit()

                return {
                    "is_duplicate": True,
                    "flow_id": flow_id,
                    "aggregated": True
                }
            else:
                # Not a duplicate
                return {
                    "is_duplicate": False,
                    "flow_id": None,
                    "aggregated": False
                }
    except Exception as e:
        logger.error(f"Error checking flow aggregation: {e}")
        return {
            "is_duplicate": False,
            "flow_id": None,
            "aggregated": False
        }
