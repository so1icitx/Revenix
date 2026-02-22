import asyncio
import contextlib
import json
import time
import os
from datetime import datetime
from typing import Optional
import redis.asyncio as aioredis
from sqlalchemy import text
from db import SessionLocal
from app.websocket_broadcast import broadcast_alert
import logging

logger = logging.getLogger(__name__)
REDIS_URL = os.getenv("REDIS_URL", "redis://redis:6379")

class LearningPhaseChecker:
    """Check if system is in learning/active mode before processing flows"""
    def __init__(self):
        self.phase = "idle"
        self.last_check = 0
        self.check_interval = 5  # Check every 5 seconds
    
    async def is_capturing_enabled(self) -> bool:
        """Check if we should capture flows (learning or active phase)"""
        now = time.time()
        if now - self.last_check > self.check_interval:
            await self._refresh_phase()
            self.last_check = now
        return self.phase in ["learning", "active"]
    
    async def _refresh_phase(self):
        """Fetch current learning phase from database"""
        try:
            async with SessionLocal() as session:
                # Check the learning_state table or use a simple approach
                result = await session.execute(
                    text("SELECT config_value FROM model_config WHERE config_key = 'learning_phase'")
                )
                row = result.fetchone()
                if row:
                    self.phase = row[0]
                else:
                    # Default to idle if not set
                    self.phase = "idle"
        except Exception as e:
            logger.error(f"[LearningPhase] Failed to check phase: {e}")
            # Keep previous phase on error

learning_checker = LearningPhaseChecker()

# Suppress repeated DPI alert spam for the same event signature.
DPI_ALERT_COOLDOWN_SECONDS = 45
_recent_dpi_alerts = {}
_max_recent_dpi_alerts = 5000

# Real-time port scan detector
class PortScanDetector:
    """Heuristic port scan detector for immediate alerting"""
    def __init__(self):
        self.scan_tracker = {}
        self.alerted_ips = {}
        self.cleanup_interval = 60
        self.alert_cooldown = 300
        self.last_cleanup = time.time()
        self.agent_ips = set(["127.0.0.1"])
        self.agent_hostnames = {}
        
    def check_for_scan(self, flow: dict) -> dict:
        """
        Check if flow indicates port scanning behavior.
        Returns alert dict if scan detected, None otherwise.
        """
        src_ip = flow.get("src_ip")
        dst_ip = flow.get("dst_ip")
        dst_port = flow.get("dst_port", 0)
        protocol = flow.get("protocol", "")
        hostname = flow.get("hostname", "")
        
        if not src_ip or not dst_ip or dst_port == 0:
            return None
        
        # Auto-discover and whitelist agent IPs
        # If this flow came from an agent (has hostname), remember its IP
        if hostname:
            if hostname not in self.agent_hostnames or self.agent_hostnames[hostname] != src_ip:
                self.agent_hostnames[hostname] = src_ip
                self.agent_ips.add(src_ip)
                logger.info(f"[PortScan] Auto-whitelisted agent IP: {src_ip} (hostname: {hostname})")
        
        # Whitelist scans from agent machines (legitimate security testing)
        if src_ip in self.agent_ips:
            return None
            
        # Clean up old entries periodically
        now = time.time()
        if now - self.last_cleanup > self.cleanup_interval:
            self._cleanup_old_entries()
            self.last_cleanup = now
        
        # Track unique destination ports per source-destination pair
        if src_ip not in self.scan_tracker:
            self.scan_tracker[src_ip] = {}
        
        if dst_ip not in self.scan_tracker[src_ip]:
            self.scan_tracker[src_ip][dst_ip] = {
                'ports': set(),
                'first_seen': now,
                'last_seen': now
            }
        
        tracker = self.scan_tracker[src_ip][dst_ip]
        tracker['ports'].add(dst_port)
        tracker['last_seen'] = now
        
        # Port scan detection criteria:
        # - 15+ unique ports to same dst in < 30 seconds = definite scan
        # - 25+ unique ports across all dsts from same src = network scan
        unique_ports = len(tracker['ports'])
        time_window = now - tracker['first_seen']
        
        # Count total unique ports scanned by this source across all destinations
        total_ports_scanned = sum(len(t['ports']) for t in self.scan_tracker[src_ip].values())
        total_targets = len(self.scan_tracker[src_ip])
        
        # Check if we've already alerted for this IP recently
        if src_ip in self.alerted_ips:
            time_since_alert = now - self.alerted_ips[src_ip]
            if time_since_alert < self.alert_cooldown:
                # Still in cooldown period, don't create duplicate alert
                return None
        
        # Definite port scan: many ports to single target in short time
        if unique_ports >= 15 and time_window < 30:
            self.alerted_ips[src_ip] = now  # Mark as alerted
            return {
                'type': 'port_scan',
                'src_ip': src_ip,
                'dst_ip': dst_ip,
                'ports_scanned': unique_ports,
                'time_window': time_window,
                'severity': 'critical',
                'confidence': 0.98,
                'description': f'Port scan detected: {unique_ports} ports probed in {int(time_window)}s'
            }
        
        # Network scan: many ports across multiple targets
        if total_ports_scanned >= 25 and total_targets >= 2:
            self.alerted_ips[src_ip] = now  # Mark as alerted
            return {
                'type': 'network_scan',
                'src_ip': src_ip,
                'targets': total_targets,
                'ports_scanned': total_ports_scanned,
                'severity': 'critical',
                'confidence': 0.95,
                'description': f'Network scan detected: {total_ports_scanned} ports across {total_targets} targets'
            }
        
        return None
    
    def _cleanup_old_entries(self):
        """Remove scan tracker entries older than 60 seconds"""
        now = time.time()
        # Clean up scan tracker
        for src_ip in list(self.scan_tracker.keys()):
            for dst_ip in list(self.scan_tracker[src_ip].keys()):
                if now - self.scan_tracker[src_ip][dst_ip]['last_seen'] > 60:
                    del self.scan_tracker[src_ip][dst_ip]
            if not self.scan_tracker[src_ip]:
                del self.scan_tracker[src_ip]
        
        # Clean up alerted IPs (after cooldown expires)
        for src_ip in list(self.alerted_ips.keys()):
            if now - self.alerted_ips[src_ip] > self.alert_cooldown:
                del self.alerted_ips[src_ip]

# Global port scan detector instance
port_scan_detector = PortScanDetector()

async def get_max_flow_limit(default: int = 1000) -> int:
    """Read max_flows_stored from model_config for stream trimming."""
    try:
        async with SessionLocal() as session:
            result = await session.execute(
                text("SELECT config_value FROM model_config WHERE config_key = 'max_flows_stored'")
            )
            row = result.fetchone()
            if row:
                return max(100, int(row[0]))
    except Exception as exc:
        logger.error(f"[Consumer] Failed to fetch max_flows_stored: {exc}")
    return default

def _cleanup_dpi_alert_cache(now: float):
    """Prune old DPI dedupe entries and cap memory growth."""
    expired_keys = [
        key for key, ts in _recent_dpi_alerts.items()
        if (now - ts) > DPI_ALERT_COOLDOWN_SECONDS
    ]
    for key in expired_keys:
        _recent_dpi_alerts.pop(key, None)

    if len(_recent_dpi_alerts) > _max_recent_dpi_alerts:
        # Drop oldest keys by timestamp.
        oldest = sorted(_recent_dpi_alerts.items(), key=lambda item: item[1])[:len(_recent_dpi_alerts) - _max_recent_dpi_alerts]
        for key, _ in oldest:
            _recent_dpi_alerts.pop(key, None)


def _dpi_dedupe_key(event_type: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int, note: str) -> str:
    note_normalized = " ".join(str(note).lower().split())[:200]
    return f"{event_type}|{src_ip}|{dst_ip}|{src_port}|{dst_port}|{note_normalized}"


async def persist_dpi_alert(event: dict, stream_message_id: Optional[str] = None):
    """Persist DPI detection as alert for UI visibility."""
    event_type = event.get("type", "dpi").lower()
    src_ip = event.get("src_ip", "unknown")
    port = event.get("port", 0)
    note = event.get("note", "DPI event detected")
    dst_ip = event.get("dst_ip", "unknown")
    src_port = event.get("src_port", 0)
    dst_port = port

    # Keep DNS events low-noise: only persist confirmed tunneling verdicts.
    if event_type == "dns_tunneling" and not bool(event.get("is_tunneling", False)):
        logger.debug("[DPI Consumer] Skipping low-confidence DNS tunneling event")
        return

    severity_map = {
        "tls": ("medium", 0.85, "DPI_TLS"),
        "dns": ("medium", 0.8, "DPI_DNS"),
        "dns_tunneling": ("high", 0.92, "DPI_DNS_TUNNELING"),
        "ssh": ("high", 0.9, "DPI_SSH"),
    }
    severity, risk_score, category = severity_map.get(event_type, ("medium", 0.8, "DPI_ALERT"))

    now = time.time()
    dedupe_key = _dpi_dedupe_key(event_type, src_ip, dst_ip, src_port, dst_port, note)
    _cleanup_dpi_alert_cache(now)
    if dedupe_key in _recent_dpi_alerts and (now - _recent_dpi_alerts[dedupe_key]) <= DPI_ALERT_COOLDOWN_SECONDS:
        logger.debug(f"[DPI Consumer] Duplicate DPI alert suppressed: {dedupe_key}")
        return

    flow_suffix = (stream_message_id or str(int(now * 1000))).replace("-", "_")
    flow_id = f"dpi:{event_type}:{src_ip}:{flow_suffix}"
    timestamp = datetime.utcnow()

    try:
        async with SessionLocal() as session:
            # Cross-process dedupe: avoid inserting same DPI alert repeatedly in a short window.
            existing = await session.execute(
                text("""
                    SELECT id
                    FROM alerts
                    WHERE hostname = 'dpi_sensor'
                      AND src_ip = :src_ip
                      AND dst_ip = :dst_ip
                      AND src_port = :src_port
                      AND dst_port = :dst_port
                      AND protocol = :protocol
                      AND reason = :reason
                      AND timestamp >= NOW() - INTERVAL '45 seconds'
                    LIMIT 1
                """),
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": event_type.upper(),
                    "reason": note,
                }
            )
            if existing.fetchone():
                logger.debug(f"[DPI Consumer] DB dedupe suppressed DPI alert: {dedupe_key}")
                _recent_dpi_alerts[dedupe_key] = now
                return

            await session.execute(
                text("""
                    INSERT INTO alerts (flow_id, hostname, src_ip, dst_ip, src_port, dst_port, protocol, risk_score, severity, reason, threat_category, timestamp)
                    VALUES (:flow_id, :hostname, :src_ip, :dst_ip, :src_port, :dst_port, :protocol, :risk_score, :severity, :reason, :category, :timestamp)
                """),
                {
                    "flow_id": flow_id,
                    "hostname": "dpi_sensor",
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "src_port": src_port,
                    "dst_port": dst_port,
                    "protocol": event_type.upper(),
                    "risk_score": risk_score,
                    "severity": severity,
                    "reason": note,
                    "category": category,
                    "timestamp": timestamp,
                }
            )
            await session.commit()

        await broadcast_alert({
            "id": flow_id,
            "flow_id": flow_id,
            "hostname": "dpi_sensor",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "risk_score": risk_score,
            "severity": severity,
            "reason": note,
            "threat_category": category,
            "timestamp": timestamp.timestamp()
        })
        _recent_dpi_alerts[dedupe_key] = now
    except Exception as exc:
        logger.error(f"[Consumer] Failed to persist DPI alert: {exc}")

async def consume_dpi_results():
    """Dedicated consumer for DPI results stream."""
    print("[DPI Consumer] Starting dpi_results stream listener...")
    last_id = "0"
    while True:
        try:
            redis = await aioredis.from_url(REDIS_URL)
            print("[DPI Consumer] ✓ Connected to Redis")
            while True:
                if not await learning_checker.is_capturing_enabled():
                    await asyncio.sleep(2)
                    continue
                    
                messages = await redis.xread(
                    {"dpi_results": last_id},
                    count=50,
                    block=1000  # 1 second for faster DPI alert processing
                )
                if not messages:
                    continue

                for stream_name, stream_messages in messages:
                    for message_id, data in stream_messages:
                        last_id = message_id.decode("utf-8")
                        payload = data.get(b"result")
                        if not payload:
                            continue
                        try:
                            event = json.loads(payload.decode("utf-8"))
                            await persist_dpi_alert(event, stream_message_id=last_id)
                        except Exception as exc:
                            logger.error(f"[DPI Consumer] Failed to process event: {exc}")
        except Exception as exc:
            logger.error(f"[DPI Consumer] Redis error: {exc}")
            await asyncio.sleep(5)

async def start_redis_consumer():
    print("[Consumer] ========================================")
    print("[Consumer] Starting Redis → Postgres consumer...")
    print("[Consumer] ========================================")

    dpi_task = asyncio.create_task(consume_dpi_results())

    try:
        while True:
            try:
                redis = await aioredis.from_url(REDIS_URL)
                print("[Consumer] ✓ Connected to Redis successfully")

                last_id = "0"
                batch_size = 50  # Reduced from 100 for faster processing
                batch = []

                stream_len = await redis.xlen("flows")
                print(f"[Consumer] Redis stream has {stream_len} flows waiting")

                while True:
                    try:
                        if not await learning_checker.is_capturing_enabled():
                            print(f"[Consumer] System in '{learning_checker.phase}' phase - waiting for learning to start...")
                            await asyncio.sleep(5)
                            continue
                        
                        messages = await redis.xread(
                            {"flows": last_id},
                            count=50,
                            block=1000
                        )

                        if messages:
                            for stream_name, stream_messages in messages:
                                for message_id, data in stream_messages:
                                    flow_json = data.get(b"flow", b"{}")
                                    flow = json.loads(flow_json.decode("utf-8"))
                                    batch.append(flow)
                                    last_id = message_id.decode("utf-8")

                                    if len(batch) >= batch_size:
                                        success = await process_batch(batch)
                                        if success:
                                            max_len = await get_max_flow_limit()
                                            await redis.xtrim("flows", maxlen=max_len, approximate=True)
                                        batch = []

                        if batch:
                            success = await process_batch(batch)
                            if success:
                                max_len = await get_max_flow_limit()
                                await redis.xtrim("flows", maxlen=max_len, approximate=True)
                            batch = []

                    except Exception as e:
                        print(f"[Consumer] Error in read loop: {e}")
                        await asyncio.sleep(2)

            except Exception as e:
                print(f"[Consumer] Redis connection failed: {e}")
                print(f"[Consumer] Retrying in 5 seconds...")
                await asyncio.sleep(5)
    finally:
        dpi_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await dpi_task

async def process_batch(batch):
    """Process multiple flows in a single database transaction with aggregation"""
    if not batch:
        return True

    try:
        async with SessionLocal() as session:
            inserted_count = 0
            aggregated_count = 0
            scan_alerts = []  # Track scan alerts to create

            for flow in batch:
                # Check for port scan/network scan patterns (real-time heuristic)
                scan_result = port_scan_detector.check_for_scan(flow)
                if scan_result:
                    scan_alerts.append(scan_result)
                    logger.warning(f"[PortScan Detector] {scan_result['description']}")
                

                start_ts = flow.get("start_ts", 0)
                bucketed_ts = start_ts - (start_ts % 5)

                result = await session.execute(
                    text("""
                        INSERT INTO flows (flow_id, hostname, src_ip, dst_ip, src_port, dst_port, protocol, bytes, packets, start_ts, end_ts, flow_count, last_seen)
                        VALUES (:flow_id, :hostname, :src_ip, :dst_ip, :src_port, :dst_port, :protocol, :bytes, :packets, :start_ts, :end_ts, 1, NOW())
                        ON CONFLICT (src_ip, dst_ip, src_port, dst_port, protocol, (start_ts - (start_ts % 5)))
                        DO UPDATE SET
                            packets = EXCLUDED.packets,
                            bytes = EXCLUDED.bytes,
                            flow_count = COALESCE(flows.flow_count, 0) + 1,
                            last_seen = NOW(),
                            end_ts = GREATEST(flows.end_ts, EXCLUDED.end_ts)
                        RETURNING (xmax = 0) AS inserted
                    """),
                    {
                        "flow_id": flow.get("flow_id", ""),
                        "hostname": flow.get("hostname", ""),
                        "src_ip": flow.get("src_ip", ""),
                        "dst_ip": flow.get("dst_ip", ""),
                        "src_port": flow.get("src_port", 0),
                        "dst_port": flow.get("dst_port", 0),
                        "protocol": flow.get("protocol", ""),
                        "bytes": flow.get("bytes", 0),
                        "packets": flow.get("packets", 0),
                        "start_ts": start_ts,
                        "end_ts": flow.get("end_ts", start_ts)
                    }
                )

                row = result.fetchone()
                if row and row[0]:
                    inserted_count += 1
                else:
                    aggregated_count += 1

            # Commit flows first
            try:
                await session.commit()
            except Exception as e:
                logger.error(f"[Consumer] Flow commit failed: {e}")
                await session.rollback()
                return False

        # Create alerts in a SEPARATE session (after flow session is closed)
        print(f"[PortScan] DEBUG: About to create {len(scan_alerts)} alerts")
        for scan in scan_alerts:
            print(f"[PortScan] DEBUG: Creating alert for {scan['src_ip']}: {scan['description']}")
            try:
                async with SessionLocal() as alert_session:
                    alert_result = await alert_session.execute(
                        text("""
                            INSERT INTO alerts (flow_id, hostname, src_ip, dst_ip, src_port, dst_port, protocol, severity, risk_score, reason, threat_category, timestamp)
                            VALUES (:flow_id, :hostname, :src_ip, :dst_ip, :src_port, :dst_port, :protocol, :severity, :risk_score, :reason, :category, NOW())
                            RETURNING id
                        """),
                        {
                            "flow_id": f"scan_{scan['src_ip']}_{int(time.time())}",
                            "hostname": "port_scan_detector",
                            "src_ip": scan['src_ip'],
                            "dst_ip": scan.get('dst_ip', 'multiple'),
                            "src_port": 0,
                            "dst_port": 0,
                            "protocol": "TCP",
                            "severity": scan['severity'],
                            "risk_score": scan['confidence'],
                            "reason": scan['description'],
                            "category": scan['type'].upper()
                        }
                    )
                    
                    alert_row = alert_result.fetchone()
                    print(f"[PortScan] DEBUG: Alert row result: {alert_row}")
                    await alert_session.commit()
                    print(f"[PortScan] DEBUG: Commit successful")
                    
                    if alert_row:
                        alert_id = alert_row[0]
                        print(f"[PortScan Alert] ✅ Created alert #{alert_id} for {scan['src_ip']}")
                        logger.info(f"[PortScan Alert] ✅ Created alert #{alert_id} for {scan['src_ip']}")
                        
                        # Broadcast immediately
                        alert_dict = {
                            "alert_id": alert_id,
                            "src_ip": scan['src_ip'],
                            "dst_ip": scan.get('dst_ip', 'multiple'),
                            "severity": scan['severity'],
                            "risk_score": scan['confidence'],
                            "reason": scan['description'],
                            "threat_category": scan['type'].upper(),
                            "detected_at": datetime.utcnow().isoformat()
                        }
                        broadcast_alert(alert_dict)
            except Exception as e:
                print(f"[PortScan] DEBUG: Exception occurred: {e}")
                import traceback
                traceback.print_exc()
                logger.error(f"[PortScan Alert] Failed to create alert: {e}")

        if inserted_count > 0 or aggregated_count > 0:
            print(f"[Consumer] ✓ Processed batch: {inserted_count} inserted, {aggregated_count} aggregated, {len(scan_alerts)} scans detected")

        return True

    except Exception as e:
        print(f"[Consumer] ✗ Error processing batch: {e}")
        logger.error(f"Error processing batch: {e}")
        return False
