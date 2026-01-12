import logging
import time
from typing import Dict, List, Optional, Set
from collections import defaultdict
import ipaddress
import aiohttp
import asyncio

logger = logging.getLogger(__name__)

API_URL = "http://api:8000"

class SelfHealingSystem:
    """
    Auto-whitelist trusted IPs and auto-block persistent threats.
    Implements dynamic rule updates based on AI confidence and behavior patterns.
    
    NEW FEATURES:
    - 99.9% confidence threshold for immediate blocking
    - 3-strike suspicious system (60min block)
    - 3-time benign tracking (60min whitelist)
    - Smarter, more cautious blocking
    """

    def __init__(
        self,
        # Immediate block threshold (very high confidence)
        immediate_block_threshold: float = 0.999,
        
        # Suspicious tracking (3 strikes)
        suspicious_threshold: float = 0.75,  # Lower than 99.9% but still concerning
        suspicious_strikes_to_block: int = 3,
        suspicious_block_duration_minutes: int = 60,
        
        # Benign tracking (3 confirmations)
        benign_threshold: float = 0.30,  # Low risk = benign
        benign_confirmations_to_whitelist: int = 3,
        benign_whitelist_duration_minutes: int = 60,
        
        # Long-term trust (old system)
        trust_threshold_days: int = 7,
        min_good_flows: int = 100,
        
        # Legacy alert-based blocking
        block_threshold_alerts: int = 3,
        block_duration_hours: int = 24,
        
        confidence_multiplier: float = 1.2,
        auto_block_enabled: bool = True,
        use_database: bool = True
    ):
        # NEW: Smart blocking thresholds
        self.immediate_block_threshold = immediate_block_threshold
        self.suspicious_threshold = suspicious_threshold
        self.suspicious_strikes_to_block = suspicious_strikes_to_block
        self.suspicious_block_duration_minutes = suspicious_block_duration_minutes
        
        # NEW: Benign tracking
        self.benign_threshold = benign_threshold
        self.benign_confirmations_to_whitelist = benign_confirmations_to_whitelist
        self.benign_whitelist_duration_minutes = benign_whitelist_duration_minutes
        
        # Old settings
        self.trust_threshold_days = trust_threshold_days
        self.min_good_flows = min_good_flows
        self.block_threshold_alerts = block_threshold_alerts
        self.block_duration_hours = block_duration_hours
        self.confidence_multiplier = confidence_multiplier
        self.auto_block_enabled = auto_block_enabled
        self.use_database = use_database

        # Local cache (synced from database)
        self.ip_history: Dict[str, Dict] = {}
        self.trusted_ips: Set[str] = set()
        self.blocked_ips: Dict[str, float] = {}
        self.alert_counts: Dict[str, int] = defaultdict(int)
        
        # NEW: Track suspicious and benign strikes
        self.suspicious_strikes: Dict[str, List[float]] = defaultdict(list)  # IP -> [timestamps]
        self.benign_confirmations: Dict[str, List[float]] = defaultdict(list)  # IP -> [timestamps]
        self.temp_whitelisted: Set[str] = set()  # 60min whitelisted IPs
        
        # Auto-whitelist private IP ranges (LAN, localhost, link-local)
        self.always_trusted_ranges = [
            ipaddress.IPv4Network('10.0.0.0/8'),      # Private Class A
            ipaddress.IPv4Network('172.16.0.0/12'),   # Private Class B
            ipaddress.IPv4Network('192.168.0.0/16'),  # Private Class C
            ipaddress.IPv4Network('127.0.0.0/8'),     # Localhost
            ipaddress.IPv4Network('169.254.0.0/16'),  # Link-local
        ]
        logger.info("[SelfHealing] ✅ Auto-whitelisted private IP ranges (LAN protection)")
        
        # Last sync time
        self.last_db_sync = 0
        self.sync_interval = 60  # Sync with database every 60 seconds

        logger.info("[SelfHealing] 🛡️ Smart Self-Healing System initialized!")
        logger.info(f"[SelfHealing] IMMEDIATE BLOCK: risk >= {immediate_block_threshold} (99.9%)")
        logger.info(f"[SelfHealing] SUSPICIOUS: {suspicious_threshold} <= risk < {immediate_block_threshold}")
        logger.info(f"[SelfHealing] 3-Strike Suspicious → 60min block")
        logger.info(f"[SelfHealing] BENIGN: risk < {benign_threshold}")
        logger.info(f"[SelfHealing] 3-Time Benign → 60min whitelist")
        logger.info(f"[SelfHealing] Legacy: {min_good_flows} good flows over {trust_threshold_days} days → permanent trust")
        
        # Initial sync - will be called explicitly by auto_learner after event loop starts
        # Note: Cannot use asyncio.create_task() in __init__ - no event loop yet!

    def track_flow(self, flow: Dict, is_anomaly: bool, risk_score: float):
        """
        Track flow for reputation building with new smart thresholds.
        
        Returns:
            str: Action taken ("immediate_block", "suspicious", "benign", "whitelist", "normal")
        """
        src_ip = flow.get('src_ip', '')
        dst_ip = flow.get('dst_ip', '')

        if not src_ip or self._is_private_ip(src_ip):
            return "ignored"

        current_time = time.time()

        # Initialize IP history if new
        if src_ip not in self.ip_history:
            self.ip_history[src_ip] = {
                'first_seen': current_time,
                'last_seen': current_time,
                'total_flows': 0,
                'good_flows': 0,
                'anomalous_flows': 0,
                'total_risk': 0.0,
                'destinations': set()
            }

        history = self.ip_history[src_ip]
        history['last_seen'] = current_time
        history['total_flows'] += 1
        history['total_risk'] += risk_score
        history['destinations'].add(dst_ip)

        if is_anomaly:
            history['anomalous_flows'] += 1
        else:
            history['good_flows'] += 1

        # NEW: Smart threshold-based actions
        action = self._evaluate_smart_thresholds(src_ip, risk_score, flow)
        
        # OLD: Long-term reputation evaluation
        self._evaluate_reputation(src_ip)
        
        return action
    
    def _evaluate_smart_thresholds(self, ip: str, risk_score: float, flow: Dict) -> str:
        """
        Evaluate flow against smart thresholds and take action.
        
        Returns action taken: "immediate_block", "suspicious", "benign", "whitelist", "normal"
        """
        current_time = time.time()
        
        # 1. IMMEDIATE BLOCK: 99.9% confidence (risk >= 0.999)
        if risk_score >= self.immediate_block_threshold:
            logger.warning(
                f"[SelfHealing] 🚨 IMMEDIATE BLOCK! {ip} (risk: {risk_score:.4f} >= 99.9%)"
            )
            self._auto_block_ip(
                ip,
                f"Extremely high confidence threat (risk: {risk_score:.4f})",
                flow.get('threat_category', 'CRITICAL_THREAT'),
                duration_hours=self.block_duration_hours
            )
            return "immediate_block"
        
        # 2. SUSPICIOUS: Between 75% and 99.9% (track strikes)
        elif risk_score >= self.suspicious_threshold:
            # Add strike
            self.suspicious_strikes[ip].append(current_time)
            
            # Clean old strikes (older than 10 minutes)
            self.suspicious_strikes[ip] = [
                t for t in self.suspicious_strikes[ip]
                if current_time - t < 600  # 10 minutes
            ]
            
            strike_count = len(self.suspicious_strikes[ip])
            logger.info(
                f"[SelfHealing] ⚠️ SUSPICIOUS: {ip} (risk: {risk_score:.2f}) "
                f"Strike {strike_count}/{self.suspicious_strikes_to_block}"
            )
            
            # 3 strikes → Block for 60 minutes
            if strike_count >= self.suspicious_strikes_to_block:
                logger.warning(
                    f"[SelfHealing] 🚫 3-STRIKE BLOCK! {ip} → Blocked for {self.suspicious_block_duration_minutes} mins"
                )
                self._auto_block_ip(
                    ip,
                    f"3 suspicious activities in 10 minutes (risk: {risk_score:.2f})",
                    flow.get('threat_category', 'SUSPICIOUS_PATTERN'),
                    duration_hours=self.suspicious_block_duration_minutes / 60  # Convert to hours
                )
                # Reset strikes after blocking
                self.suspicious_strikes[ip] = []
                return "suspicious_blocked"
            
            return "suspicious"
        
        # 3. BENIGN: Low risk (< 30%)
        elif risk_score < self.benign_threshold:
            # Add benign confirmation
            self.benign_confirmations[ip].append(current_time)
            
            # Clean old confirmations (older than 5 minutes)
            self.benign_confirmations[ip] = [
                t for t in self.benign_confirmations[ip]
                if current_time - t < 300  # 5 minutes
            ]
            
            confirm_count = len(self.benign_confirmations[ip])
            
            # 3 benign confirmations → Whitelist for 60 minutes
            if confirm_count >= self.benign_confirmations_to_whitelist:
                if ip not in self.temp_whitelisted and ip not in self.trusted_ips:
                    logger.info(
                        f"[SelfHealing] ✅ 3-TIME BENIGN! {ip} → Whitelisted for {self.benign_whitelist_duration_minutes} mins"
                    )
                    self._temp_whitelist_ip(ip, self.benign_whitelist_duration_minutes)
                    # Reset confirmations
                    self.benign_confirmations[ip] = []
                    return "benign_whitelisted"
            else:
                logger.debug(f"[SelfHealing] ✓ Benign: {ip} (risk: {risk_score:.2f}) Confirmation {confirm_count}/3")
            
            return "benign"
        
        # 4. NORMAL: Between 30% and 75% (no special action)
        else:
            return "normal"
    
    def _temp_whitelist_ip(self, ip: str, duration_minutes: int):
        """Temporarily whitelist an IP for a specific duration."""
        self.temp_whitelisted.add(ip)
        
        # Persist to database
        if self.use_database:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self._persist_temp_whitelist(ip, duration_minutes))
            except RuntimeError:
                logger.warning(f"[SelfHealing] No event loop, skipping temp whitelist persist for {ip}")
    
    async def _persist_temp_whitelist(self, ip: str, duration_minutes: int):
        """Persist temporary whitelist to database."""
        try:
            expires_at = time.time() + (duration_minutes * 60)
            
            async with aiohttp.ClientSession() as session:
                payload = {
                    "ip": ip,
                    "confidence": 0.7,  # Moderate confidence
                    "auto_added": True,
                    "metadata": {
                        "reason": "3 benign confirmations",
                        "duration_minutes": duration_minutes,
                        "expires_at": expires_at,
                        "temporary": True
                    }
                }
                async with session.post(f"{API_URL}/self-healing/trusted-ips/add", json=payload) as resp:
                    if resp.status in [200, 201]:
                        logger.info(f"[SelfHealing] Persisted temp whitelist for {ip}")
                    else:
                        logger.error(f"[SelfHealing] Failed to persist temp whitelist: HTTP {resp.status}")
        except Exception as e:
            logger.error(f"[SelfHealing] Error persisting temp whitelist: {e}")
    
    def is_temp_whitelisted(self, ip: str) -> bool:
        """Check if IP is temporarily whitelisted."""
        return ip in self.temp_whitelisted
    
    def is_trusted_or_whitelisted(self, ip: str) -> bool:
        """Check if IP is trusted (permanent) or temporarily whitelisted."""
        return ip in self.trusted_ips or ip in self.temp_whitelisted

    def track_alert(self, alert: Dict):
        """Track alerts for auto-blocking persistent threats."""
        src_ip = alert.get('src_ip', '')

        if not src_ip or self._is_private_ip(src_ip):
            return

        self.alert_counts[src_ip] += 1

        if self.alert_counts[src_ip] >= self.block_threshold_alerts:
            if src_ip not in self.blocked_ips:
                self._auto_block_ip(
                    src_ip, 
                    alert.get('reason', 'Persistent malicious activity'),
                    alert.get('threat_category')
                )

    def _evaluate_reputation(self, ip: str):
        """Evaluate IP reputation and potentially add to trusted list."""
        if ip in self.trusted_ips or ip in self.blocked_ips:
            return

        history = self.ip_history.get(ip)
        if not history:
            return

        current_time = time.time()
        days_observed = (current_time - history['first_seen']) / 86400

        if days_observed < self.trust_threshold_days:
            return

        if history['good_flows'] >= self.min_good_flows:
            anomaly_rate = history['anomalous_flows'] / history['total_flows']
            avg_risk = history['total_risk'] / history['total_flows']

            if anomaly_rate < 0.05 and avg_risk < 0.3:
                self._auto_whitelist_ip(ip, history)

    def _auto_whitelist_ip(self, ip: str, history: Dict):
        """Add IP to trusted whitelist."""
        self.trusted_ips.add(ip)
        
        confidence = min(0.9, history['good_flows'] / self.min_good_flows)
        
        logger.info(
            f"[SelfHealing] ✓ Auto-whitelisted {ip}: "
            f"{history['good_flows']} good flows over "
            f"{(time.time() - history['first_seen']) / 86400:.1f} days (confidence: {confidence:.2f})"
        )
        
        # Persist to database (fire and forget - no await needed)
        if self.use_database:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self._persist_trusted_ip(ip, history, confidence))
                else:
                    logger.warning(f"[SelfHealing] No event loop running, skipping database persist for {ip}")
            except RuntimeError:
                logger.warning(f"[SelfHealing] No event loop available, skipping database persist for {ip}")

    def _auto_block_ip(self, ip: str, reason: str, threat_category: str = None, duration_hours: float = None):
        """Add IP to auto-block list with custom duration."""
        if not self.auto_block_enabled:
            logger.debug(f"[SelfHealing] Auto-block disabled. Skipping block for {ip}")
            return

        if duration_hours is None:
            duration_hours = self.block_duration_hours
        
        current_time = time.time()
        block_until = current_time + (duration_hours * 3600)

        self.blocked_ips[ip] = block_until

        if ip in self.trusted_ips:
            self.trusted_ips.remove(ip)

        confidence = min(0.95, self.alert_counts[ip] / self.block_threshold_alerts)

        logger.warning(
            f"[SelfHealing] 🚫 Auto-blocked {ip} for {self.block_duration_hours}h: "
            f"{self.alert_counts[ip]} alerts - {reason} (confidence: {confidence:.2f})"
        )
        
        # Persist to database (fire and forget - no await needed)
        if self.use_database:
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self._persist_blocked_ip(ip, reason, confidence, threat_category, duration_hours))
                else:
                    logger.warning(f"[SelfHealing] No event loop running, skipping database persist for {ip}")
            except RuntimeError:
                logger.warning(f"[SelfHealing] No event loop available, skipping database persist for {ip}")

    def is_trusted(self, ip: str) -> bool:
        """Check if IP is in trusted whitelist."""
        return ip in self.trusted_ips

    def is_blocked(self, ip: str) -> bool:
        """Check if IP is currently blocked."""
        if ip not in self.blocked_ips:
            return False

        current_time = time.time()
        if current_time >= self.blocked_ips[ip]:
            del self.blocked_ips[ip]
            logger.info(f"[SelfHealing] ⏰ Auto-block expired for {ip}")
            return False

        return True

    def should_skip_analysis(self, flow: Dict) -> bool:
        """
        Determine if flow should skip anomaly detection.
        Returns True if IP is trusted or blocked.
        """
        src_ip = flow.get('src_ip', '')

        if self.is_trusted(src_ip):
            return True

        if self.is_blocked(src_ip):
            return True

        return False

    def adjust_confidence(self, src_ip: str, base_confidence: float) -> float:
        """
        Adjust rule confidence based on IP reputation.
        Increases confidence for known bad actors.
        """
        if src_ip in self.blocked_ips or self.alert_counts[src_ip] >= 2:
            return min(base_confidence * self.confidence_multiplier, 1.0)

        return base_confidence

    def get_trusted_ips(self) -> List[Dict]:
        """Get list of trusted IPs with details."""
        trusted_list = []
        for ip in self.trusted_ips:
            history = self.ip_history.get(ip, {})
            trusted_list.append({
                'ip': ip,
                'good_flows': history.get('good_flows', 0),
                'days_trusted': (time.time() - history.get('first_seen', time.time())) / 86400,
                'destinations': len(history.get('destinations', set()))
            })
        return trusted_list

    def get_blocked_ips(self) -> List[Dict]:
        """Get list of blocked IPs with expiration times."""
        current_time = time.time()
        blocked_list = []
        for ip, block_until in self.blocked_ips.items():
            remaining_hours = (block_until - current_time) / 3600
            blocked_list.append({
                'ip': ip,
                'alerts': self.alert_counts.get(ip, 0),
                'remaining_hours': max(0, remaining_hours),
                'expires_at': block_until
            })
        return blocked_list

    def get_stats(self) -> Dict:
        """Get self-healing system statistics."""
        return {
            'trusted_ips': len(self.trusted_ips),
            'blocked_ips': len(self.blocked_ips),
            'tracked_ips': len(self.ip_history),
            'total_flows_tracked': sum(h.get('total_flows', 0) for h in self.ip_history.values())
        }

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return (
                ip_obj.is_private or
                ip_obj.is_loopback or
                ip_obj.is_link_local
            )
        except ValueError:
            return False
    
    # ============================================================================
    # DATABASE PERSISTENCE METHODS (Phase 1 Week 1)
    # ============================================================================
    
    async def _sync_from_database(self):
        """Sync trusted/blocked IPs from database to local cache."""
        try:
            async with aiohttp.ClientSession() as session:
                # Sync trusted IPs
                async with session.get(f"{API_URL}/self-healing/trusted-ips") as resp:
                    if resp.status == 200:
                        trusted_ips = await resp.json()
                        self.trusted_ips = {ip['ip'] for ip in trusted_ips}
                        logger.info(f"[SelfHealing] Synced {len(self.trusted_ips)} trusted IPs from database")
                
                # Sync blocked IPs
                async with session.get(f"{API_URL}/self-healing/blocked-ips") as resp:
                    if resp.status == 200:
                        blocked_ips = await resp.json()
                        self.blocked_ips = {}
                        for block in blocked_ips:
                            if block.get('hours_remaining', 0) > 0:
                                expires_at = time.time() + (block['hours_remaining'] * 3600)
                                self.blocked_ips[block['ip']] = expires_at
                        logger.info(f"[SelfHealing] Synced {len(self.blocked_ips)} blocked IPs from database")
            
            self.last_db_sync = time.time()
        except Exception as e:
            logger.error(f"[SelfHealing] Error syncing from database: {e}")
    
    async def _persist_trusted_ip(self, ip: str, history: Dict, confidence: float):
        """Persist trusted IP to database."""
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "ip": ip,
                    "confidence": confidence,
                    "auto_added": True,
                    "metadata": {
                        "good_flows": history.get('good_flows', 0),
                        "total_flows": history.get('total_flows', 0),
                        "destinations_count": len(history.get('destinations', set())),
                        "avg_risk_score": history.get('total_risk', 0.0) / max(history.get('total_flows', 1), 1)
                    }
                }
                async with session.post(f"{API_URL}/self-healing/trusted-ips/add", json=payload) as resp:
                    if resp.status == 200:
                        logger.info(f"[SelfHealing] Persisted trusted IP {ip} to database")
                    else:
                        logger.error(f"[SelfHealing] Failed to persist trusted IP {ip}: {resp.status}")
        except Exception as e:
            logger.error(f"[SelfHealing] Error persisting trusted IP: {e}")
    
    async def _persist_blocked_ip(self, ip: str, reason: str, confidence: float, threat_category: str = None, duration_hours: float = None):
        """Persist blocked IP to database."""
        if duration_hours is None:
            duration_hours = self.block_duration_hours
        
        try:
            async with aiohttp.ClientSession() as session:
                payload = {
                    "ip": ip,
                    "block_reason": reason,
                    "confidence": confidence,
                    "expires_hours": duration_hours,
                    "threat_category": threat_category,
                    "manual_override": False
                }
                async with session.post(f"{API_URL}/self-healing/blocked-ips/add", json=payload) as resp:
                    if resp.status == 200:
                        logger.info(f"[SelfHealing] Persisted blocked IP {ip} to database ({duration_hours}h)")
                    else:
                        logger.error(f"[SelfHealing] Failed to persist blocked IP {ip}: {resp.status}")
        except Exception as e:
            logger.error(f"[SelfHealing] Error persisting blocked IP: {e}")
    
    async def should_sync_database(self) -> bool:
        """Check if it's time to sync with database."""
        current_time = time.time()
        if current_time - self.last_db_sync >= self.sync_interval:
            await self._sync_from_database()
            return True
        return False
