"""
CROSS-PLATFORM FIREWALL MANAGER
Supports Windows Firewall and Linux nftables/iptables
"""

import logging
import asyncio
import subprocess
import platform
import time
import ipaddress
from typing import List, Dict, Set, Optional
from enum import Enum
import aiohttp
from .internal_api import get_api_base_url, get_internal_headers

logger = logging.getLogger(__name__)

API_URL = get_api_base_url()
INTERNAL_HEADERS = get_internal_headers()


class FirewallPlatform(Enum):
    """Supported firewall platforms."""
    LINUX_NFTABLES = "linux_nftables"
    LINUX_IPTABLES = "linux_iptables"
    WINDOWS = "windows"
    UNSUPPORTED = "unsupported"


class CrossPlatformFirewallManager:
    """
    Cross-platform firewall manager that works on Windows and Linux.
    Automatically detects the platform and uses the appropriate firewall commands.
    """
    
    def __init__(
        self,
        sync_interval: int = 30,
        enable_blocking: bool = True
    ):
        self.sync_interval = sync_interval
        self.enable_blocking = enable_blocking
        
        # Track currently blocked IPs to minimize firewall calls
        self.current_blocked_ips: Set[str] = set()
        
        # Detect platform
        self.platform = self._detect_platform()
        
        logger.info(f"[FirewallManager] Initialized on platform: {self.platform.value}")
        logger.info(f"[FirewallManager] Blocking: {'ENABLED' if enable_blocking else 'DISABLED (simulation)'}")
        logger.info(f"[FirewallManager] Sync interval: {sync_interval}s")
    
    def _detect_platform(self) -> FirewallPlatform:
        """Detect which firewall platform we're running on."""
        os_name = platform.system().lower()
        
        if os_name == "windows":
            try:
                result = subprocess.run(
                    ["powershell", "-Command", "Get-NetFirewallProfile | Select-Object -First 1"],
                    capture_output=True,
                    timeout=5
                )
                if result.returncode == 0:
                    logger.info("[FirewallManager] Detected Windows with Windows Firewall")
                    return FirewallPlatform.WINDOWS
            except Exception as e:
                logger.warning(f"[FirewallManager] Windows Firewall not accessible: {e}")
            return FirewallPlatform.UNSUPPORTED
        
        elif os_name == "linux":
            # Check if nftables is available
            try:
                result = subprocess.run(
                    ["which", "nft"],
                    capture_output=True,
                    timeout=2
                )
                if result.returncode == 0:
                    logger.info("[FirewallManager] Detected Linux with nftables")
                    return FirewallPlatform.LINUX_NFTABLES
            except Exception as e:
                logger.debug(f"[FirewallManager] nftables not found: {e}")
            
            # Check if iptables is available
            try:
                result = subprocess.run(
                    ["which", "iptables"],
                    capture_output=True,
                    timeout=2
                )
                if result.returncode == 0:
                    logger.info("[FirewallManager] Detected Linux with iptables")
                    return FirewallPlatform.LINUX_IPTABLES
            except Exception as e:
                logger.debug(f"[FirewallManager] iptables not found: {e}")
            
            logger.warning("[FirewallManager] Linux detected but no firewall tools found (nft/iptables)")
            logger.warning("[FirewallManager] Running in SIMULATION mode - no actual blocking will occur")
            return FirewallPlatform.UNSUPPORTED
        
        else:
            logger.warning(f"[FirewallManager] Unsupported OS: {os_name}")
            return FirewallPlatform.UNSUPPORTED

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            logger.error(f"[FirewallManager] Invalid IP address: {ip}")
            return False

    @staticmethod
    def _ensure_iptables_jump(chain: str):
        """Insert jump only when missing to avoid duplicate rules on restarts."""
        exists = subprocess.run(
            ["iptables", "-C", chain, "-j", "REVENIX"],
            check=False,
            capture_output=True,
        )
        if exists.returncode == 0:
            return
        subprocess.run(
            ["iptables", "-I", chain, "-j", "REVENIX"],
            check=False,
            capture_output=True,
        )
    
    async def initialize_firewall(self) -> bool:
        """Initialize the firewall based on platform."""
        if not self.enable_blocking:
            logger.info("[FirewallManager] Blocking disabled, skipping initialization")
            return True
        
        if self.platform == FirewallPlatform.LINUX_NFTABLES:
            return await self._initialize_nftables()
        elif self.platform == FirewallPlatform.LINUX_IPTABLES:
            return await self._initialize_iptables()
        elif self.platform == FirewallPlatform.WINDOWS:
            return await self._initialize_windows_firewall()
        else:
            logger.warning("[FirewallManager] Unsupported platform, running in simulation")
            self.enable_blocking = False
            return False
    
    async def _initialize_nftables(self) -> bool:
        """Initialize nftables on Linux."""
        try:
            logger.info("[FirewallManager] Initializing nftables...")
            
            # Create table
            subprocess.run(
                ["nft", "add", "table", "inet", "revenix"],
                check=False,
                capture_output=True
            )
            
            # Create set for blocked IPs
            subprocess.run(
                ["nft", "add", "set", "inet", "revenix", "blocked_ips", 
                 "{ type ipv4_addr; flags interval; }"],
                check=False,
                capture_output=True
            )
            
            # Create input chain (incoming traffic)
            subprocess.run(
                ["nft", "add", "chain", "inet", "revenix", "input",
                 "{ type filter hook input priority 0; policy accept; }"],
                check=False,
                capture_output=True
            )
            
            # Create output chain (outgoing traffic)
            subprocess.run(
                ["nft", "add", "chain", "inet", "revenix", "output",
                 "{ type filter hook output priority 0; policy accept; }"],
                check=False,
                capture_output=True
            )
            
            # Add drop rule for INPUT (incoming)
            subprocess.run(
                ["nft", "add", "rule", "inet", "revenix", "input",
                 "ip", "saddr", "@blocked_ips", "counter", "drop"],
                check=True,
                capture_output=True
            )
            
            # Add drop rule for OUTPUT (outgoing)
            subprocess.run(
                ["nft", "add", "rule", "inet", "revenix", "output",
                 "ip", "daddr", "@blocked_ips", "counter", "drop"],
                check=True,
                capture_output=True
            )
            
            logger.info("[FirewallManager] ✅ nftables initialized (bidirectional blocking)")
            return True
        
        except Exception as e:
            logger.error(f"[FirewallManager] nftables initialization failed: {e}")
            return False
    
    async def _initialize_iptables(self) -> bool:
        """Initialize iptables on Linux."""
        try:
            logger.info("[FirewallManager] Initializing iptables...")
            
            # Create chain for Revenix
            subprocess.run(
                ["iptables", "-N", "REVENIX"],
                check=False,
                capture_output=True
            )
            
            # Ensure jump to custom chain exists exactly once.
            self._ensure_iptables_jump("INPUT")
            self._ensure_iptables_jump("OUTPUT")
            
            logger.info("[FirewallManager] ✅ iptables initialized (bidirectional blocking)")
            return True
        
        except Exception as e:
            logger.error(f"[FirewallManager] iptables initialization failed: {e}")
            return False
    
    async def _initialize_windows_firewall(self) -> bool:
        """Initialize Windows Firewall."""
        try:
            logger.info("[FirewallManager] Initializing Windows Firewall...")
            
            # Check if we can run PowerShell/netsh
            result = subprocess.run(
                ["powershell", "-Command", "Get-NetFirewallRule -DisplayName 'Revenix*' | Select-Object -First 1"],
                capture_output=True,
                timeout=5
            )
            
            logger.info("[FirewallManager] ✅ Windows Firewall accessible")
            return True
        
        except Exception as e:
            logger.error(f"[FirewallManager] Windows Firewall initialization failed: {e}")
            return False
    
    async def block_ip(self, ip: str, direction: str = "both") -> bool:
        """
        Block an IP address.
        
        Args:
            ip: IP address to block
            direction: "incoming", "outgoing", or "both"
        """
        if not self._validate_ip(ip):
            return False

        if not self.enable_blocking:
            logger.info(f"[FirewallManager] [SIMULATION] Would block IP: {ip} ({direction})")
            return True
        
        start_time = time.time()
        success = False
        
        try:
            if self.platform == FirewallPlatform.LINUX_NFTABLES:
                success = await self._block_ip_nftables(ip)
            elif self.platform == FirewallPlatform.LINUX_IPTABLES:
                success = await self._block_ip_iptables(ip, direction)
            elif self.platform == FirewallPlatform.WINDOWS:
                success = await self._block_ip_windows(ip, direction)
            
            if success:
                self.current_blocked_ips.add(ip)
                execution_time = int((time.time() - start_time) * 1000)
                logger.info(f"[FirewallManager] 🚫 Blocked {ip} ({direction}) - {execution_time}ms")
                await self._log_sync_action("block", ip, True, execution_time_ms=execution_time)
            
            return success
        
        except Exception as e:
            logger.error(f"[FirewallManager] Failed to block {ip}: {e}")
            await self._log_sync_action("block", ip, False, str(e))
            return False
    
    async def _block_ip_nftables(self, ip: str) -> bool:
        """Block IP using nftables (handles both directions with the set)."""
        if not self._validate_ip(ip):
            return False
        
        result = subprocess.run(
            ["nft", "add", "element", "inet", "revenix", "blocked_ips", f"{{ {ip} }}"],
            check=True,
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0
    
    async def _block_ip_iptables(self, ip: str, direction: str) -> bool:
        """Block IP using iptables."""
        success = True
        
        if direction in ["incoming", "both"]:
            result = subprocess.run(
                ["iptables", "-A", "REVENIX", "-s", ip, "-j", "DROP"],
                check=False,
                capture_output=True,
                timeout=5
            )
            success = success and (result.returncode == 0)
        
        if direction in ["outgoing", "both"]:
            result = subprocess.run(
                ["iptables", "-A", "REVENIX", "-d", ip, "-j", "DROP"],
                check=False,
                capture_output=True,
                timeout=5
            )
            success = success and (result.returncode == 0)
        
        return success
    
    async def _block_ip_windows(self, ip: str, direction: str) -> bool:
        """Block IP using Windows Firewall."""
        success = True
        
        if direction in ["incoming", "both"]:
            # Block inbound
            result = subprocess.run(
                [
                    "powershell", "-Command",
                    f"New-NetFirewallRule -DisplayName 'Revenix Block {ip} IN' "
                    f"-Direction Inbound -RemoteAddress {ip} -Action Block -ErrorAction SilentlyContinue"
                ],
                capture_output=True,
                timeout=10
            )
            success = success and (result.returncode == 0)
        
        if direction in ["outgoing", "both"]:
            # Block outbound
            result = subprocess.run(
                [
                    "powershell", "-Command",
                    f"New-NetFirewallRule -DisplayName 'Revenix Block {ip} OUT' "
                    f"-Direction Outbound -RemoteAddress {ip} -Action Block -ErrorAction SilentlyContinue"
                ],
                capture_output=True,
                timeout=10
            )
            success = success and (result.returncode == 0)
        
        return success
    
    async def unblock_ip(self, ip: str) -> bool:
        """Unblock an IP address."""
        if not self._validate_ip(ip):
            return False

        if not self.enable_blocking:
            logger.info(f"[FirewallManager] [SIMULATION] Would unblock IP: {ip}")
            return True
        
        start_time = time.time()
        success = False
        
        try:
            if self.platform == FirewallPlatform.LINUX_NFTABLES:
                success = await self._unblock_ip_nftables(ip)
            elif self.platform == FirewallPlatform.LINUX_IPTABLES:
                success = await self._unblock_ip_iptables(ip)
            elif self.platform == FirewallPlatform.WINDOWS:
                success = await self._unblock_ip_windows(ip)
            
            if success:
                self.current_blocked_ips.discard(ip)
                execution_time = int((time.time() - start_time) * 1000)
                logger.info(f"[FirewallManager] ✅ Unblocked {ip} - {execution_time}ms")
                await self._log_sync_action("unblock", ip, True, execution_time_ms=execution_time)
            
            return success
        
        except Exception as e:
            logger.error(f"[FirewallManager] Failed to unblock {ip}: {e}")
            await self._log_sync_action("unblock", ip, False, str(e))
            return False
    
    async def _unblock_ip_nftables(self, ip: str) -> bool:
        """Unblock IP using nftables."""
        result = subprocess.run(
            ["nft", "delete", "element", "inet", "revenix", "blocked_ips", f"{{ {ip} }}"],
            check=False,
            capture_output=True,
            timeout=5
        )
        return result.returncode == 0 or "not found" in result.stderr.decode().lower()
    
    async def _unblock_ip_iptables(self, ip: str) -> bool:
        """Unblock IP using iptables."""
        success = True
        
        # Remove inbound rule
        result = subprocess.run(
            ["iptables", "-D", "REVENIX", "-s", ip, "-j", "DROP"],
            check=False,
            capture_output=True,
            timeout=5
        )
        
        # Remove outbound rule
        result2 = subprocess.run(
            ["iptables", "-D", "REVENIX", "-d", ip, "-j", "DROP"],
            check=False,
            capture_output=True,
            timeout=5
        )
        
        return True  # Consider success even if rules don't exist
    
    async def _unblock_ip_windows(self, ip: str) -> bool:
        """Unblock IP using Windows Firewall."""
        # Remove inbound rule
        subprocess.run(
            [
                "powershell", "-Command",
                f"Remove-NetFirewallRule -DisplayName 'Revenix Block {ip} IN' -ErrorAction SilentlyContinue"
            ],
            capture_output=True,
            timeout=10
        )
        
        # Remove outbound rule
        subprocess.run(
            [
                "powershell", "-Command",
                f"Remove-NetFirewallRule -DisplayName 'Revenix Block {ip} OUT' -ErrorAction SilentlyContinue"
            ],
            capture_output=True,
            timeout=10
        )
        
        return True
    
    async def get_database_blocked_ips(self) -> List[Dict]:
        """Fetch currently blocked IPs from database API."""
        try:
            async with aiohttp.ClientSession(headers=INTERNAL_HEADERS) as session:
                async with session.get(f"{API_URL}/self-healing/blocked-ips") as resp:
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        logger.error(f"[FirewallManager] Failed to fetch blocked IPs: HTTP {resp.status}")
                        return []
        except Exception as e:
            logger.error(f"[FirewallManager] Error fetching blocked IPs: {e}")
            return []
    
    async def _log_sync_action(self, action: str, ip: str, success: bool, error_msg: str = None, execution_time_ms: int = 0):
        """Log firewall sync action to database."""
        try:
            async with aiohttp.ClientSession(headers=INTERNAL_HEADERS) as session:
                params = {
                    "action": action,
                    "ip": ip,
                    "success": str(success).lower(),
                    "error_message": error_msg or "",
                    "execution_time_ms": str(execution_time_ms)
                }
                async with session.post(f"{API_URL}/self-healing/firewall-sync-log", params=params) as resp:
                    if resp.status != 200:
                        logger.debug(f"[FirewallManager] Failed to log sync: HTTP {resp.status}")
        except Exception as e:
            logger.debug(f"[FirewallManager] Error logging sync: {e}")
    
    async def sync_with_database(self):
        """Sync firewall rules with database."""
        logger.info("[FirewallManager] Syncing with database...")
        
        db_blocked_ips = await self.get_database_blocked_ips()
        db_blocked_set = {entry['ip'] for entry in db_blocked_ips}
        
        logger.info(f"[FirewallManager] Database: {len(db_blocked_set)} blocked | Firewall: {len(self.current_blocked_ips)} blocked")
        
        # Block new IPs
        to_block = db_blocked_set - self.current_blocked_ips
        if to_block:
            logger.info(f"[FirewallManager] Blocking {len(to_block)} new IPs")
            for ip in to_block:
                await self.block_ip(ip)
                await asyncio.sleep(0.1)
        
        # Unblock expired IPs
        to_unblock = self.current_blocked_ips - db_blocked_set
        if to_unblock:
            logger.info(f"[FirewallManager] Unblocking {len(to_unblock)} expired IPs")
            for ip in to_unblock:
                await self.unblock_ip(ip)
                await asyncio.sleep(0.1)
        
        if not to_block and not to_unblock:
            logger.debug("[FirewallManager] In sync with database")
    
    async def run_continuous_sync(self):
        """Main service loop."""
        logger.info("[FirewallManager] 🔥 Starting continuous firewall sync...")
        
        # Initialize firewall
        if not await self.initialize_firewall():
            logger.warning("[FirewallManager] Initialization failed, running in simulation")
            self.enable_blocking = False
        
        sync_count = 0
        while True:
            try:
                sync_count += 1
                logger.info(f"[FirewallManager] Sync cycle #{sync_count}")
                
                await self.sync_with_database()
                
                logger.info(f"[FirewallManager] Next sync in {self.sync_interval}s")
                await asyncio.sleep(self.sync_interval)
            
            except Exception as e:
                logger.error(f"[FirewallManager] Sync error: {e}")
                import traceback
                traceback.print_exc()
                await asyncio.sleep(self.sync_interval)


# Global instance
firewall_manager = None

async def start_firewall_manager():
    """Start the cross-platform firewall manager."""
    global firewall_manager
    
    firewall_manager = CrossPlatformFirewallManager(
        sync_interval=30,
        enable_blocking=True
    )
    
    await firewall_manager.run_continuous_sync()

def get_firewall_manager() -> CrossPlatformFirewallManager:
    """Get the global firewall manager instance."""
    return firewall_manager
