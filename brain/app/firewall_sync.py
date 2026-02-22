"""
FIREWALL SYNCHRONIZATION SERVICE
Phase 1 Week 1 Day 3-4: Actual nftables Integration

This service synchronizes the database blocked_ips table with the actual firewall (nftables).
It ensures that AI decisions are immediately enforced at the network level.
"""

import logging
import asyncio
import subprocess
import time
import ipaddress
from typing import List, Dict, Set
import aiohttp
from .internal_api import get_api_base_url, get_internal_headers

logger = logging.getLogger(__name__)

API_URL = get_api_base_url()
INTERNAL_HEADERS = get_internal_headers()

class FirewallSyncService:
    """
    Syncs blocked IPs from database to actual nftables firewall.
    Continuously monitors database and applies changes in real-time.
    """
    
    def __init__(
        self,
        sync_interval: int = 30,
        nft_table: str = "inet revenix",
        nft_set: str = "blocked_ips",
        enable_nftables: bool = True
    ):
        self.sync_interval = sync_interval
        self.nft_table = nft_table
        self.nft_set = nft_set
        self.enable_nftables = enable_nftables
        
        # Track currently blocked IPs to minimize nftables calls
        self.current_blocked_ips: Set[str] = set()
        
        logger.info("[FirewallSync] Firewall synchronization service initialized")
        logger.info(f"[FirewallSync] nftables table: {nft_table}, set: {nft_set}")
        logger.info(f"[FirewallSync] Sync interval: {sync_interval}s")
        logger.info(f"[FirewallSync] nftables enforcement: {'ENABLED' if enable_nftables else 'DISABLED (simulation mode)'}")
    
    async def initialize_nftables(self):
        """Initialize nftables table and set for blocked IPs."""
        if not self.enable_nftables:
            logger.info("[FirewallSync] nftables disabled, skipping initialization")
            return True
        
        try:
            # Create table if it doesn't exist
            logger.info(f"[FirewallSync] Creating nftables table: {self.nft_table}")
            subprocess.run(
                ["nft", "add", "table", "inet", "revenix"],
                check=False,  # Don't fail if it already exists
                capture_output=True
            )
            
            # Create set for blocked IPs (type: ipv4_addr, flags: interval for CIDR support)
            logger.info(f"[FirewallSync] Creating nftables set: {self.nft_set}")
            subprocess.run(
                ["nft", "add", "set", "inet", "revenix", self.nft_set, 
                 "{ type ipv4_addr; flags interval; }"],
                check=False,  # Don't fail if it already exists
                capture_output=True
            )
            
            # Create input chain if it doesn't exist
            logger.info("[FirewallSync] Creating input chain")
            subprocess.run(
                ["nft", "add", "chain", "inet", "revenix", "input",
                 "{ type filter hook input priority 0; policy accept; }"],
                check=False,
                capture_output=True
            )
            
            # Add rule to drop packets from blocked IPs
            logger.info("[FirewallSync] Adding drop rule for blocked IPs")
            # First, try to delete the rule if it exists
            subprocess.run(
                ["nft", "delete", "rule", "inet", "revenix", "input",
                 "ip", "saddr", "@blocked_ips", "drop"],
                check=False,
                capture_output=True
            )
            # Now add it
            subprocess.run(
                ["nft", "add", "rule", "inet", "revenix", "input",
                 "ip", "saddr", "@blocked_ips", "counter", "drop"],
                check=True,
                capture_output=True
            )
            
            logger.info("[FirewallSync] ✅ nftables initialized successfully")
            return True
        
        except subprocess.CalledProcessError as e:
            logger.error(f"[FirewallSync] Failed to initialize nftables: {e}")
            logger.error(f"[FirewallSync] stdout: {e.stdout.decode() if e.stdout else 'none'}")
            logger.error(f"[FirewallSync] stderr: {e.stderr.decode() if e.stderr else 'none'}")
            return False
        except Exception as e:
            logger.error(f"[FirewallSync] Unexpected error initializing nftables: {e}")
            return False
    
    async def get_database_blocked_ips(self) -> List[Dict]:
        """Fetch currently blocked IPs from database API."""
        try:
            async with aiohttp.ClientSession(headers=INTERNAL_HEADERS) as session:
                async with session.get(f"{API_URL}/self-healing/blocked-ips") as resp:
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        logger.error(f"[FirewallSync] Failed to fetch blocked IPs: HTTP {resp.status}")
                        return []
        except Exception as e:
            logger.error(f"[FirewallSync] Error fetching blocked IPs from database: {e}")
            return []
    
    async def log_sync_action(self, action: str, ip: str, success: bool, error_msg: str = None, execution_time_ms: int = 0):
        """Log firewall sync action to database."""
        try:
            async with aiohttp.ClientSession(headers=INTERNAL_HEADERS) as session:
                # We'll add this endpoint in the API next
                payload = {
                    "action": action,
                    "ip": ip,
                    "success": success,
                    "error_message": error_msg,
                    "execution_time_ms": execution_time_ms
                }
                async with session.post(f"{API_URL}/self-healing/firewall-sync-log", json=payload) as resp:
                    if resp.status != 200:
                        logger.warning(f"[FirewallSync] Failed to log sync action: HTTP {resp.status}")
        except Exception as e:
            logger.error(f"[FirewallSync] Error logging sync action: {e}")
    
    async def block_ip_in_firewall(self, ip: str) -> bool:
        """Add an IP to the nftables blocked set."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.error(f"[FirewallSync] Invalid IP address: {ip}")
            return False

        if not self.enable_nftables:
            logger.info(f"[FirewallSync] [SIMULATION] Would block IP: {ip}")
            return True
        
        start_time = time.time()
        try:
            # Add IP to the set
            result = subprocess.run(
                ["nft", "add", "element", "inet", "revenix", self.nft_set, f"{{ {ip} }}"],
                check=True,
                capture_output=True,
                timeout=5
            )
            
            execution_time = int((time.time() - start_time) * 1000)
            logger.info(f"[FirewallSync] 🚫 Blocked IP in firewall: {ip} ({execution_time}ms)")
            
            await self.log_sync_action("block", ip, True, execution_time_ms=execution_time)
            self.current_blocked_ips.add(ip)
            return True
        
        except subprocess.CalledProcessError as e:
            execution_time = int((time.time() - start_time) * 1000)
            error_msg = e.stderr.decode() if e.stderr else str(e)
            logger.error(f"[FirewallSync] Failed to block IP {ip}: {error_msg}")
            
            await self.log_sync_action("block", ip, False, error_msg, execution_time)
            return False
        except Exception as e:
            execution_time = int((time.time() - start_time) * 1000)
            logger.error(f"[FirewallSync] Unexpected error blocking IP {ip}: {e}")
            
            await self.log_sync_action("block", ip, False, str(e), execution_time)
            return False
    
    async def unblock_ip_in_firewall(self, ip: str) -> bool:
        """Remove an IP from the nftables blocked set."""
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            logger.error(f"[FirewallSync] Invalid IP address: {ip}")
            return False

        if not self.enable_nftables:
            logger.info(f"[FirewallSync] [SIMULATION] Would unblock IP: {ip}")
            return True
        
        start_time = time.time()
        try:
            # Remove IP from the set
            result = subprocess.run(
                ["nft", "delete", "element", "inet", "revenix", self.nft_set, f"{{ {ip} }}"],
                check=True,
                capture_output=True,
                timeout=5
            )
            
            execution_time = int((time.time() - start_time) * 1000)
            logger.info(f"[FirewallSync] ✓ Unblocked IP in firewall: {ip} ({execution_time}ms)")
            
            await self.log_sync_action("unblock", ip, True, execution_time_ms=execution_time)
            self.current_blocked_ips.discard(ip)
            return True
        
        except subprocess.CalledProcessError as e:
            execution_time = int((time.time() - start_time) * 1000)
            error_msg = e.stderr.decode() if e.stderr else str(e)
            
            # If error is "No such file or directory", it means IP wasn't in the set (which is fine)
            if "No such file or directory" in error_msg or "not found" in error_msg:
                logger.info(f"[FirewallSync] IP {ip} was not in firewall (already unblocked)")
                await self.log_sync_action("unblock", ip, True, "IP not in set", execution_time)
                self.current_blocked_ips.discard(ip)
                return True
            
            logger.error(f"[FirewallSync] Failed to unblock IP {ip}: {error_msg}")
            await self.log_sync_action("unblock", ip, False, error_msg, execution_time)
            return False
        except Exception as e:
            execution_time = int((time.time() - start_time) * 1000)
            logger.error(f"[FirewallSync] Unexpected error unblocking IP {ip}: {e}")
            
            await self.log_sync_action("unblock", ip, False, str(e), execution_time)
            return False
    
    async def sync_firewall_with_database(self):
        """
        Main sync loop: compare database with current firewall state and apply changes.
        """
        logger.info("[FirewallSync] Starting firewall synchronization...")
        
        # Fetch blocked IPs from database
        db_blocked_ips = await self.get_database_blocked_ips()
        db_blocked_set = {entry['ip'] for entry in db_blocked_ips}
        
        logger.info(f"[FirewallSync] Database has {len(db_blocked_set)} blocked IPs")
        logger.info(f"[FirewallSync] Firewall has {len(self.current_blocked_ips)} blocked IPs")
        
        # Find IPs to block (in DB but not in firewall)
        to_block = db_blocked_set - self.current_blocked_ips
        
        # Find IPs to unblock (in firewall but not in DB)
        to_unblock = self.current_blocked_ips - db_blocked_set
        
        if to_block:
            logger.info(f"[FirewallSync] Blocking {len(to_block)} new IPs: {list(to_block)[:5]}...")
            for ip in to_block:
                await self.block_ip_in_firewall(ip)
                await asyncio.sleep(0.1)  # Small delay to avoid overwhelming nftables
        
        if to_unblock:
            logger.info(f"[FirewallSync] Unblocking {len(to_unblock)} expired IPs: {list(to_unblock)[:5]}...")
            for ip in to_unblock:
                await self.unblock_ip_in_firewall(ip)
                await asyncio.sleep(0.1)
        
        if not to_block and not to_unblock:
            logger.debug("[FirewallSync] Firewall is in sync with database")
    
    async def run_continuous_sync(self):
        """
        Main service loop: continuously sync firewall with database.
        """
        logger.info("[FirewallSync] 🔥 Starting continuous firewall synchronization service...")
        
        # Initialize nftables
        if not await self.initialize_nftables():
            logger.error("[FirewallSync] Failed to initialize nftables, running in simulation mode")
            self.enable_nftables = False
        
        sync_count = 0
        while True:
            try:
                sync_count += 1
                logger.info(f"[FirewallSync] Sync cycle #{sync_count}")
                
                await self.sync_firewall_with_database()
                
                logger.info(f"[FirewallSync] Sync complete. Next sync in {self.sync_interval}s")
                await asyncio.sleep(self.sync_interval)
            
            except Exception as e:
                logger.error(f"[FirewallSync] Error in sync loop: {e}")
                import traceback
                traceback.print_exc()
                await asyncio.sleep(self.sync_interval)
    
    async def get_firewall_stats(self) -> Dict:
        """Get statistics about firewall blocks."""
        if not self.enable_nftables:
            return {
                "mode": "simulation",
                "blocked_count": len(self.current_blocked_ips),
                "blocked_ips": list(self.current_blocked_ips)
            }
        
        try:
            # Get blocked IPs from nftables
            result = subprocess.run(
                ["nft", "list", "set", "inet", "revenix", self.nft_set],
                check=True,
                capture_output=True,
                timeout=5
            )
            
            output = result.stdout.decode()
            
            # Get drop counters from the rule
            rule_result = subprocess.run(
                ["nft", "list", "chain", "inet", "revenix", "input"],
                check=True,
                capture_output=True,
                timeout=5
            )
            
            rule_output = rule_result.stdout.decode()
            
            return {
                "mode": "active",
                "blocked_count": len(self.current_blocked_ips),
                "blocked_ips": list(self.current_blocked_ips),
                "nftables_output": output,
                "rule_counters": rule_output
            }
        
        except Exception as e:
            logger.error(f"[FirewallSync] Error getting firewall stats: {e}")
            return {
                "mode": "error",
                "error": str(e),
                "blocked_count": len(self.current_blocked_ips)
            }


# Global instance
firewall_sync_service = None

async def start_firewall_sync_service():
    """Start the firewall synchronization service."""
    global firewall_sync_service
    
    firewall_sync_service = FirewallSyncService(
        sync_interval=30,  # Sync every 30 seconds
        enable_nftables=True  # Set to False for testing without root
    )
    
    await firewall_sync_service.run_continuous_sync()

def get_firewall_sync_service() -> FirewallSyncService:
    """Get the global firewall sync service instance."""
    return firewall_sync_service
