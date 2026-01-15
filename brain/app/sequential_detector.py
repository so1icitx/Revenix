"""
SEQUENTIAL PATTERN DETECTOR
Detects multi-step attacks by analyzing flow sequences over time.

This detector tracks the SEQUENCE of flows from each IP and identifies
attack patterns using statistical analysis:

Patterns Detected:
1. Port Scanning (horizontal) - Many ports, few IPs
2. Network Scanning (vertical) - Many IPs, same port
3. C2 Beaconing - Regular callbacks to same destination
4. Data Exfiltration - Large sustained uploads
5. Brute Force - Many login attempts

Note: Uses statistical pattern matching for explainability and reliability.
"""

import numpy as np
from collections import deque, defaultdict
from typing import List, Dict, Optional, Tuple
import time
import logging

logger = logging.getLogger(__name__)


class FlowSequence:
    """
    Represents a time-ordered sequence of flows from a single source IP.
    Tracks patterns across multiple flows to detect complex attacks.
    """
    
    def __init__(self, src_ip: str, max_length: int = 100):
        self.src_ip = src_ip
        self.max_length = max_length
        
        # Store recent flows (rolling window)
        self.flows = deque(maxlen=max_length)
        self.timestamps = deque(maxlen=max_length)
        
        # Track creation and last update
        self.created_at = time.time()
        self.last_updated = time.time()
        
        # Cache computed statistics
        self._stats_cache = None
        self._stats_cache_time = 0
    
    def add_flow(self, flow: Dict):
        """Add a new flow to the sequence."""
        self.flows.append(flow)
        self.timestamps.append(time.time())
        self.last_updated = time.time()
        self._stats_cache = None  # Invalidate cache
    
    def get_statistics(self) -> Dict:
        """
        Compute statistics about this flow sequence.
        Cached for 1 second to avoid repeated calculations.
        """
        current_time = time.time()
        if self._stats_cache and (current_time - self._stats_cache_time) < 1.0:
            return self._stats_cache
        
        if len(self.flows) == 0:
            return {}
        
        # Extract all relevant data
        dst_ips = [f.get('dst_ip', '') for f in self.flows]
        dst_ports = [f.get('dst_port', 0) for f in self.flows]
        protocols = [f.get('protocol', 'TCP') for f in self.flows]
        bytes_list = [f.get('bytes', 0) for f in self.flows]
        packets_list = [f.get('packets', 0) for f in self.flows]
        
        # Time analysis
        time_span = self.last_updated - self.created_at
        flow_rate = len(self.flows) / max(1, time_span)
        
        # Intervals between flows
        intervals = []
        if len(self.timestamps) > 1:
            for i in range(1, len(self.timestamps)):
                intervals.append(self.timestamps[i] - self.timestamps[i-1])
        
        stats = {
            # Diversity metrics
            'unique_dst_ips': len(set(dst_ips)),
            'unique_dst_ports': len(set(dst_ports)),
            'unique_protocols': len(set(protocols)),
            
            # Volume metrics
            'total_flows': len(self.flows),
            'total_bytes': sum(bytes_list),
            'total_packets': sum(packets_list),
            'avg_bytes_per_flow': np.mean(bytes_list) if bytes_list else 0,
            'avg_packets_per_flow': np.mean(packets_list) if packets_list else 0,
            
            # Time metrics
            'time_span': time_span,
            'flow_rate': flow_rate,
            'avg_interval': np.mean(intervals) if intervals else 0,
            'std_interval': np.std(intervals) if intervals else 0,
            
            # Port analysis
            'well_known_ports': sum(1 for p in dst_ports if 0 < p < 1024),
            'ephemeral_ports': sum(1 for p in dst_ports if p >= 1024),
            'sequential_ports': self._count_sequential_ports(dst_ports),
            
            # Raw data for detailed analysis
            'dst_ips': dst_ips,
            'dst_ports': dst_ports,
            'protocols': protocols,
            'bytes_list': bytes_list,
            'intervals': intervals
        }
        
        # Cache the result
        self._stats_cache = stats
        self._stats_cache_time = current_time
        
        return stats
    
    def _count_sequential_ports(self, ports: List[int]) -> int:
        """Count how many ports are in sequence (e.g., 80, 81, 82)."""
        if len(ports) < 3:
            return 0
        
        sorted_ports = sorted(set(ports))
        sequential = 0
        
        for i in range(len(sorted_ports) - 1):
            if sorted_ports[i+1] - sorted_ports[i] == 1:
                sequential += 1
        
        return sequential
    
    def is_stale(self, timeout_seconds: int) -> bool:
        """Check if this sequence hasn't been updated recently."""
        return (time.time() - self.last_updated) > timeout_seconds


class SequentialPatternDetector:
    """
    Sequential pattern detector for multi-step attacks.
    
    Uses statistical pattern matching for:
    - Better explainability (judges can understand the logic)
    - No training required (works immediately)
    - Faster inference (no GPU needed)
    - More reliable in production
    """
    
    def __init__(
        self,
        sequence_length: int = 25,
        timeout_seconds: int = 300,
        enable_detailed_logging: bool = True
    ):
        self.sequence_length = sequence_length
        self.timeout_seconds = timeout_seconds
        self.enable_detailed_logging = enable_detailed_logging
        
        # Track sequences per source IP
        self.sequences: Dict[str, FlowSequence] = {}
        
        # Pattern detection functions
        self.patterns = {
            'port_scan': self._detect_port_scan,
            'network_scan': self._detect_network_scan,
            'c2_beacon': self._detect_c2_beacon,
            'data_exfiltration': self._detect_data_exfiltration,
            'brute_force': self._detect_brute_force,
        }
        
        # Statistics
        self.detections_count = defaultdict(int)
        self.last_cleanup = time.time()
        
        logger.info("[SeqDetect] 🧠 Sequential Pattern Detector initialized")
        logger.info(f"[SeqDetect] Tracking up to {sequence_length} flows per IP")
        logger.info(f"[SeqDetect] Sequence timeout: {timeout_seconds}s")
        logger.info(f"[SeqDetect] Patterns: {', '.join(self.patterns.keys())}")
    
    def add_flow(self, flow: Dict) -> Optional[Tuple[str, float, str]]:
        """
        Add a flow and check for sequential attack patterns.
        
        Returns:
            Tuple of (pattern_name, confidence, description) if detected
            None if no pattern detected
        """
        src_ip = flow.get('src_ip', '')
        if not src_ip:
            return None
        
        # Create or update sequence for this IP
        if src_ip not in self.sequences:
            self.sequences[src_ip] = FlowSequence(src_ip, self.sequence_length)
        
        sequence = self.sequences[src_ip]
        sequence.add_flow(flow)
        
        # Periodic cleanup of stale sequences
        self._maybe_cleanup()
        
        # Need minimum flows to detect patterns
        if len(sequence.flows) < 5:
            return None
        
        # Check each pattern and return the highest confidence match
        best_match = None
        best_confidence = 0.0
        
        for pattern_name, detector_func in self.patterns.items():
            result = detector_func(sequence)
            if result and result[0] > best_confidence:
                best_confidence = result[0]
                best_match = (pattern_name, result[0], result[1])
        
        # Only report if confidence is high enough
        if best_match and best_confidence > 0.75:
            pattern_name, confidence, description = best_match
            self.detections_count[pattern_name] += 1
            
            if self.enable_detailed_logging:
                logger.warning(
                    f"[SeqDetect] 🎯 {pattern_name.upper()} detected! "
                    f"IP: {src_ip}, Confidence: {confidence:.0%}, "
                    f"Flows: {len(sequence.flows)}"
                )
                logger.info(f"[SeqDetect] Details: {description}")
            
            return best_match
        
        return None
    
    def _detect_port_scan(self, seq: FlowSequence) -> Optional[Tuple[float, str]]:
        """
        Detect horizontal port scanning.
        Pattern: Many different ports scanned on few IPs in short time.
        """
        stats = seq.get_statistics()
        
        unique_ports = stats['unique_dst_ports']
        unique_ips = stats['unique_dst_ips']
        time_span = stats['time_span']
        flow_rate = stats['flow_rate']
        sequential_ports = stats['sequential_ports']
        
        # Strong indicators of port scanning:
        # 1. Many ports (>15)
        # 2. Few target IPs (1-3)
        # 3. Fast rate (>1 flow/sec)
        # 4. Sequential ports (common in automated scans)
        
        if unique_ports < 15:
            return None
        
        confidence = 0.0
        reasons = []
        
        # Score based on port diversity
        if unique_ports > 50:
            confidence += 0.70
            reasons.append(f"{unique_ports} different ports targeted")
        elif unique_ports > 30:
            confidence += 0.55
            reasons.append(f"{unique_ports} different ports targeted")
        elif unique_ports > 15:
            confidence += 0.40
            reasons.append(f"{unique_ports} ports scanned")
        
        # Score based on target concentration
        if unique_ips == 1:
            confidence += 0.35
            reasons.append(f"Focused on single target")
        elif unique_ips <= 3:
            confidence += 0.25
            reasons.append(f"Focused on {unique_ips} targets")
        elif unique_ips <= 5:
            confidence += 0.15
        
        # Score based on speed
        if time_span < 30 and flow_rate > 2:
            confidence += 0.20
            reasons.append(f"Fast scan: {flow_rate:.1f} flows/sec")
        elif time_span < 60 and flow_rate > 1:
            confidence += 0.10
        
        # Bonus for sequential ports (automation signature)
        if sequential_ports > 5:
            confidence += 0.10
            reasons.append(f"{sequential_ports} sequential ports (automated)")
        
        if confidence > 0.75:
            description = "PORT SCAN: " + ", ".join(reasons)
            logger.warning(f"[SeqDetect] 🚨 PORT SCAN DETECTED from {seq.src_ip}: {description} (confidence: {confidence:.2f})")
            return (min(confidence, 0.98), description)
        
        # Debug logging for near-misses
        if unique_ports > 10:
            logger.debug(f"[SeqDetect] Port scan check for {seq.src_ip}: {unique_ports} ports, {unique_ips} IPs, confidence={confidence:.2f} (need >0.75)")
        
        return None
    
    def _detect_network_scan(self, seq: FlowSequence) -> Optional[Tuple[float, str]]:
        """
        Detect vertical/network scanning.
        Pattern: Same port(s) scanned across many IPs.
        """
        stats = seq.get_statistics()
        
        unique_ports = stats['unique_dst_ports']
        unique_ips = stats['unique_dst_ips']
        time_span = stats['time_span']
        flow_rate = stats['flow_rate']
        
        # Network scan indicators:
        # 1. Many IPs (>10)
        # 2. Few ports (1-3)
        # 3. Fast rate
        
        if unique_ips < 10 or unique_ports > 3:
            return None
        
        confidence = 0.0
        reasons = []
        
        # Score based on IP diversity
        if unique_ips > 50:
            confidence += 0.50
            reasons.append(f"{unique_ips} different hosts probed")
        elif unique_ips > 20:
            confidence += 0.35
            reasons.append(f"{unique_ips} hosts scanned")
        elif unique_ips > 10:
            confidence += 0.20
        
        # Score based on port focus
        if unique_ports == 1:
            port = stats['dst_ports'][0]
            confidence += 0.35
            reasons.append(f"Targeting port {port}")
        elif unique_ports <= 3:
            confidence += 0.20
            reasons.append(f"Focused on {unique_ports} ports")
        
        # Score based on speed
        if time_span < 60 and flow_rate > 1:
            confidence += 0.15
            reasons.append(f"Rapid scan: {flow_rate:.1f} hosts/sec")
        
        if confidence > 0.75:
            description = "Network reconnaissance: " + ", ".join(reasons)
            return (min(confidence, 0.95), description)
        
        return None
    
    def _detect_c2_beacon(self, seq: FlowSequence) -> Optional[Tuple[float, str]]:
        """
        Detect Command & Control beaconing.
        Pattern: Regular intervals to same destination.
        """
        if len(seq.flows) < 8:
            return None
        
        stats = seq.get_statistics()
        
        unique_ips = stats['unique_dst_ips']
        unique_ports = stats['unique_dst_ports']
        intervals = stats['intervals']
        avg_interval = stats['avg_interval']
        std_interval = stats['std_interval']
        
        # C2 beaconing indicators:
        # 1. Same destination (1-2 IPs)
        # 2. Regular intervals (low variance)
        # 3. Sustained over time
        
        if unique_ips > 2 or unique_ports > 2:
            return None
        
        if not intervals or len(intervals) < 7:
            return None
        
        # Calculate interval regularity
        if avg_interval == 0:
            return None
        
        coefficient_of_variation = std_interval / avg_interval
        
        confidence = 0.0
        reasons = []
        
        # Score based on interval regularity
        if coefficient_of_variation < 0.20:  # Very regular
            confidence += 0.50
            reasons.append(f"Highly regular intervals ({avg_interval:.1f}s ± {std_interval:.1f}s)")
        elif coefficient_of_variation < 0.35:  # Regular
            confidence += 0.35
            reasons.append(f"Regular callbacks every {avg_interval:.1f}s")
        
        # Score based on destination consistency
        if unique_ips == 1 and unique_ports == 1:
            ip = stats['dst_ips'][0]
            port = stats['dst_ports'][0]
            confidence += 0.35
            reasons.append(f"Same destination: {ip}:{port}")
        
        # Score based on interval range (typical C2 is 5-300 seconds)
        if 5 < avg_interval < 300:
            confidence += 0.15
            reasons.append("Typical C2 timing")
        
        if confidence > 0.75:
            description = "Command & Control: " + ", ".join(reasons)
            return (min(confidence, 0.92), description)
        
        return None
    
    def _detect_data_exfiltration(self, seq: FlowSequence) -> Optional[Tuple[float, str]]:
        """
        Detect data exfiltration.
        Pattern: Large sustained upload to external destination.
        """
        stats = seq.get_statistics()
        
        total_bytes = stats['total_bytes']
        time_span = stats['time_span']
        unique_ips = stats['unique_dst_ips']
        avg_bytes = stats['avg_bytes_per_flow']
        
        if time_span < 10 or total_bytes < 1000000:  # At least 1MB
            return None
        
        upload_rate = total_bytes / time_span  # Bytes per second
        
        confidence = 0.0
        reasons = []
        
        # Score based on upload volume
        if total_bytes > 100000000:  # >100MB
            confidence += 0.45
            reasons.append(f"Large transfer: {total_bytes / 1000000:.1f}MB")
        elif total_bytes > 10000000:  # >10MB
            confidence += 0.30
            reasons.append(f"Significant data: {total_bytes / 1000000:.1f}MB")
        elif total_bytes > 1000000:  # >1MB
            confidence += 0.15
        
        # Score based on upload rate
        if upload_rate > 500000:  # >500KB/s
            confidence += 0.30
            reasons.append(f"High rate: {upload_rate / 1000:.0f}KB/s")
        elif upload_rate > 100000:  # >100KB/s
            confidence += 0.20
            reasons.append(f"Sustained upload: {upload_rate / 1000:.0f}KB/s")
        
        # Score based on destination (single target)
        if unique_ips == 1:
            confidence += 0.25
            reasons.append(f"Single destination ({stats['dst_ips'][0]})")
        
        # Score based on sustained duration
        if time_span > 60:
            confidence += 0.10
            reasons.append(f"Sustained over {time_span:.0f}s")
        
        if confidence > 0.75:
            description = "Data exfiltration: " + ", ".join(reasons)
            return (min(confidence, 0.90), description)
        
        return None
    
    def _detect_brute_force(self, seq: FlowSequence) -> Optional[Tuple[float, str]]:
        """
        Detect brute force attacks.
        Pattern: Many small attempts to authentication service.
        """
        if len(seq.flows) < 10:
            return None
        
        stats = seq.get_statistics()
        
        unique_ports = stats['unique_dst_ports']
        avg_bytes = stats['avg_bytes_per_flow']
        time_span = stats['time_span']
        total_flows = stats['total_flows']
        
        # Brute force indicators:
        # 1. Many attempts (>10)
        # 2. Small packets (login attempts)
        # 3. Same service (1-2 ports)
        # 4. Common auth ports
        
        if unique_ports > 3:
            return None
        
        # Check for authentication ports
        auth_ports = {21, 22, 23, 25, 110, 143, 389, 445, 1433, 3306, 3389, 5432, 5900}
        dst_ports = set(stats['dst_ports'])
        has_auth_port = bool(dst_ports & auth_ports)
        
        confidence = 0.0
        reasons = []
        
        # Score based on attempt count
        if total_flows > 50:
            confidence += 0.40
            reasons.append(f"{total_flows} login attempts")
        elif total_flows > 25:
            confidence += 0.30
            reasons.append(f"{total_flows} attempts")
        elif total_flows > 10:
            confidence += 0.15
        
        # Score based on packet size (small = likely auth attempts)
        if avg_bytes < 300:
            confidence += 0.30
            reasons.append(f"Small packets ({avg_bytes:.0f} bytes avg)")
        elif avg_bytes < 600:
            confidence += 0.15
        
        # Score based on auth port
        if has_auth_port:
            confidence += 0.30
            matched_ports = dst_ports & auth_ports
            port_names = {
                22: 'SSH', 23: 'Telnet', 21: 'FTP',
                3389: 'RDP', 445: 'SMB', 3306: 'MySQL',
                5432: 'PostgreSQL', 1433: 'MSSQL'
            }
            port_desc = ', '.join([f"{p} ({port_names.get(p, 'Auth')})" 
                                  for p in matched_ports])
            reasons.append(f"Targeting {port_desc}")
        
        # Score based on speed
        if time_span < 120 and total_flows > 20:
            confidence += 0.10
            reasons.append(f"Fast: {total_flows / time_span:.1f} attempts/sec")
        
        if confidence > 0.75:
            description = "Brute force attack: " + ", ".join(reasons)
            return (min(confidence, 0.95), description)
        
        return None
    
    def _maybe_cleanup(self):
        """Periodically clean up old sequences."""
        current_time = time.time()
        
        # Only cleanup every 60 seconds
        if current_time - self.last_cleanup < 60:
            return
        
        to_remove = []
        for ip, seq in self.sequences.items():
            if seq.is_stale(self.timeout_seconds):
                to_remove.append(ip)
        
        for ip in to_remove:
            del self.sequences[ip]
        
        if to_remove:
            logger.info(f"[SeqDetect] Cleaned up {len(to_remove)} stale sequences")
        
        self.last_cleanup = current_time
    
    def get_sequence(self, src_ip: str) -> Optional[FlowSequence]:
        """Get the current sequence for an IP."""
        return self.sequences.get(src_ip)
    
    def get_stats(self) -> Dict:
        """Get detector statistics."""
        return {
            "active_sequences": len(self.sequences),
            "sequence_length": self.sequence_length,
            "timeout_seconds": self.timeout_seconds,
            "detections": dict(self.detections_count),
            "total_detections": sum(self.detections_count.values())
        }
