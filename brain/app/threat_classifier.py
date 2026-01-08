import ipaddress
import numpy as np
from typing import Dict, List, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

class ThreatClassifier:
    """
    Classifies network threats into specific attack categories.
    Reduces false positives by identifying legitimate traffic patterns.
    """

    # Well-known ports for legitimate services
    WHITELIST_PORTS = {
        53,    # DNS
        80,    # HTTP
        443,   # HTTPS
        22,    # SSH
        25,    # SMTP
        587,   # SMTP Submission
        993,   # IMAPS
        995,   # POP3S
        465,   # SMTPS
        3389,  # RDP
        5432,  # PostgreSQL
        6379,  # Redis
        8080,  # HTTP Alt
        8443,  # HTTPS Alt
    }

    # Common cloud provider IP ranges (simplified - should be expanded)
    TRUSTED_RANGES = [
        "8.8.8.8",      # Google DNS
        "1.1.1.1",      # Cloudflare DNS
        "cloudflare",   # Cloudflare services

    ]

    LOCAL_MULTICAST_UDP_PORTS = {
        5353,  # mDNS
        5355,  # LLMNR
        1900,  # SSDP/UPnP
        137,   # NetBIOS Name Service
        138,   # NetBIOS Datagram
    }

    def __init__(self):
        self.threat_categories = {
            "port_scan": self._detect_port_scan,
            "ddos_attack": self._detect_ddos,
            "botnet_c2": self._detect_botnet,
            "data_exfiltration": self._detect_data_exfiltration,
            "brute_force": self._detect_brute_force,
            "dns_tunneling": self._detect_dns_tunneling,
        }

    def classify_threat(
        self,
        flow: Dict,
        features: Dict[str, float],
        risk_score: float
    ) -> Tuple[Optional[str], float, str]:
        """
        Classify the threat type and adjust confidence.

        Returns:
            (threat_category, adjusted_confidence, detailed_reason)
            Returns (None, 0.0, reason) if traffic is whitelisted/legitimate
        """
        # First check if this is legitimate traffic
        if self._is_whitelisted(flow, features):
            return (None, 0.0, "Legitimate traffic pattern - whitelisted")

        # Suppress common local control-plane traffic to reduce false positives.
        if self._is_benign_local_control_traffic(flow):
            return (None, 0.0, "Benign local control-plane traffic - suppressed")

        # Check each threat category
        threat_scores = {}

        for category_name, detector_func in self.threat_categories.items():
            is_threat, confidence, reason = detector_func(flow, features, risk_score)
            if is_threat:
                threat_scores[category_name] = (confidence, reason)

        # Return the highest confidence threat
        if threat_scores:
            best_category = max(threat_scores.items(), key=lambda x: x[1][0])
            category_name = best_category[0]
            confidence, reason = best_category[1]
            return (category_name, confidence, reason)

        # No specific threat pattern matched but ML flagged it
        if risk_score >= 0.75:
            src_ip = flow.get('src_ip', '')
            dst_ip = flow.get('dst_ip', '')
            if self._is_non_routable_or_control_ip(src_ip) or self._is_non_routable_or_control_ip(dst_ip):
                return (None, 0.0, "Non-routable/control traffic anomaly suppressed")
            return ("anomalous_behavior", risk_score, "Statistical anomaly detected by ML model")

        return (None, 0.0, "No threat detected")

    def _is_whitelisted(self, flow: Dict, features: Dict[str, float]) -> bool:
        """Check if traffic matches known legitimate patterns."""
        dst_port = flow.get('dst_port')
        src_port = flow.get('src_port')
        protocol = flow.get('protocol', 'TCP')
        dst_ip = flow.get('dst_ip', '')

        # Whitelist common service ports for TCP/UDP
        if protocol in ['TCP', 'UDP']:
            if dst_port in self.WHITELIST_PORTS or src_port in self.WHITELIST_PORTS:
                # Check if behavior looks normal for these ports
                packets = flow.get('packets', 0)
                bytes_val = flow.get('bytes', 0)

                # HTTPS/HTTP with reasonable traffic volume
                if dst_port in [443, 80, 8080, 8443]:
                    if packets < 10000 and bytes_val < 100_000_000:  # < 100MB
                        return True

                # DNS with small packets - ONLY whitelist if TRULY normal
                # Removed overly permissive DNS whitelist that was causing missed detections
                # DNS tunneling check moved to dedicated detector

                # Other common services with moderate traffic
                if dst_port in self.WHITELIST_PORTS:
                    if packets < 5000 and bytes_val < 50_000_000:
                        return True

        # Whitelist known cloud providers (simplified check)
        for trusted in self.TRUSTED_RANGES:
            if trusted in dst_ip.lower():
                return True

        return False

    def _is_non_routable_or_control_ip(self, ip: str) -> bool:
        """Return True for local-only/control-plane addresses that commonly create noise."""
        if not ip:
            return False

        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return ip.lower() in {"localhost"}

        return (
            ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_unspecified
            or ip_obj.is_reserved
        )

    def _is_benign_local_control_traffic(self, flow: Dict) -> bool:
        """
        Suppress known noisy local traffic patterns (IPv6 NDP/MLD, mDNS/LLMNR/SSDP)
        that are expected on enterprise and home networks.
        """
        protocol = str(flow.get('protocol', '')).upper()
        src_ip = flow.get('src_ip', '')
        dst_ip = flow.get('dst_ip', '')
        src_port = flow.get('src_port') or 0
        dst_port = flow.get('dst_port') or 0
        packets = flow.get('packets', 0) or 0
        bytes_val = flow.get('bytes', 0) or 0

        try:
            src_obj = ipaddress.ip_address(src_ip)
            dst_obj = ipaddress.ip_address(dst_ip)
        except ValueError:
            return False

        # ICMPv6 to multicast from unspecified/link-local/private sources is usually
        # local discovery/control chatter (NDP/MLD), not an attack.
        if protocol in {'ICMPV6', 'ICMP'} and dst_obj.is_multicast:
            if src_obj.is_unspecified or src_obj.is_link_local or src_obj.is_private:
                return True

        # Common local UDP discovery protocols.
        if protocol == 'UDP' and (src_port in self.LOCAL_MULTICAST_UDP_PORTS or dst_port in self.LOCAL_MULTICAST_UDP_PORTS):
            if src_obj.is_private or src_obj.is_link_local or src_obj.is_loopback:
                if dst_obj.is_multicast or dst_obj.is_private or dst_obj.is_link_local:
                    # Keep a sanity bound so extremely large bursts can still be analyzed.
                    if packets < 20000 and bytes_val < 100_000_000:
                        return True

        return False

    def _detect_port_scan(
        self,
        flow: Dict,
        features: Dict[str, float],
        risk_score: float
    ) -> Tuple[bool, float, str]:
        """Detect port scanning activity."""
        port_range = features.get('port_range', 0)
        unique_dst_ports = features.get('unique_dst_ports', 0)
        packets_per_sec = features.get('packets_per_sec', 0)

        # Port scan indicators:
        # - High number of different destination ports
        # - Low bytes per packet (connection attempts)
        # - High packet rate

        if port_range > 20 or unique_dst_ports > 10:
            confidence = min(0.95, 0.7 + (port_range / 100))
            reason = (
                f"PORT SCAN DETECTED: Device is systematically probing {int(port_range)} different ports. "
                f"This is characteristic reconnaissance behavior used by attackers to discover vulnerable services. "
                f"Detected {int(unique_dst_ports)} unique destination ports targeted in rapid succession."
            )
            return (True, confidence, reason)

        return (False, 0.0, "")

    def _detect_ddos(
        self,
        flow: Dict,
        features: Dict[str, float],
        risk_score: float
    ) -> Tuple[bool, float, str]:
        """Detect DDoS attack patterns."""
        packets_per_sec = features.get('packets_per_sec', 0)
        packet_rate_variance = features.get('packet_rate_variance', 0)
        bytes_val = flow.get('bytes', 0)
        dst_ip = flow.get('dst_ip', '')

        # DDoS indicators:
        # - Very high packet rate
        # - Low variance (automated/constant rate)
        # - Targeting external IP

        is_external = not self._is_private_ip(dst_ip)

        if packets_per_sec > 300 and packet_rate_variance < 100 and is_external:
            confidence = min(0.98, 0.75 + (packets_per_sec / 1000))
            reason = (
                f"DDOS ATTACK PARTICIPATION DETECTED: Device is generating extremely high-volume traffic "
                f"({int(packets_per_sec)} packets/second) with consistent timing patterns targeting external host {dst_ip}. "
                f"Low rate variance ({packet_rate_variance:.1f}) indicates automated attack traffic rather than legitimate user activity. "
                f"This device may be compromised and participating in a distributed denial-of-service attack."
            )
            return (True, confidence, reason)

        # Lower threshold for potential DDoS
        if packets_per_sec > 150 and is_external:
            confidence = 0.70
            reason = (
                f"POTENTIAL DDOS ACTIVITY: Elevated packet rate of {int(packets_per_sec)} pps directed at external IP {dst_ip}. "
                f"While not definitively malicious, this traffic volume warrants investigation for potential attack participation."
            )
            return (True, confidence, reason)

        return (False, 0.0, "")

    def _detect_botnet(
        self,
        flow: Dict,
        features: Dict[str, float],
        risk_score: float
    ) -> Tuple[bool, float, str]:
        """Detect botnet command & control patterns."""
        src_port_entropy = features.get('src_port_entropy', 0)
        dst_port_entropy = features.get('dst_port_entropy', 0)
        duration = features.get('duration', 0)
        dst_ip = flow.get('dst_ip', '')
        dst_port = flow.get('dst_port')

        # Botnet C2 indicators:
        # - Random source ports (high entropy)
        # - Unusual destination ports
        # - Regular beaconing (periodic connections)
        # - External connections

        is_external = not self._is_private_ip(dst_ip)
        unusual_port = dst_port not in self.WHITELIST_PORTS if dst_port else True

        if src_port_entropy > 2.5 and is_external and unusual_port:
            confidence = min(0.90, 0.65 + (src_port_entropy / 10))
            reason = (
                f"BOTNET C&C COMMUNICATION SUSPECTED: Traffic exhibits highly randomized source ports (entropy: {src_port_entropy:.2f}) "
                f"connecting to external IP {dst_ip} on non-standard port {dst_port}. "
                f"This pattern is characteristic of malware command-and-control communications used by botnets. "
                f"The device may be infected and receiving instructions from an attacker-controlled server."
            )
            return (True, confidence, reason)

        return (False, 0.0, "")

    def _detect_data_exfiltration(
        self,
        flow: Dict,
        features: Dict[str, float],
        risk_score: float
    ) -> Tuple[bool, float, str]:
        """Detect data exfiltration attempts."""
        total_bytes = flow.get('bytes', 0)
        duration = features.get('duration', 1)
        bytes_per_sec = total_bytes / duration if duration > 0 else 0
        dst_ip = flow.get('dst_ip', '')
        dst_port = flow.get('dst_port')

        # Data exfiltration indicators:
        # - Large outbound data transfers
        # - Sustained high throughput
        # - External destinations
        # - Non-standard ports

        is_external = not self._is_private_ip(dst_ip)
        unusual_port = dst_port not in self.WHITELIST_PORTS if dst_port else True

        # High volume exfiltration
        if total_bytes > 50_000_000 and duration > 30 and is_external:  # > 50MB over 30+ seconds
            confidence = min(0.92, 0.70 + (total_bytes / 500_000_000))
            reason = (
                f"DATA EXFILTRATION DETECTED: Sustained large outbound data transfer of {total_bytes / 1_000_000:.1f}MB "
                f"to external IP {dst_ip} over {duration:.0f} seconds ({bytes_per_sec / 1_000_000:.2f} MB/s). "
                f"This volume and pattern is inconsistent with normal network usage and suggests unauthorized data extraction. "
                f"Immediate investigation required to determine data sensitivity and prevent further loss."
            )
            return (True, confidence, reason)

        # Moderate suspicious transfer on unusual port
        if total_bytes > 10_000_000 and is_external and unusual_port:
            confidence = 0.75
            reason = (
                f"SUSPICIOUS DATA TRANSFER: {total_bytes / 1_000_000:.1f}MB transferred to external host {dst_ip} "
                f"on non-standard port {dst_port}. While this may be legitimate, the volume and port usage warrant investigation."
            )
            return (True, confidence, reason)

        return (False, 0.0, "")

    def _detect_brute_force(
        self,
        flow: Dict,
        features: Dict[str, float],
        risk_score: float
    ) -> Tuple[bool, float, str]:
        """Detect brute force attack attempts."""
        packets_per_sec = features.get('packets_per_sec', 0)
        bytes_per_packet = features.get('bytes_per_packet', 0)
        dst_port = flow.get('dst_port')
        protocol = flow.get('protocol', 'TCP')

        # Brute force indicators:
        # - Many connection attempts
        # - Small packets (auth attempts)
        # - Targeting auth services (SSH, RDP, etc.)

        auth_ports = {22, 3389, 21, 23, 5900}  # SSH, RDP, FTP, Telnet, VNC

        if dst_port in auth_ports and protocol == 'TCP':
            if packets_per_sec > 50 and bytes_per_packet < 200:
                confidence = 0.88
                reason = (
                    f"BRUTE FORCE ATTACK DETECTED: Rapid authentication attempts ({int(packets_per_sec)} attempts/second) "
                    f"targeting service on port {dst_port}. Small packet sizes ({bytes_per_packet:.0f} bytes) indicate "
                    f"automated password guessing. This is a credential stuffing attack attempting to gain unauthorized access."
                )
                return (True, confidence, reason)

        return (False, 0.0, "")

    def _detect_dns_tunneling(
        self,
        flow: Dict,
        features: Dict[str, float],
        risk_score: float
    ) -> Tuple[bool, float, str]:
        """Detect DNS tunneling for C2 or exfiltration - Production-ready detector."""
        dst_port = flow.get('dst_port')
        protocol = flow.get('protocol', 'TCP')
        packets = flow.get('packets', 0)
        bytes_val = flow.get('bytes', 0)
        bytes_per_packet = features.get('bytes_per_packet', 0)

        # DNS tunneling indicators (TUNED FOR PRODUCTION):
        # - Port 53 traffic with suspicious characteristics
        # - Unusually large DNS packets (>512 bytes is suspicious for UDP)
        # - Very high volume of DNS queries (>1000 in single flow)
        # - TCP DNS (rare - usually only for zone transfers or tunneling)

        if dst_port == 53:
            # TCP DNS is inherently suspicious (rarely used except for zone transfers)
            if protocol == 'TCP' and bytes_val > 10000:
                confidence = 0.90
                reason = (
                    f"DNS TUNNELING DETECTED: TCP-based DNS with {bytes_val:,} bytes. "
                    f"TCP DNS is rarely used legitimately and is a strong indicator of tunneling. "
                    f"Attackers use DNS tunneling to bypass firewalls and exfiltrate data or establish covert C2 channels."
                )
                return (True, confidence, reason)
            
            # UDP DNS - only flag if SIGNIFICANTLY abnormal
            if protocol == 'UDP':
                is_suspicious = False
                confidence = 0.0
                reasons = []
                
                # Large average packet size (>512 bytes for UDP DNS is suspicious)
                if bytes_per_packet > 512:
                    is_suspicious = True
                    confidence += 0.40
                    reasons.append(f"{bytes_per_packet:.0f} bytes/packet (normal: <512)")
                
                # Extremely high query volume in single flow
                if packets > 1500:
                    is_suspicious = True
                    confidence += 0.35
                    reasons.append(f"{int(packets)} queries in single flow")
                
                # High total data transfer
                if bytes_val > 500_000:  # >500KB of DNS data
                    is_suspicious = True
                    confidence += 0.30
                    reasons.append(f"{bytes_val / 1000:.0f}KB total data")
                
                if is_suspicious and confidence >= 0.75:
                    reason = (
                        f"DNS TUNNELING SUSPECTED: Abnormal DNS traffic - "
                        f"{', '.join(reasons)}. "
                        f"This pattern is characteristic of DNS tunneling used for covert data exfiltration or C2 communications."
                    )
                    return (True, min(confidence, 0.92), reason)

        return (False, 0.0, "")

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private ranges."""
        if not ip:
            return False

        try:
            ip_obj = ipaddress.ip_address(ip)
            return (
                ip_obj.is_private
                or ip_obj.is_loopback
                or ip_obj.is_link_local
                or ip_obj.is_multicast
                or ip_obj.is_unspecified
            )
        except ValueError:
            return ip.lower() == 'localhost'

    def get_threat_severity(self, threat_category: Optional[str], confidence: float) -> str:
        """Map threat category and confidence to severity level."""
        if not threat_category or confidence < 0.75:
            return "low"

        critical_threats = {"ddos_attack", "data_exfiltration", "botnet_c2"}
        high_threats = {"port_scan", "brute_force"}

        if threat_category in critical_threats and confidence >= 0.85:
            return "critical"
        elif threat_category in critical_threats or (threat_category in high_threats and confidence >= 0.90):
            return "high"
        elif confidence >= 0.80:
            return "medium"
        else:
            return "low"
