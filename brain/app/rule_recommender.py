import logging
from typing import Dict, List, Optional
import ipaddress

logger = logging.getLogger(__name__)

class RuleRecommender:
    """
    Recommends firewall rules based on detected threats.
    Analyzes anomalies and suggests mitigation actions.
    """

    def __init__(self):
        self.rule_confidence_threshold = 0.5  # Lower threshold for more rule suggestions

    def is_private_ip(self, ip: str) -> bool:
        """Check if IP is private/local (RFC1918, loopback, link-local)"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            return (
                ip_obj.is_private or
                ip_obj.is_loopback or
                ip_obj.is_link_local or
                ip_obj.is_multicast
            )
        except ValueError:
            return False

    def recommend_rules(self, flow: Dict, risk_score: float, reason: str, dpi_context: Dict = None) -> List[Dict]:
        """
        Generate firewall rule recommendations for a threat.
        Now includes DPI-based rule generation.
        Returns list of recommended rules with confidence scores.
        """
        rules = []
        src_ip = flow.get("src_ip", "")
        dst_ip = flow.get("dst_ip", "")
        dpi_context = dpi_context or {}

        # BLOCK rules for high-risk external IPs (lowered threshold)
        if risk_score >= 0.7 and not self.is_private_ip(src_ip):
            rules.append({
                "rule_type": "block_ip",
                "action": "BLOCK",
                "target": src_ip,
                "reason": f"High risk external IP ({risk_score:.2f}): {reason}",
                "confidence": min(risk_score, 1.0)
            })

        # RATE_LIMIT for medium-risk (lowered threshold)
        if 0.5 <= risk_score < 0.7 and not self.is_private_ip(src_ip):
            rules.append({
                "rule_type": "rate_limit",
                "action": "RATE_LIMIT",
                "target": src_ip,
                "reason": f"Suspicious external activity from {src_ip}: {reason}",
                "confidence": risk_score * 0.9
            })

        if ("port scan" in reason.lower() or "multiple ports" in reason.lower()) and not self.is_private_ip(src_ip):
            rules.append({
                "rule_type": "block_scanner",
                "action": "BLOCK",
                "target": src_ip,
                "reason": f"Port scanning detected from {src_ip}",
                "confidence": 0.95
            })

        if "high packet rate" in reason.lower() and not self.is_private_ip(src_ip):
            rules.append({
                "rule_type": "ddos_mitigation",
                "action": "RATE_LIMIT",
                "target": f"{src_ip} -> {dst_ip}",
                "reason": f"Potential DDoS from {src_ip}: High packet rate",
                "confidence": 0.85
            })

        protocol = flow.get("protocol", "").upper()
        if protocol not in ["TCP", "UDP", "ICMP", "ICMPV6"] and risk_score >= 0.7 and not self.is_private_ip(src_ip):
            rules.append({
                "rule_type": "block_protocol",
                "action": "BLOCK",
                "target": src_ip,  # Use src_ip instead of protocol= string
                "reason": f"Unusual protocol {protocol} with high risk from {src_ip}",
                "confidence": 0.80
            })

        # NEW: DPI-based rule recommendations
        if dpi_context:
            dpi_type = dpi_context.get('type')
            
            # Malware C2 detection (JA3)
            if dpi_context.get('is_malicious') or dpi_type == 'tls_fingerprint':
                malware_name = dpi_context.get('malware_name')
                if malware_name:
                    rules.append({
                        "rule_type": "block_malware_c2",
                        "action": "BLOCK",
                        "target": src_ip,
                        "reason": f"Malware C2 detected: {malware_name} (JA3 fingerprint match)",
                        "confidence": 0.98
                    })
            
            # DNS Tunneling
            if dpi_context.get('is_tunneling') or dpi_type == 'dns_analysis':
                suspicion = dpi_context.get('suspicion_score', 0)
                if suspicion >= 0.7:
                    domain = dpi_context.get('domain', dst_ip)
                    rules.append({
                        "rule_type": "block_dns_tunneling",
                        "action": "BLOCK",
                        "target": src_ip,
                        "reason": f"DNS tunneling detected to {domain} (entropy-based analysis)",
                        "confidence": min(suspicion + 0.1, 0.99)
                    })
            
            # SSH Brute Force
            if dpi_context.get('is_brute_force') or dpi_type == 'ssh_brute_force':
                threat_score = dpi_context.get('threat_score', 0)
                if threat_score >= 0.7:
                    failed_attempts = dpi_context.get('failed_attempts', 0)
                    rules.append({
                        "rule_type": "block_ssh_brute_force",
                        "action": "BLOCK",
                        "target": src_ip,
                        "reason": f"SSH brute force attack: {failed_attempts} failed attempts",
                        "confidence": min(threat_score + 0.15, 0.99)
            })

        high_confidence_rules = [
            rule for rule in rules
            if rule['confidence'] >= self.rule_confidence_threshold
        ]

        return high_confidence_rules

    def format_rule_command(self, rule: Dict) -> str:
        """
        Convert rule recommendation to actual firewall command.
        Generates iptables-compatible commands.
        """
        action = rule['action']
        target = rule['target']
        rule_type = rule['rule_type']

        if rule_type == "block_ip":
            return f"iptables -A INPUT -s {target} -j DROP"

        elif rule_type == "rate_limit":
            return f"iptables -A INPUT -s {target} -m limit --limit 10/min -j ACCEPT"

        elif rule_type == "block_scanner":
            return f"iptables -A INPUT -s {target} -p tcp --dport 1:65535 -j DROP"

        elif rule_type == "ddos_mitigation":
            parts = target.split(" -> ")
            if len(parts) == 2:
                src, dst = parts
                return f"iptables -A FORWARD -s {src} -d {dst} -m limit --limit 100/sec -j ACCEPT"

        elif rule_type == "block_protocol":
            return f"iptables -A INPUT -s {target} -j DROP"

        return f"# Unknown rule type: {rule_type}"
