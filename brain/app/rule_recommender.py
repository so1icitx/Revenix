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
        self.rule_confidence_threshold = 0.7

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

    def recommend_rules(self, flow: Dict, risk_score: float, reason: str) -> List[Dict]:
        """
        Generate firewall rule recommendations for a threat.
        Returns list of recommended rules with confidence scores.
        """
        rules = []
        src_ip = flow.get("src_ip", "")
        dst_ip = flow.get("dst_ip", "")

        if risk_score >= 0.8 and not self.is_private_ip(src_ip):
            rules.append({
                "rule_type": "block_ip",
                "action": "BLOCK",
                "target": src_ip,
                "reason": f"High risk external IP ({risk_score:.2f}): {reason}",
                "confidence": min(risk_score, 1.0)
            })

        if 0.6 <= risk_score < 0.8 and not self.is_private_ip(src_ip):
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
