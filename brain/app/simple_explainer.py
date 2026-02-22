"""
ADVANCED THREAT EXPLAINER
Converts technical ML outputs into clean, structured intelligence reports.
"""

import logging
from typing import Dict, List, Optional
from .ip_intelligence import get_ip_intelligence, get_threat_context, IPIntelligence

logger = logging.getLogger(__name__)


class SimpleExplainer:
    """
    Generates clean, structured threat explanations.
    """
    
    def __init__(self):
        logger.info("[SimpleExplainer] Advanced threat analysis system initialized")
    
    def explain_threat(
        self,
        threat_category: str,
        risk_score: float,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        src_port: int = None,
        dst_port: int = None,
        packets: int = None,
        bytes_transferred: int = None,
        voting_details: Dict = None,
        sequential_pattern: str = None,
        features: Dict = None
    ) -> str:
        """Generate a clean, structured explanation of the threat."""
        
        # Get IP intelligence
        src_intel = get_ip_intelligence(src_ip)
        
        report_parts = []
        
        # Main threat explanation
        if sequential_pattern:
            report_parts.append(self._explain_sequential_pattern(sequential_pattern, src_ip, dst_ip, src_intel, features))
        elif threat_category:
            report_parts.append(self._explain_by_category(
                threat_category, src_ip, dst_ip, protocol, src_port, dst_port,
                risk_score, src_intel, features, packets, bytes_transferred
            ))
        else:
            report_parts.append(self._explain_generic_anomaly(src_ip, dst_ip, risk_score, src_intel, voting_details))
        
        # IP Intelligence section
        report_parts.append("### Source Intelligence")
        report_parts.append(self._format_ip_intel(src_intel))
        
        # Detection details
        if voting_details:
            report_parts.append("### Detection Method")
            report_parts.append(self._explain_detection_models(voting_details, risk_score))
        
        # Recommendation
        report_parts.append("### Recommended Actions")
        report_parts.append(self._make_detailed_recommendation(risk_score, threat_category, src_intel))
        
        return "\n\n".join(report_parts)
    
    def _format_ip_intel(self, intel: IPIntelligence) -> str:
        """Format IP intelligence cleanly."""
        parts = []
        
        if intel.organization:
            parts.append(f"- Organization: {intel.organization}")
        
        parts.append(f"- Category: {intel.category.value.replace('_', ' ').title()}")
        parts.append(f"- Reputation Score: {intel.reputation_score:.0f}/100")
        
        flags = []
        if intel.is_vpn:
            flags.append("VPN Service")
        if intel.is_tor:
            flags.append("TOR Exit Node")
        if intel.is_proxy:
            flags.append("Proxy Server")
        if intel.is_datacenter:
            flags.append("Cloud/Datacenter")
        if intel.is_scanner:
            flags.append("Known Scanner")
        if intel.is_known_attacker:
            flags.append("Known Attacker")
        if intel.is_botnet:
            flags.append("Botnet Infrastructure")
        
        if flags:
            parts.append(f"- Flags: {', '.join(flags)}")
        
        parts.append(f"- Assessment: {intel.details}")
        
        return "\n".join(parts)
    
    def _explain_sequential_pattern(self, pattern: str, src_ip: str, dst_ip: str, intel: IPIntelligence, features: Dict = None) -> str:
        """Explain sequential-pattern detector findings."""
        
        patterns = {
            'port_scan': (
                "### Port Scanning Attack\n\n"
                "The source IP is systematically probing multiple ports on your network to discover open services.\n\n"
                "- Technique: Sequential or randomized port enumeration\n"
                "- Goal: Identify vulnerable services for exploitation\n"
                "- Stage: Reconnaissance (pre-attack)\n"
                "- Risk: High - typically precedes targeted attacks"
            ),
            'network_scan': (
                "### Network Reconnaissance\n\n"
                "Multiple devices across your network are being scanned to map your infrastructure.\n\n"
                "- Technique: ICMP sweep or TCP/UDP probing\n"
                "- Goal: Build network topology map\n"
                "- Stage: Reconnaissance (pre-attack)\n"
                "- Risk: High - attacker planning larger operation"
            ),
            'c2_beacon': (
                "### Command & Control Communication\n\n"
                "A device on your network is sending regular check-in signals to an external server.\n\n"
                "- Pattern: Periodic outbound connections\n"
                "- Indication: Compromised endpoint with active malware\n"
                "- Risk: Critical - device under attacker control\n"
                "- Urgency: Immediate isolation required"
            ),
            'data_exfiltration': (
                "### Data Exfiltration Detected\n\n"
                "Large volumes of data are being transferred out of your network.\n\n"
                "- Pattern: Sustained high-volume outbound transfer\n"
                "- Risk: Critical - active data theft in progress\n"
                "- Potential Impact: Data breach, regulatory violations\n"
                "- Urgency: Immediate action required"
            ),
            'brute_force': (
                "### Brute Force Attack\n\n"
                "Rapid repeated authentication attempts detected from the source.\n\n"
                "- Technique: Automated credential guessing\n"
                "- Goal: Gain unauthorized access\n"
                "- Risk: High if successful - full account compromise\n"
                "- Defense: Account lockout, IP blocking"
            ),
        }
        
        base = patterns.get(pattern, f"### Suspicious Pattern: {pattern}\n\nAnomalous behavior pattern detected by sequential analysis.")
        
        # Add IP context
        context = ""
        if intel.is_vpn:
            context = f"\n\nSource is using {intel.organization or 'a VPN service'} to mask their identity."
        elif intel.is_datacenter:
            context = f"\n\nSource originates from {intel.organization or 'cloud infrastructure'} - common attack origin."
        elif intel.is_known_attacker:
            context = "\n\nThis IP is flagged in threat intelligence databases as malicious."
        
        return base + context
    
    def _explain_by_category(
        self,
        category: str,
        src_ip: str,
        dst_ip: str,
        protocol: str,
        src_port: int,
        dst_port: int,
        risk_score: float,
        intel: IPIntelligence,
        features: Dict = None,
        packets: int = None,
        bytes_transferred: int = None
    ) -> str:
        """Generate explanation by threat category."""
        
        cat_lower = category.lower()
        
        if 'port_scan' in cat_lower or 'scan' in cat_lower:
            return (
                "### Port Scan Detected\n\n"
                f"Source {src_ip} is scanning ports on your network.\n\n"
                "- Attack Type: Port Enumeration\n"
                f"- Protocol: {protocol}\n"
                "- Intent: Service discovery for vulnerability assessment\n"
                "- Typical Next Step: Targeted exploitation of discovered services"
            )
        
        elif 'ddos' in cat_lower or 'flood' in cat_lower:
            pps = features.get('packets_per_sec', 0) if features else 0
            return (
                "### DDoS Attack Detected\n\n"
                f"High-volume traffic flood from {src_ip}.\n\n"
                f"- Attack Type: Denial of Service\n"
                f"- Traffic Rate: {int(pps)} packets/second\n"
                f"- Protocol: {protocol}\n"
                "- Impact: Service degradation or outage\n"
                "- Goal: Make your services unavailable"
            )
        
        elif 'c2' in cat_lower or 'command' in cat_lower or 'botnet' in cat_lower:
            return (
                "### Malware Command & Control\n\n"
                f"Device {src_ip} is communicating with suspected C2 server {dst_ip}.\n\n"
                "- Indication: Compromised endpoint\n"
                "- Risk: Device under remote attacker control\n"
                "- Potential Actions: Data theft, ransomware deployment, lateral movement\n"
                "- Required Response: Immediate isolation and forensic analysis"
            )
        
        elif 'exfil' in cat_lower:
            return (
                "### Data Exfiltration Alert\n\n"
                f"Abnormal data transfer from {src_ip} to {dst_ip}.\n\n"
                "- Risk Level: Critical\n"
                "- Indication: Active data theft\n"
                "- Potential Data: Credentials, PII, intellectual property\n"
                "- Compliance Impact: Potential breach notification required"
            )
        
        elif 'brute' in cat_lower:
            service = self._identify_service(dst_port)
            return (
                "### Brute Force Attack\n\n"
                f"Credential guessing attack on {service}.\n\n"
                f"- Target Service: {service} (port {dst_port})\n"
                f"- Source: {src_ip}\n"
                "- Technique: Automated password guessing\n"
                "- Risk: Account compromise if successful"
            )
        
        elif 'dns' in cat_lower and 'tunnel' in cat_lower:
            return (
                "### DNS Tunneling Detected\n\n"
                "Covert data channel using DNS protocol.\n\n"
                "- Technique: Data hidden in DNS queries\n"
                "- Purpose: Bypass security controls\n"
                "- Use Cases: Exfiltration, C2 communication\n"
                "- Why DNS: Usually allowed through firewalls"
            )
        
        # Default
        return (
            "### Security Anomaly Detected\n\n"
            f"Suspicious activity from {src_ip} to {dst_ip}.\n\n"
            f"- Category: {category}\n"
            f"- Protocol: {protocol}\n"
            f"- Risk Score: {risk_score*100:.0f}%\n"
            "- Detection: AI behavioral analysis"
        )
    
    def _identify_service(self, port: int) -> str:
        """Identify service by port."""
        services = {
            22: "SSH", 23: "Telnet", 21: "FTP", 25: "SMTP",
            53: "DNS", 80: "HTTP", 443: "HTTPS", 3306: "MySQL",
            5432: "PostgreSQL", 3389: "RDP", 5900: "VNC",
            1433: "MSSQL", 27017: "MongoDB", 6379: "Redis",
        }
        return services.get(port, f"Port {port}")
    
    def _explain_generic_anomaly(self, src_ip: str, dst_ip: str, risk_score: float, intel: IPIntelligence, voting_details: Dict) -> str:
        """Explain generic anomalies."""
        
        context = ""
        if intel.is_vpn:
            context = "Source is using a VPN service, which may indicate intent to hide identity."
        elif intel.is_datacenter:
            context = "Source is from cloud infrastructure, commonly used for automated attacks."
        elif intel.is_scanner:
            context = f"Source is a known scanner service ({intel.organization})."
        else:
            context = "Source has no specific threat indicators but behavior is anomalous."
        
        return (
            "### Anomalous Network Activity\n\n"
            f"Unusual traffic pattern from {src_ip}.\n\n"
            f"- Risk Score: {risk_score*100:.0f}%\n"
            f"- Assessment: {context}\n"
            "- Detection: Multiple AI models flagged this traffic"
        )
    
    def _explain_detection_models(self, voting_details: Dict, risk_score: float) -> str:
        """Explain detection method."""

        if not isinstance(voting_details, dict) or not voting_details:
            return "- Ensemble Detection: Multiple models agreed on threat classification"

        lines = []
        anomaly_votes = voting_details.get("anomaly_votes")
        total_votes = voting_details.get("total_votes")
        final_risk = voting_details.get("final_risk_score", risk_score)
        voting_models = voting_details.get("voting_models", []) or []
        dissenting_models = voting_details.get("dissenting_models", []) or []

        if isinstance(anomaly_votes, (int, float)) and isinstance(total_votes, (int, float)):
            lines.append(f"- Ensemble Agreement: {int(anomaly_votes)}/{int(total_votes)} models flagged anomaly")

        try:
            lines.append(f"- Final Risk Score: {float(final_risk)*100:.0f}%")
        except (TypeError, ValueError):
            lines.append(f"- Final Risk Score: {risk_score*100:.0f}%")

        if voting_models:
            formatted_models = ", ".join(str(model).replace("_", " ").title() for model in voting_models)
            lines.append(f"- Triggered Models: {formatted_models}")

        if dissenting_models:
            formatted_dissent = ", ".join(str(model).replace("_", " ").title() for model in dissenting_models)
            lines.append(f"- Dissenting Models: {formatted_dissent}")

        return "\n".join(lines)
    
    def _make_detailed_recommendation(self, risk_score: float, threat_category: str, intel: IPIntelligence) -> str:
        """Generate actionable recommendations."""
        
        actions = []
        
        if risk_score >= 0.9:
            actions.append("- IMMEDIATE: Block source IP at firewall")
            actions.append("- Isolate affected internal systems")
            actions.append("- Initiate incident response procedure")
        elif risk_score >= 0.75:
            actions.append("- Block source IP for 24 hours")
            actions.append("- Review logs for related activity")
            actions.append("- Monitor affected endpoints")
        elif risk_score >= 0.5:
            actions.append("- Add to watchlist for monitoring")
            actions.append("- Investigate source reputation")
            actions.append("- Review if traffic is expected")
        else:
            actions.append("- Log for analysis")
            actions.append("- Monitor for pattern escalation")
        
        if intel.is_known_attacker or intel.is_botnet:
            actions.insert(0, "- PRIORITY: Known malicious infrastructure - block permanently")
        
        return "\n".join(actions)


# Singleton instance
_explainer = None

def get_explainer() -> SimpleExplainer:
    """Get the singleton explainer instance."""
    global _explainer
    if _explainer is None:
        _explainer = SimpleExplainer()
    return _explainer

def explain_threat(**kwargs) -> str:
    """Convenience function to explain a threat."""
    return get_explainer().explain_threat(**kwargs)
