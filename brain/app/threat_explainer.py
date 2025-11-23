import numpy as np
from typing import Dict, List, Optional, Any
import logging

logger = logging.getLogger(__name__)

class ThreatExplainer:
    """
    Generates detailed, human-readable explanations for detected threats.
    Analyzes flow features and patterns to provide verbose threat context.
    """

    def __init__(self):
        self.explanation_templates = self._load_explanation_templates()

    def _load_explanation_templates(self) -> Dict[str, str]:
        """Load explanation templates for different threat patterns."""
        return {
            "port_scan": "This device is systematically probing multiple network ports ({port_count} ports targeted), which is characteristic of reconnaissance activity used by attackers to discover vulnerable services before launching an attack.",

            "high_packet_rate": "Detected an unusually high packet transmission rate of {packets_per_sec} packets/second, which is {factor}x higher than this device's normal baseline. This could indicate automated scanning, denial-of-service attack participation, or malware communication.",

            "large_packets": "Traffic contains abnormally large packets averaging {bytes_per_packet} bytes per packet, significantly exceeding typical sizes for {protocol} protocol. Large packets can be used for data exfiltration or buffer overflow exploit attempts.",

            "random_ports": "Connection attempts use highly randomized source ports (entropy: {entropy}), suggesting automated tool usage rather than legitimate application behavior. This pattern is commonly seen in botnet activity and network scanning tools.",

            "unusual_protocol": "Device is using {protocol} protocol in an unusual manner for its established behavior profile. The traffic pattern deviates significantly from previously observed legitimate {protocol} usage by this device.",

            "suspicious_timing": "Traffic exhibits suspicious timing patterns with connections occurring at irregular intervals inconsistent with human behavior or normal application schedules. This may indicate automated malicious activity.",

            "data_exfiltration": "Detected sustained outbound data transfer of {bytes_transferred} bytes to external IP {dst_ip}, which significantly exceeds normal communication volume with this destination. This pattern is consistent with data exfiltration or command-and-control communications.",

            "ddos_participant": "Device is generating high-volume network traffic ({packets_per_sec} pps) directed at {dst_ip}, exhibiting patterns consistent with distributed denial-of-service attack participation. The traffic volume and regularity suggest botnet control.",

            "anomalous_destination": "Connection to {dst_ip} is highly unusual for this device. Historical analysis shows no prior communication with this IP address or geographic region, and the connection pattern differs from established behavior.",

            "protocol_anomaly": "The {protocol} traffic exhibits statistical anomalies in packet sizes, timing, and payload characteristics that differ from standard {protocol} implementations. This may indicate protocol tunneling or covert channel usage."
        }

    def explain_threat(
        self,
        flow: Dict[str, Any],
        risk_score: float,
        features: Dict[str, float],
        device_profile_trained: bool = False,
        baseline_comparison: Optional[Dict[str, float]] = None
    ) -> str:
        """
        Generatea a detailed, verbose explanation for why this flow is considered threatening.

        Args:
            flow: The network flow data
            risk_score: AI-calculated risk score (0-1)
            features: Extracted flow features
            device_profile_trained: Whether device has established baseline
            baseline_comparison: Comparison with device's normal behavior

        Returns:
            Detailed multi-sentence explanation of the threat
        """
        explanations = []

        # Device context
        hostname = flow.get('hostname', 'unknown')
        src_ip = flow.get('src_ip', 'unknown')
        dst_ip = flow.get('dst_ip', 'unknown')
        protocol = flow.get('protocol', 'TCP')

        # Start with device-specific context if available
        if device_profile_trained:
            baseline_text = self._explain_baseline_deviation(
                hostname, features, baseline_comparison
            )
            if baseline_text:
                explanations.append(baseline_text)

        # Analyze specific threat patterns
        port_scan_explanation = self._detect_port_scan(features, flow)
        if port_scan_explanation:
            explanations.append(port_scan_explanation)

        packet_rate_explanation = self._analyze_packet_rate(
            features, baseline_comparison
        )
        if packet_rate_explanation:
            explanations.append(packet_rate_explanation)

        packet_size_explanation = self._analyze_packet_size(
            features, protocol
        )
        if packet_size_explanation:
            explanations.append(packet_size_explanation)

        port_randomness_explanation = self._analyze_port_randomness(features)
        if port_randomness_explanation:
            explanations.append(port_randomness_explanation)

        data_volume_explanation = self._analyze_data_volume(
            flow, features, dst_ip
        )
        if data_volume_explanation:
            explanations.append(data_volume_explanation)

        ddos_explanation = self._detect_ddos_pattern(features, dst_ip)
        if ddos_explanation:
            explanations.append(ddos_explanation)

        # Protocol-specific analysis
        protocol_explanation = self._analyze_protocol_behavior(
            protocol, features, flow
        )
        if protocol_explanation:
            explanations.append(protocol_explanation)

        # If no specific patterns detected, provide general anomaly explanation
        if not explanations:
            explanations.append(
                f"AI anomaly detection identified this traffic from {hostname} ({src_ip}) "
                f"to {dst_ip} as suspicious with {risk_score*100:.1f}% confidence. "
                f"The flow exhibits statistical characteristics that significantly deviate "
                f"from established normal behavior patterns for both this specific device "
                f"and the broader network baseline."
            )

        # Add risk assessment summary
        risk_level = self._get_risk_level_description(risk_score)
        summary = (
            f"Threat Assessment: {risk_level} - Risk Score {risk_score*100:.1f}%. "
            f"This traffic pattern warrants immediate investigation and potential mitigation."
        )
        explanations.append(summary)

        return " ".join(explanations)

    def _explain_baseline_deviation(
        self,
        hostname: str,
        features: Dict[str, float],
        baseline_comparison: Optional[Dict[str, float]]
    ) -> str:
        """Explain how this deviates from device's normal behavior."""
        return (
            f"Device '{hostname}' is exhibiting network behavior that significantly "
            f"deviates from its established baseline profile. The AI model trained on "
            f"this device's historical traffic patterns has flagged this activity as "
            f"anomalous, indicating a potential compromise or unauthorized usage."
        )

    def _detect_port_scan(self, features: Dict[str, float], flow: Dict) -> Optional[str]:
        """Detect and explain port scanning behavior."""
        port_range = features.get('port_range', 0)
        unique_ports = features.get('unique_dst_ports', 0)

        if port_range > 10 or unique_ports > 5:
            port_count = max(port_range, unique_ports)
            return self.explanation_templates["port_scan"].format(
                port_count=int(port_count)
            )
        return None

    def _analyze_packet_rate(
        self,
        features: Dict[str, float],
        baseline_comparison: Optional[Dict[str, float]]
    ) -> Optional[str]:
        """Analyze and explain packet rate anomalies."""
        packets_per_sec = features.get('packets_per_sec', 0)

        if packets_per_sec > 100:
            # Calculate factor if baseline available
            baseline_rate = baseline_comparison.get('packets_per_sec', 20) if baseline_comparison else 20
            factor = packets_per_sec / baseline_rate if baseline_rate > 0 else packets_per_sec / 20

            return self.explanation_templates["high_packet_rate"].format(
                packets_per_sec=int(packets_per_sec),
                factor=f"{factor:.1f}"
            )
        return None

    def _analyze_packet_size(
        self,
        features: Dict[str, float],
        protocol: str
    ) -> Optional[str]:
        """Analyze and explain packet size anomalies."""
        bytes_per_packet = features.get('bytes_per_packet', 0)

        # Protocol-specific thresholds
        thresholds = {
            'TCP': 1500,  # MTU size
            'UDP': 1500,
            'ICMP': 100
        }

        threshold = thresholds.get(protocol, 1500)

        if bytes_per_packet > threshold * 2:  # Significantly larger
            return self.explanation_templates["large_packets"].format(
                bytes_per_packet=int(bytes_per_packet),
                protocol=protocol
            )
        return None

    def _analyze_port_randomness(self, features: Dict[str, float]) -> Optional[str]:
        """Analyze source port entropy."""
        src_port_entropy = features.get('src_port_entropy', 0)
        dst_port_entropy = features.get('dst_port_entropy', 0)

        if src_port_entropy > 2.0 or dst_port_entropy > 2.0:
            entropy = max(src_port_entropy, dst_port_entropy)
            return self.explanation_templates["random_ports"].format(
                entropy=f"{entropy:.2f}"
            )
        return None

    def _analyze_data_volume(
        self,
        flow: Dict,
        features: Dict[str, float],
        dst_ip: str
    ) -> Optional[str]:
        """Detect potential data exfiltration."""
        total_bytes = flow.get('bytes', 0)
        duration = features.get('duration', 1)

        # High sustained data transfer
        if total_bytes > 10_000_000 and duration > 60:  # 10MB over 60 seconds
            return self.explanation_templates["data_exfiltration"].format(
                bytes_transferred=f"{total_bytes / 1_000_000:.1f}MB",
                dst_ip=dst_ip
            )
        return None

    def _detect_ddos_pattern(
        self,
        features: Dict[str, float],
        dst_ip: str
    ) -> Optional[str]:
        """Detect DDoS participation patterns."""
        packets_per_sec = features.get('packets_per_sec', 0)
        packet_rate_variance = features.get('packet_rate_variance', 0)

        # High volume, low variance = automated attack
        if packets_per_sec > 200 and packet_rate_variance < 50:
            return self.explanation_templates["ddos_participant"].format(
                packets_per_sec=int(packets_per_sec),
                dst_ip=dst_ip
            )
        return None

    def _analyze_protocol_behavior(
        self,
        protocol: str,
        features: Dict[str, float],
        flow: Dict
    ) -> Optional[str]:
        """Analyze protocol-specific behavioral anomalies."""
        # Check for protocol anomalies based on expected behavior
        bytes_per_packet = features.get('bytes_per_packet', 0)
        packets_per_sec = features.get('packets_per_sec', 0)

        # ICMP should have small packets and low rate
        if protocol == 'ICMP' and (bytes_per_packet > 100 or packets_per_sec > 10):
            return self.explanation_templates["protocol_anomaly"].format(
                protocol=protocol
            )

        # UDP with very high packet rate might be DNS amplification or other attack
        if protocol == 'UDP' and packets_per_sec > 500:
            return self.explanation_templates["protocol_anomaly"].format(
                protocol=protocol
            )

        return None

    def _get_risk_level_description(self, risk_score: float) -> str:
        """Get verbose risk level description."""
        if risk_score >= 0.9:
            return "CRITICAL THREAT DETECTED"
        elif risk_score >= 0.8:
            return "High Risk Activity"
        elif risk_score >= 0.75:
            return "Moderate Risk Detected"
        else:
            return "Suspicious Activity"

    def get_mitigation_recommendations(
        self,
        flow: Dict,
        risk_score: float,
        threat_type: str
    ) -> List[str]:
        """Generate specific mitigation recommendations."""
        recommendations = []

        src_ip = flow.get('src_ip', '')
        dst_ip = flow.get('dst_ip', '')
        hostname = flow.get('hostname', 'unknown')

        if risk_score >= 0.9:
            recommendations.append(
                f"IMMEDIATE ACTION REQUIRED: Isolate device '{hostname}' from the network "
                f"to prevent potential lateral movement or data exfiltration."
            )
            recommendations.append(
                f"Block all traffic from source IP {src_ip} at the perimeter firewall."
            )

        if risk_score >= 0.8:
            recommendations.append(
                f"Implement rate limiting on traffic from {src_ip} to prevent resource exhaustion."
            )
            recommendations.append(
                f"Enable detailed packet capture for {hostname} to gather forensic evidence."
            )

        recommendations.append(
            f"Investigate recent activity from device '{hostname}' including process list, "
            f"network connections, and recently modified files."
        )

        recommendations.append(
            f"Check for indicators of compromise (IoCs) associated with {dst_ip} "
            f"using threat intelligence feeds."
        )

        return recommendations
