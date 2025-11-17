import numpy as np
from typing import Dict, List
import math

class FlowFeatureExtractor:
    """
    Extracts machine learning features from network flows for anomaly detection.
    Calculates: packets/sec, duration, bytes/packet, entropy, burstiness
    """

    def extract_features(self, flow: Dict) -> Dict[str, float]:
        """
        Extract numeric features from a single flow.

        Args:
            flow: Flow dict with keys: packets, bytes, start_ts, end_ts, src_port, dst_port, protocol

        Returns:
            Dictionary of extracted features ready for ML model
        """
        features = {}

        # Basic metrics
        packets = flow.get('packets', 0)
        total_bytes = flow.get('bytes', 0)
        start_ts = flow.get('start_ts', 0)
        end_ts = flow.get('end_ts', 0)

        # Duration in seconds
        duration = max(end_ts - start_ts, 0.001)  # Avoid division by zero
        features['duration'] = duration

        # Packets per second (flow rate)
        features['packets_per_sec'] = packets / duration if duration > 0 else 0

        # Bytes per packet (payload size)
        features['bytes_per_packet'] = total_bytes / packets if packets > 0 else 0

        # Total bytes
        features['total_bytes'] = total_bytes

        # Total packets
        features['total_packets'] = packets

        # Port features
        src_port = flow.get('src_port', 0)
        dst_port = flow.get('dst_port', 0)
        features['src_port'] = src_port
        features['dst_port'] = dst_port

        # Well-known port flags
        features['is_well_known_port'] = 1 if dst_port < 1024 else 0
        features['is_ephemeral_port'] = 1 if src_port > 49152 else 0

        # Protocol encoding (TCP=6, UDP=17, ICMP=1, etc.)
        protocol = flow.get('protocol', 0)
        if isinstance(protocol, str):
            protocol_map = {'TCP': 6, 'UDP': 17, 'ICMP': 1, 'ICMPV6': 58}
            protocol = protocol_map.get(protocol.upper(), 0)
        features['protocol'] = protocol

        # Entropy calculation (measure of randomness in port usage)
        features['port_entropy'] = self._calculate_port_entropy(src_port, dst_port)

        # Burstiness (variance in packet timing)
        features['burstiness'] = self._calculate_burstiness(packets, duration)

        return features

    def extract_features_batch(self, flows: List[Dict]) -> np.ndarray:
        """
        Extract features from multiple flows and return as numpy array.

        Args:
            flows: List of flow dictionaries

        Returns:
            2D numpy array of shape (n_flows, n_features)
        """
        feature_list = []
        for flow in flows:
            features = self.extract_features(flow)
            feature_list.append(list(features.values()))

        return np.array(feature_list)

    def get_feature_names(self) -> List[str]:
        """Return list of feature names in order."""
        return [
            'duration',
            'packets_per_sec',
            'bytes_per_packet',
            'total_bytes',
            'total_packets',
            'src_port',
            'dst_port',
            'is_well_known_port',
            'is_ephemeral_port',
            'protocol',
            'port_entropy',
            'burstiness'
        ]

    def _calculate_port_entropy(self, src_port: int, dst_port: int) -> float:
        """
        Calculate Shannon entropy of port numbers.
        Higher entropy = more random/suspicious port usage.
        """
        if src_port == 0 and dst_port == 0:
            return 0.0

        # Simple entropy based on port distribution
        ports = [src_port, dst_port]
        port_counts = {}
        for p in ports:
            port_counts[p] = port_counts.get(p, 0) + 1

        entropy = 0.0
        total = len(ports)
        for count in port_counts.values():
            if count > 0:
                p = count / total
                entropy -= p * math.log2(p)

        return entropy

    def _calculate_burstiness(self, packets: int, duration: float) -> float:
        """
        Calculate burstiness metric.
        High burstiness = packets sent in short bursts (potential attack).
        Low burstiness = steady rate (normal traffic).
        """
        if duration == 0 or packets == 0:
            return 0.0

        # Simple burstiness: ratio of packets to duration
        # Higher value = more bursty
        avg_rate = packets / duration

        # Normalize to 0-1 range
        # Assume normal traffic is < 100 packets/sec
        burstiness = min(avg_rate / 100.0, 1.0)

        return burstiness
