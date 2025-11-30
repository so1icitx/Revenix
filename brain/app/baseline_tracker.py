"""
Device baseline tracking for behavioral analysis.
Stores per-device statistics to detect deviations from normal patterns.
"""
import json
import os
from typing import Dict, List, Optional
from collections import defaultdict
import numpy as np


class DeviceBaseline:
    """Tracks behavioral baseline for a single device."""

    def __init__(self, hostname: str):
        self.hostname = hostname
        self.flow_count = 0

        # Traffic statistics
        self.avg_bytes_per_flow = 0.0
        self.avg_packets_per_flow = 0.0
        self.avg_duration = 0.0
        self.avg_bytes_per_sec = 0.0

        # Connection patterns
        self.common_destinations = {}  # dst_ip -> count
        self.common_ports = {}  # dst_port -> count
        self.protocol_distribution = {}  # protocol -> count

        # Temporal patterns
        self.peak_hours = set()  # Hours with most traffic
        self.flow_rate_history = []  # Recent flow rates

        # Statistical measures
        self.bytes_std_dev = 0.0
        self.packets_std_dev = 0.0

    def update(self, flows: List[Dict]):
        """Update baseline with new flows."""
        if not flows:
            return

        total_bytes = sum(f.get('bytes', 0) for f in flows)
        total_packets = sum(f.get('packets', 0) for f in flows)
        total_duration = sum(f.get('end_ts', 0) - f.get('start_ts', 0) for f in flows)

        alpha = 0.3  # Exponential moving average weight
        self.avg_bytes_per_flow = (
            alpha * (total_bytes / len(flows)) + (1 - alpha) * self.avg_bytes_per_flow
        )
        self.avg_packets_per_flow = (
            alpha * (total_packets / len(flows)) + (1 - alpha) * self.avg_packets_per_flow
        )
        self.avg_duration = (
            alpha * (total_duration / len(flows)) + (1 - alpha) * self.avg_duration
        )

        if total_duration > 0:
            self.avg_bytes_per_sec = (
                alpha * (total_bytes / total_duration) + (1 - alpha) * self.avg_bytes_per_sec
            )

        for flow in flows:
            dst_ip = flow.get('dst_ip', '')
            dst_port = flow.get('dst_port', 0)
            protocol = flow.get('protocol', 'unknown')

            if dst_ip:
                self.common_destinations[dst_ip] = self.common_destinations.get(dst_ip, 0) + 1
            if dst_port:
                self.common_ports[dst_port] = self.common_ports.get(dst_port, 0) + 1
            self.protocol_distribution[protocol] = self.protocol_distribution.get(protocol, 0) + 1

        if len(self.common_destinations) > 100:
            sorted_dests = sorted(self.common_destinations.items(), key=lambda x: x[1], reverse=True)
            self.common_destinations = dict(sorted_dests[:100])

        if len(self.common_ports) > 50:
            sorted_ports = sorted(self.common_ports.items(), key=lambda x: x[1], reverse=True)
            self.common_ports = dict(sorted_ports[:50])

        bytes_list = [f.get('bytes', 0) for f in flows]
        packets_list = [f.get('packets', 0) for f in flows]

        if len(bytes_list) > 1:
            self.bytes_std_dev = float(np.std(bytes_list))
            self.packets_std_dev = float(np.std(packets_list))

        self.flow_count += len(flows)

    def get_deviation_score(self, flow: Dict) -> float:
        """
        Calculate how much a flow deviates from this device's baseline.
        Returns 0-1 score where higher = more deviation.
        """
        if self.flow_count < 10:
            return 0.0  # Not enough baseline data

        deviations = []

        flow_bytes = flow.get('bytes', 0)
        if self.avg_bytes_per_flow > 0:
            bytes_ratio = flow_bytes / self.avg_bytes_per_flow
            deviations.append(abs(1.0 - bytes_ratio))

        flow_packets = flow.get('packets', 0)
        if self.avg_packets_per_flow > 0:
            packets_ratio = flow_packets / self.avg_packets_per_flow
            deviations.append(abs(1.0 - packets_ratio))

        dst_ip = flow.get('dst_ip', '')
        if dst_ip and dst_ip not in self.common_destinations:
            deviations.append(0.5)  # Penalty for unknown destination

        dst_port = flow.get('dst_port', 0)
        if dst_port and dst_port not in self.common_ports:
            deviations.append(0.3)  # Penalty for unusual port

        return min(np.mean(deviations) if deviations else 0.0, 1.0)

    def is_destination_known(self, dst_ip: str) -> bool:
        """Check if destination IP is commonly contacted."""
        return dst_ip in self.common_destinations

    def get_destination_frequency(self, dst_ip: str) -> int:
        """Get connection count to destination."""
        return self.common_destinations.get(dst_ip, 0)

    def to_dict(self) -> Dict:
        """Serialize baseline to dictionary."""
        return {
            'hostname': self.hostname,
            'flow_count': self.flow_count,
            'avg_bytes_per_flow': self.avg_bytes_per_flow,
            'avg_packets_per_flow': self.avg_packets_per_flow,
            'avg_duration': self.avg_duration,
            'avg_bytes_per_sec': self.avg_bytes_per_sec,
            'common_destinations': self.common_destinations,
            'common_ports': self.common_ports,
            'protocol_distribution': self.protocol_distribution,
            'bytes_std_dev': self.bytes_std_dev,
            'packets_std_dev': self.packets_std_dev,
        }


class BaselineTracker:
    """Manages baselines for all devices."""

    def __init__(self, save_dir: str = "/app/models/baselines"):
        self.save_dir = save_dir
        self.baselines: Dict[str, DeviceBaseline] = {}
        os.makedirs(save_dir, exist_ok=True)
        self.load_all()

    def get_or_create_baseline(self, hostname: str) -> DeviceBaseline:
        """Get existing baseline or create new one."""
        if hostname not in self.baselines:
            self.baselines[hostname] = DeviceBaseline(hostname)
            self.load_baseline(hostname)
        return self.baselines[hostname]

    def update_baseline(self, hostname: str, flows: List[Dict]):
        """Update device baseline with new flows."""
        baseline = self.get_or_create_baseline(hostname)
        baseline.update(flows)
        self.save_baseline(hostname)

    def get_deviation_score(self, hostname: str, flow: Dict) -> float:
        """Calculate deviation score for a flow."""
        baseline = self.get_or_create_baseline(hostname)
        return baseline.get_deviation_score(flow)

    def save_baseline(self, hostname: str):
        """Save device baseline to disk."""
        if hostname not in self.baselines:
            return

        baseline = self.baselines[hostname]
        baseline_path = os.path.join(self.save_dir, f"{hostname}.json")

        try:
            with open(baseline_path, 'w') as f:
                json.dump(baseline.to_dict(), f, indent=2)
        except Exception as e:
            print(f"[BaselineTracker] Failed to save baseline for {hostname}: {e}")

    def load_baseline(self, hostname: str) -> bool:
        """Load device baseline from disk."""
        baseline_path = os.path.join(self.save_dir, f"{hostname}.json")

        if not os.path.exists(baseline_path):
            return False

        try:
            with open(baseline_path, 'r') as f:
                data = json.load(f)

            if hostname not in self.baselines:
                self.baselines[hostname] = DeviceBaseline(hostname)

            baseline = self.baselines[hostname]
            baseline.flow_count = data.get('flow_count', 0)
            baseline.avg_bytes_per_flow = data.get('avg_bytes_per_flow', 0.0)
            baseline.avg_packets_per_flow = data.get('avg_packets_per_flow', 0.0)
            baseline.avg_duration = data.get('avg_duration', 0.0)
            baseline.avg_bytes_per_sec = data.get('avg_bytes_per_sec', 0.0)
            baseline.common_destinations = data.get('common_destinations', {})
            baseline.common_ports = data.get('common_ports', {})
            baseline.protocol_distribution = data.get('protocol_distribution', {})
            baseline.bytes_std_dev = data.get('bytes_std_dev', 0.0)
            baseline.packets_std_dev = data.get('packets_std_dev', 0.0)

            return True
        except Exception as e:
            print(f"[BaselineTracker] Failed to load baseline for {hostname}: {e}")
            return False

    def load_all(self):
        """Load all saved baselines."""
        if not os.path.exists(self.save_dir):
            return

        for filename in os.listdir(self.save_dir):
            if filename.endswith('.json'):
                hostname = filename[:-5]  # Remove .json
                self.load_baseline(hostname)

    def get_baseline_info(self, hostname: str) -> Optional[Dict]:
        """Get baseline statistics for a device."""
        if hostname not in self.baselines:
            return None

        return self.baselines[hostname].to_dict()
