"""
Pytest configuration and shared fixtures for Brain tests
"""

import pytest
import numpy as np
import asyncio
from unittest.mock import MagicMock, AsyncMock


@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests"""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def mock_api_client():
    """Mock API client for testing"""
    client = MagicMock()
    client.get_flows = AsyncMock(return_value=[])
    client.post_alert = AsyncMock(return_value={'id': 'alert-1'})
    client.get_config = AsyncMock(return_value={'training_threshold': 500})
    return client


@pytest.fixture
def sample_flow_data():
    """Generate sample flow data for testing"""
    return {
        'flow_id': 'test-flow-1',
        'src_ip': '192.168.1.100',
        'dst_ip': '8.8.8.8',
        'hostname': 'test-device',
        'packets': 10,
        'bytes': 1500,
        'start_ts': 1000.0,
        'end_ts': 1005.0,
        'src_port': 54321,
        'dst_port': 443,
        'protocol': 'TCP'
    }


@pytest.fixture
def normal_traffic_features():
    """Generate normal traffic feature vectors"""
    np.random.seed(42)
    # Simulate normal HTTPS traffic patterns
    return np.array([
        [100, 50, 5.0, 0.2, 10],   # Normal web browsing
        [150, 75, 3.5, 0.1, 15],   # File download
        [80, 40, 2.0, 0.15, 8],    # API call
        [200, 100, 10.0, 0.25, 20], # Video streaming
        [50, 25, 1.0, 0.1, 5],     # Keep-alive
    ])


@pytest.fixture
def anomalous_traffic_features():
    """Generate anomalous traffic feature vectors"""
    return np.array([
        [10000, 5000, 0.1, 0.9, 1000],  # Port scan
        [50, 1, 3600, 0.01, 0.01],       # Slow loris
        [1000000, 500000, 5.0, 0.99, 100000], # DDoS
        [100, 50, 0.001, 0.5, 10000],    # Rapid connection
    ])


@pytest.fixture
def feature_names():
    """Standard feature names"""
    return [
        'bytes_per_packet',
        'packets_per_second',
        'duration',
        'port_entropy',
        'flow_rate'
    ]
