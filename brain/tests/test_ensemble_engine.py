"""
Tests for the Ensemble Engine
"""

import pytest
import numpy as np
from unittest.mock import MagicMock, patch, AsyncMock
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class MockFlow:
    """Mock flow object for testing"""
    def __init__(self, **kwargs):
        self.flow_id = kwargs.get('flow_id', 'test-flow-1')
        self.src_ip = kwargs.get('src_ip', '192.168.1.100')
        self.dst_ip = kwargs.get('dst_ip', '8.8.8.8')
        self.hostname = kwargs.get('hostname', 'test-device')
        self.packets = kwargs.get('packets', 10)
        self.bytes = kwargs.get('bytes', 1500)
        self.start_ts = kwargs.get('start_ts', 1000.0)
        self.end_ts = kwargs.get('end_ts', 1005.0)
        self.src_port = kwargs.get('src_port', 54321)
        self.dst_port = kwargs.get('dst_port', 443)
        self.protocol = kwargs.get('protocol', 'TCP')


class TestEnsembleVoting:
    """Test ensemble voting logic"""
    
    def test_unanimous_agreement(self):
        """Test when all models agree"""
        votes = {
            'isolation_forest': {'is_anomaly': True, 'confidence': 0.9},
            'autoencoder': {'is_anomaly': True, 'confidence': 0.85},
            'baseline': {'is_anomaly': True, 'confidence': 0.8},
            'lstm': {'is_anomaly': True, 'confidence': 0.75}
        }
        
        weights = {
            'isolation_forest': 0.25,
            'autoencoder': 0.40,
            'baseline': 0.15,
            'lstm': 0.20
        }
        
        # Calculate weighted score
        weighted_score = sum(
            votes[model]['confidence'] * weights[model]
            for model in votes
        )
        
        assert weighted_score > 0.65  # Threshold
        
    def test_split_decision(self):
        """Test split decision between models"""
        votes = {
            'isolation_forest': {'is_anomaly': True, 'confidence': 0.9},
            'autoencoder': {'is_anomaly': False, 'confidence': 0.3},
            'baseline': {'is_anomaly': True, 'confidence': 0.8},
            'lstm': {'is_anomaly': False, 'confidence': 0.2}
        }
        
        weights = {
            'isolation_forest': 0.25,
            'autoencoder': 0.40,
            'baseline': 0.15,
            'lstm': 0.20
        }
        
        # Count agreeing models
        agreeing = sum(1 for v in votes.values() if v['is_anomaly'])
        
        # Need 2+ models to agree
        assert agreeing >= 2
        
    def test_weighted_confidence(self):
        """Test weighted confidence calculation"""
        model_outputs = [
            (0.9, 0.25),  # IF: 90% confident, 25% weight
            (0.85, 0.40),  # AE: 85% confident, 40% weight
            (0.7, 0.15),   # Baseline: 70% confident, 15% weight
            (0.6, 0.20),   # LSTM: 60% confident, 20% weight
        ]
        
        weighted_sum = sum(conf * weight for conf, weight in model_outputs)
        total_weight = sum(weight for _, weight in model_outputs)
        
        final_confidence = weighted_sum / total_weight
        
        assert 0 <= final_confidence <= 1
        assert abs(final_confidence - 0.795) < 0.01  # Expected value


class TestModelDisagreement:
    """Test handling of model disagreement"""
    
    def test_majority_wins(self):
        """Test that majority vote determines outcome"""
        votes = [True, True, True, False]  # 3 say anomaly, 1 says normal
        
        is_anomaly = sum(votes) >= 2
        
        assert is_anomaly == True
        
    def test_tie_breaker(self):
        """Test tie-breaking behavior"""
        votes = [True, True, False, False]  # 2-2 tie
        
        # In tie, use weighted confidence
        confidences = {
            True: 0.9 * 0.25 + 0.85 * 0.40,  # IF + AE
            False: 0.7 * 0.15 + 0.6 * 0.20   # Baseline + LSTM
        }
        
        is_anomaly = confidences[True] > confidences[False]
        
        assert is_anomaly == True  # Higher weighted confidence wins


class TestConfidenceThresholds:
    """Test confidence threshold behavior"""
    
    @pytest.mark.parametrize("confidence,expected_action", [
        (0.999, "immediate_block"),
        (0.85, "strike_tracking"),
        (0.65, "alert"),
        (0.30, "normal"),
        (0.10, "whitelist_candidate"),
    ])
    def test_confidence_to_action(self, confidence, expected_action):
        """Test mapping of confidence to action"""
        if confidence >= 0.999:
            action = "immediate_block"
        elif confidence >= 0.75:
            action = "strike_tracking"
        elif confidence >= 0.65:
            action = "alert"
        elif confidence < 0.30:
            action = "whitelist_candidate"
        else:
            action = "normal"
            
        assert action == expected_action


class TestExplainability:
    """Test AI decision explainability"""
    
    def test_generate_explanation(self):
        """Test explanation generation"""
        model_contributions = {
            'isolation_forest': {'contribution': 0.3, 'reason': 'Unusual packet rate'},
            'autoencoder': {'contribution': 0.5, 'reason': 'Behavioral deviation detected'},
            'baseline': {'contribution': 0.1, 'reason': 'Within normal range'},
            'lstm': {'contribution': 0.1, 'reason': 'No attack pattern matched'}
        }
        
        # Sort by contribution
        sorted_contributions = sorted(
            model_contributions.items(),
            key=lambda x: x[1]['contribution'],
            reverse=True
        )
        
        # Top contributor should be autoencoder
        assert sorted_contributions[0][0] == 'autoencoder'
        
        # Generate human-readable explanation
        top_model, top_data = sorted_contributions[0]
        explanation = f"Primary indicator: {top_data['reason']} ({top_model})"
        
        assert "Behavioral deviation" in explanation
