"""
Tests for the Isolation Forest Anomaly Detector
"""

import pytest
import numpy as np
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from app.anomaly_detector import AnomalyDetector


class TestAnomalyDetector:
    """Test suite for AnomalyDetector class"""
    
    @pytest.fixture
    def detector(self):
        """Create a fresh detector for each test"""
        return AnomalyDetector(contamination=0.1)
    
    @pytest.fixture
    def sample_features(self):
        """Generate sample feature data for testing"""
        np.random.seed(42)
        # Normal traffic patterns
        normal_data = np.random.randn(100, 5) * 0.5 + 2
        return normal_data
    
    @pytest.fixture
    def feature_names(self):
        """Sample feature names"""
        return ['bytes_per_packet', 'packets_per_second', 'duration', 'port_entropy', 'flow_rate']

    @pytest.fixture
    def flow_ids(self, sample_features):
        """Flow IDs aligned with sample feature rows"""
        return list(range(len(sample_features)))
    
    def test_init(self, detector):
        """Test detector initialization"""
        assert detector.model is not None
        assert detector.model.contamination == 0.1
        assert detector.is_trained == False
    
    def test_train_success(self, detector, sample_features, feature_names, flow_ids):
        """Test successful model training"""
        result = detector.train(sample_features, feature_names, flow_ids)
        
        assert detector.is_trained == True
        assert detector.model is not None
        assert 'n_samples' in result
        assert result['n_samples'] == 100
    
    def test_train_small_dataset(self, detector, feature_names):
        """Current implementation supports training with small datasets."""
        small_data = np.random.randn(3, 5)
        small_flow_ids = list(range(len(small_data)))
        result = detector.train(small_data, feature_names, small_flow_ids)
        assert result['n_samples'] == 3
    
    def test_predict_before_training(self, detector, sample_features):
        """Test prediction before model is trained"""
        with pytest.raises(ValueError) as excinfo:
            detector.predict(sample_features)
        
        assert "trained" in str(excinfo.value).lower()
    
    def test_predict_after_training(self, detector, sample_features, feature_names, flow_ids):
        """Test prediction after successful training"""
        detector.train(sample_features, feature_names, flow_ids)
        
        # Generate test data
        test_data = np.random.randn(10, 5) * 0.5 + 2
        
        predictions, risk_scores = detector.predict(test_data)
        
        assert len(predictions) == 10
        assert len(risk_scores) == 10
        assert all(p in [-1, 1] for p in predictions)
        assert all(0 <= s <= 1 for s in risk_scores)
    
    def test_detect_anomalies(self, detector, sample_features, feature_names, flow_ids):
        """Test anomaly detection with clear outliers"""
        detector.train(sample_features, feature_names, flow_ids)
        
        # Score a mixed batch so normalization has a meaningful range.
        np.random.seed(123)
        normal_batch = np.random.randn(50, 5) * 0.5 + 2
        anomaly = np.array([[100, 100, 100, 100, 100]])
        mixed_batch = np.vstack([normal_batch, anomaly])

        _, risk_scores = detector.predict(mixed_batch)

        # The synthetic outlier should rank in the high-risk tail.
        anomaly_score = risk_scores[-1]
        normal_tail_p90 = np.percentile(risk_scores[:-1], 90)
        assert anomaly_score >= normal_tail_p90
    
    def test_feature_names_stored(self, detector, sample_features, feature_names, flow_ids):
        """Test that feature names are stored after training"""
        detector.train(sample_features, feature_names, flow_ids)
        
        assert detector.feature_names == feature_names
    
    def test_model_persistence(self, detector, sample_features, feature_names, flow_ids, tmp_path):
        """Test model save and load"""
        detector.train(sample_features, feature_names, flow_ids)
        
        # Save model
        model_path = tmp_path / "model.joblib"
        detector.save_model(str(model_path))
        
        # Load into new detector
        new_detector = AnomalyDetector()
        new_detector.load_model(str(model_path))
        
        assert new_detector.is_trained == True
        
        # Predictions should be identical
        test_data = np.random.randn(5, 5)
        pred1, scores1 = detector.predict(test_data)
        pred2, scores2 = new_detector.predict(test_data)
        
        np.testing.assert_array_equal(pred1, pred2)
        np.testing.assert_array_almost_equal(scores1, scores2)


class TestAnomalyDetectorEdgeCases:
    """Edge case tests for AnomalyDetector"""
    
    def test_empty_input(self):
        """Test handling of empty input"""
        detector = AnomalyDetector()
        
        with pytest.raises(ValueError):
            detector.train(np.array([]), [], [])
    
    def test_mismatched_features(self):
        """Test handling of mismatched feature dimensions"""
        detector = AnomalyDetector()
        data = np.random.randn(100, 5)
        flow_ids = list(range(len(data)))
        
        # Train with 5 features
        detector.train(data, ['f1', 'f2', 'f3', 'f4', 'f5'], flow_ids)
        
        # Try to predict with 3 features
        test_data = np.random.randn(10, 3)
        
        with pytest.raises(ValueError):
            detector.predict(test_data)
    
    def test_nan_handling(self):
        """Test handling of NaN values"""
        detector = AnomalyDetector()
        data = np.random.randn(100, 5)
        data[0, 0] = np.nan
        flow_ids = list(range(len(data)))
        
        # Accept either path depending on sklearn version: reject NaN or handle it.
        try:
            result = detector.train(data, ['f1', 'f2', 'f3', 'f4', 'f5'], flow_ids)
            assert detector.is_trained is True
            assert result['status'] == 'trained'
        except ValueError:
            pass


class TestAnomalyDetectorPerformance:
    """Performance tests for AnomalyDetector"""
    
    def test_large_dataset_training(self):
        """Test training with large dataset"""
        detector = AnomalyDetector()
        large_data = np.random.randn(10000, 20)
        feature_names = [f'feature_{i}' for i in range(20)]
        flow_ids = list(range(len(large_data)))
        
        result = detector.train(large_data, feature_names, flow_ids)
        
        assert detector.is_trained == True
        assert result['n_samples'] == 10000
    
    def test_batch_prediction_performance(self):
        """Test batch prediction performance"""
        detector = AnomalyDetector()
        train_data = np.random.randn(1000, 10)
        feature_names = [f'feature_{i}' for i in range(10)]
        flow_ids = list(range(len(train_data)))
        
        detector.train(train_data, feature_names, flow_ids)
        
        # Large batch prediction
        test_data = np.random.randn(5000, 10)
        predictions, scores = detector.predict(test_data)
        
        assert len(predictions) == 5000
        assert len(scores) == 5000
