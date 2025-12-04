import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
import os
from typing import Dict, List, Tuple

class AnomalyDetector:
    """
    Isolation Forest anomaly detector for network flows.
    Detects unusual patterns that may indicate attacks or threats.
    """

    def __init__(self, contamination=0.05):  # Reduced from 0.1 to 0.05 (expect only 5% anomalies instead of 10%)
        """
        Initialize anomaly detector.

        Args:
            contamination: Expected proportion of anomalies (0.05 = 5%)
        """
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=100,
            max_samples='auto',
            random_state=42,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.feature_names = []

    def train(self, features: np.ndarray, feature_names: List[str]):
        """
        Train the model on normal traffic baseline.

        Args:
            features: 2D array of shape (n_samples, n_features)
            feature_names: List of feature names
        """
        if len(features) == 0:
            raise ValueError("Cannot train on empty dataset")

        # Normalize features
        features_scaled = self.scaler.fit_transform(features)

        # Train Isolation Forest
        self.model.fit(features_scaled)
        self.is_trained = True
        self.feature_names = feature_names

        return {
            "status": "trained",
            "n_samples": len(features),
            "n_features": features.shape[1]
        }

    def predict(self, features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict anomaly scores for flows.

        Args:
            features: 2D array of flow features

        Returns:
            Tuple of (predictions, anomaly_scores)
            - predictions: 1 = normal, -1 = anomaly
            - anomaly_scores: Higher (closer to 0) = more anomalous
        """
        if not self.is_trained:
            raise ValueError("Model must be trained before prediction")

        # Normalize using training scaler
        features_scaled = self.scaler.transform(features)

        # Predict: -1 = anomaly, 1 = normal
        predictions = self.model.predict(features_scaled)

        # Get anomaly scores (lower = more anomalous)
        scores = self.model.score_samples(features_scaled)

        # Convert to risk scores (0-1, higher = more risky)
        # Normalize scores to 0-1 range
        risk_scores = self._normalize_scores(scores)

        return predictions, risk_scores

    def _normalize_scores(self, scores: np.ndarray) -> np.ndarray:
        """
        Convert anomaly scores to risk scores (0-1 range).
        Higher risk score = more suspicious.
        """
        # Isolation Forest scores are negative, lower = more anomalous
        # Convert to 0-1 range where 1 = high risk

        min_score = scores.min()
        max_score = scores.max()

        if max_score == min_score:
            return np.zeros_like(scores)

        # Normalize and invert (so high risk = high score)
        normalized = (scores - min_score) / (max_score - min_score)
        risk_scores = 1.0 - normalized  # Invert so anomalies have high scores

        return risk_scores

    def save_model(self, path: str):
        """Save trained model to disk."""
        if not self.is_trained:
            raise ValueError("Cannot save untrained model")

        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'feature_names': self.feature_names,
            'is_trained': self.is_trained
        }

        with open(path, 'wb') as f:
            pickle.dump(model_data, f)

    def load_model(self, path: str):
        """Load trained model from disk."""
        if not os.path.exists(path):
            raise FileNotFoundError(f"Model file not found: {path}")

        with open(path, 'rb') as f:
            model_data = pickle.load(f)

        self.model = model_data['model']
        self.scaler = model_data['scaler']
        self.feature_names = model_data['feature_names']
        self.is_trained = model_data['is_trained']

        return {"status": "loaded", "n_features": len(self.feature_names)}
