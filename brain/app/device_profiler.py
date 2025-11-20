import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pickle
import os
import json
from typing import Dict, List, Tuple, Optional

class DeviceProfile:
    """Individual behavior profile for a single device."""

    def __init__(self, hostname: str, contamination=0.1):
        self.hostname = hostname
        self.model = IsolationForest(
            contamination=contamination,
            n_estimators=100,
            max_samples='auto',
            random_state=42,
            n_jobs=-1
        )
        self.scaler = StandardScaler()
        self.is_trained = False
        self.flow_count = 0
        self.feature_names = []

    def train(self, features: np.ndarray, feature_names: List[str]):
        """Train device-specific baseline."""
        if len(features) == 0:
            raise ValueError("Cannot train on empty dataset")

        features_scaled = self.scaler.fit_transform(features)
        self.model.fit(features_scaled)
        self.is_trained = True
        self.flow_count = len(features)
        self.feature_names = feature_names

        return {"status": "trained", "n_samples": len(features)}

    def predict(self, features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Predict anomalies for this device."""
        if not self.is_trained:
            raise ValueError("Profile must be trained first")

        features_scaled = self.scaler.transform(features)
        predictions = self.model.predict(features_scaled)
        scores = self.model.score_samples(features_scaled)
        risk_scores = self._normalize_scores(scores)

        return predictions, risk_scores

    def _normalize_scores(self, scores: np.ndarray) -> np.ndarray:
        """Convert to 0-1 risk scores."""
        min_score = scores.min()
        max_score = scores.max()

        if max_score == min_score:
            return np.zeros_like(scores)

        normalized = (scores - min_score) / (max_score - min_score)
        return 1.0 - normalized

class DeviceProfiler:
    """Manages per-device behavior profiles."""

    def __init__(self, save_dir: str = "/app/models/profiles"):
        self.save_dir = save_dir
        self.profiles: Dict[str, DeviceProfile] = {}
        os.makedirs(save_dir, exist_ok=True)

    def get_or_create_profile(self, hostname: str) -> DeviceProfile:
        """Get existing profile or create new one."""
        if hostname not in self.profiles:
            self.profiles[hostname] = DeviceProfile(hostname)
            self.load_profile(hostname)
        return self.profiles[hostname]

    def train_device(self, hostname: str, features: np.ndarray, feature_names: List[str]):
        """Train profile for specific device."""
        profile = self.get_or_create_profile(hostname)
        result = profile.train(features, feature_names)
        self.save_profile(hostname)
        return result

    def predict_device(self, hostname: str, features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """Predict anomalies for specific device."""
        profile = self.get_or_create_profile(hostname)
        if not profile.is_trained:
            raise ValueError(f"Profile for {hostname} not trained yet")
        return profile.predict(features)

    def save_profile(self, hostname: str):
        """Save device profile to disk."""
        if hostname not in self.profiles:
            return

        profile = self.profiles[hostname]
        if not profile.is_trained:
            return

        profile_path = os.path.join(self.save_dir, f"{hostname}.pkl")
        profile_data = {
            'model': profile.model,
            'scaler': profile.scaler,
            'feature_names': profile.feature_names,
            'flow_count': profile.flow_count,
            'is_trained': profile.is_trained
        }

        with open(profile_path, 'wb') as f:
            pickle.dump(profile_data, f)

    def load_profile(self, hostname: str) -> bool:
        """Load device profile from disk."""
        profile_path = os.path.join(self.save_dir, f"{hostname}.pkl")

        if not os.path.exists(profile_path):
            return False

        try:
            with open(profile_path, 'rb') as f:
                profile_data = pickle.load(f)

            if hostname not in self.profiles:
                self.profiles[hostname] = DeviceProfile(hostname)

            profile = self.profiles[hostname]
            profile.model = profile_data['model']
            profile.scaler = profile_data['scaler']
            profile.feature_names = profile_data['feature_names']
            profile.flow_count = profile_data['flow_count']
            profile.is_trained = profile_data['is_trained']

            return True
        except Exception as e:
            return False

    def get_profile_status(self, hostname: str) -> Dict:
        """Get training status for device."""
        if hostname not in self.profiles:
            return {"exists": False, "trained": False}

        profile = self.profiles[hostname]
        return {
            "exists": True,
            "trained": profile.is_trained,
            "flow_count": profile.flow_count,
            "features": len(profile.feature_names)
        }

    def list_profiles(self) -> List[Dict]:
        """List all device profiles."""
        profiles = []
        for hostname, profile in self.profiles.items():
            profiles.append({
                "hostname": hostname,
                "trained": profile.is_trained,
                "flow_count": profile.flow_count
            })
        return profiles
