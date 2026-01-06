import numpy as np
from sklearn.preprocessing import StandardScaler
import pickle
import os
import json
import hashlib
from typing import Dict, List, Tuple, Optional
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

class SimpleAutoencoder:
    """
    Neural network autoencoder for anomaly detection.
    Learns to reconstruct normal traffic patterns.
    High reconstruction error = anomaly.
    """

    def __init__(self, encoding_dim: int = 8, learning_rate: float = 0.01):
        """
        Initialize autoencoder with simple architecture.

        Args:
            encoding_dim: Size of compressed representation
            learning_rate: Learning rate for training
        """
        self.encoding_dim = encoding_dim
        self.learning_rate = learning_rate
        self.input_dim = None

        # Network weights (will be initialized on first train)
        self.W_encoder = None
        self.b_encoder = None
        self.W_decoder = None
        self.b_decoder = None

        self.is_trained = False
        self.reconstruction_errors = []
        self.threshold = None
        self.threshold_multiplier = 2.0  # Increased from 1.5 to 2.0 for less sensitive autoencoder detection

    def _initialize_weights(self, input_dim: int):
        """Initialize network weights with small random values."""
        self.input_dim = input_dim

        # Xavier initialization
        limit_encoder = np.sqrt(6 / (input_dim + self.encoding_dim))
        self.W_encoder = np.random.uniform(-limit_encoder, limit_encoder,
                                          (input_dim, self.encoding_dim))
        self.b_encoder = np.zeros(self.encoding_dim)

        limit_decoder = np.sqrt(6 / (self.encoding_dim + input_dim))
        self.W_decoder = np.random.uniform(-limit_decoder, limit_decoder,
                                          (self.encoding_dim, input_dim))
        self.b_decoder = np.zeros(input_dim)

    def _sigmoid(self, x):
        """Sigmoid activation function."""
        return 1 / (1 + np.exp(-np.clip(x, -500, 500)))

    def _relu(self, x):
        """ReLU activation function."""
        return np.maximum(0, x)

    def _encode(self, X):
        """Encode input to compressed representation."""
        return self._relu(np.dot(X, self.W_encoder) + self.b_encoder)

    def _decode(self, encoded):
        """Decode compressed representation back to input space."""
        return self._sigmoid(np.dot(encoded, self.W_decoder) + self.b_decoder)

    def _forward(self, X):
        """Forward pass through autoencoder."""
        encoded = self._encode(X)
        decoded = self._decode(encoded)
        return decoded

    def train(self, X: np.ndarray, epochs: int = 50):
        """
        Train autoencoder on normal traffic.

        Args:
            X: Training data (n_samples, n_features) - should be normalized
            epochs: Number of training epochs
        """
        if len(X) < 5:
            logger.warning(f"Insufficient samples for training: {len(X)} < 5")
            return {"status": "insufficient_data", "samples": len(X), "is_trained": False}

        if self.W_encoder is None:
            self._initialize_weights(X.shape[1])

        n_samples = X.shape[0]

        for epoch in range(epochs):
            # Forward pass
            encoded = self._encode(X)
            reconstructed = self._decode(encoded)

            # Calculate reconstruction error (MSE)
            error = reconstructed - X
            mse = np.mean(error ** 2)

            # Backward pass (simplified gradient descent)
            # Decoder gradients
            d_decoder = error / n_samples
            grad_W_decoder = np.dot(encoded.T, d_decoder)
            grad_b_decoder = np.sum(d_decoder, axis=0)

            # Encoder gradients
            d_encoded = np.dot(d_decoder, self.W_decoder.T)
            d_encoded[encoded <= 0] = 0  # ReLU derivative
            grad_W_encoder = np.dot(X.T, d_encoded)
            grad_b_encoder = np.sum(d_encoded, axis=0)

            # Update weights
            self.W_decoder -= self.learning_rate * grad_W_decoder
            self.b_decoder -= self.learning_rate * grad_b_decoder
            self.W_encoder -= self.learning_rate * grad_W_encoder
            self.b_encoder -= self.learning_rate * grad_b_encoder

            if epoch % 10 == 0:
                logger.debug(f"Epoch {epoch}/{epochs}, MSE: {mse:.6f}")

        # Calculate reconstruction errors for training data
        reconstructed = self._forward(X)
        errors = np.mean((X - reconstructed) ** 2, axis=1)
        self.reconstruction_errors = errors.tolist()

        # Set adaptive threshold: mean + (2.0 * std_dev)
        mean_error = np.mean(errors)
        std_error = np.std(errors)
        self.threshold = mean_error + (self.threshold_multiplier * std_error)

        # Explicitly set is_trained flag and verify it's set
        self.is_trained = True

        if not self.is_trained:
            logger.error("❌ CRITICAL BUG: is_trained flag did not get set!")
            self.is_trained = True  # Force set it

        logger.info(f"✅ Autoencoder training COMPLETE: threshold={self.threshold:.6f}, mean_error={mean_error:.6f}, is_trained={self.is_trained}")

        return {
            "status": "trained",
            "threshold": float(self.threshold),
            "mean_error": float(mean_error),
            "std_error": float(std_error),
            "is_trained": self.is_trained  # Explicitly return training status
        }

    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict anomalies based on reconstruction error.

        Args:
            X: Input data (n_samples, n_features) - should be normalized

        Returns:
            Tuple of (predictions, risk_scores)
            - predictions: 1 = normal, -1 = anomaly
            - risk_scores: 0-1 normalized reconstruction errors
        """
        if not self.is_trained:
            raise ValueError("Autoencoder must be trained before prediction")

        # Reconstruct inputs
        reconstructed = self._forward(X)

        # Calculate reconstruction errors (MSE per sample)
        errors = np.mean((X - reconstructed) ** 2, axis=1)

        # Classify as anomaly if error > threshold
        predictions = np.where(errors > self.threshold, -1, 1)

        # Normalize errors to 0-1 risk scores
        risk_scores = self._normalize_errors(errors)

        return predictions, risk_scores

    def _normalize_errors(self, errors: np.ndarray) -> np.ndarray:
        """
        Normalize reconstruction errors to 0-1 risk scores.
        Uses threshold as reference point.
        """
        if self.threshold is None or self.threshold == 0:
            return np.zeros_like(errors)

        risk_scores = errors / (self.threshold * 1.5)  # More lenient scaling
        risk_scores = np.clip(risk_scores, 0, 1)

        return risk_scores

    def update_threshold(self, recent_errors: List[float]):
        """
        Adaptively update threshold based on recent errors.
        Allows model to adjust to changing network patterns.
        """
        if len(recent_errors) < 10:
            return

        # Combine with historical errors
        all_errors = self.reconstruction_errors[-100:] + recent_errors

        mean_error = np.mean(all_errors)
        std_error = np.std(all_errors)

        # Update threshold adaptively
        new_threshold = mean_error + (self.threshold_multiplier * std_error)

        # Smooth threshold changes
        alpha = 0.3
        self.threshold = alpha * new_threshold + (1 - alpha) * self.threshold

        # Keep recent errors for future updates
        self.reconstruction_errors = all_errors[-200:]

        logger.debug(f"Updated threshold: {self.threshold:.6f}")


class AutoencoderDetector:
    """
    Per-device autoencoder anomaly detector with model caching and versioning.
    """

    def __init__(self, save_dir: str = "/app/models/autoencoders"):
        self.save_dir = save_dir
        self.device_models: Dict[str, SimpleAutoencoder] = {}
        self.device_scalers: Dict[str, StandardScaler] = {}
        self.device_training_meta: Dict[str, Dict] = {}
        self.model_versions: Dict[str, int] = {}
        self.model_checksums: Dict[str, str] = {}
        os.makedirs(save_dir, exist_ok=True)
        self._load_all_cached_models()

    def _load_all_cached_models(self):
        """Load all cached models from disk on startup."""
        try:
            devices = [f.replace('_autoencoder.pkl', '')
                      for f in os.listdir(self.save_dir)
                      if f.endswith('_autoencoder.pkl')]

            for device in devices:
                if self.load_device_model(device):
                    logger.info(f"[Autoencoder] Loaded cached model for {device}")
        except Exception as e:
            logger.error(f"[Autoencoder] Error loading cached models: {e}")

    def _calculate_model_checksum(self, hostname: str) -> str:
        """Calculate checksum of model weights for versioning."""
        if hostname not in self.device_models:
            return ""

        model = self.device_models[hostname]

        # Combine all weights into single array
        weights = []
        if model.W_encoder is not None:
            weights.extend([
                model.W_encoder.tobytes(),
                model.b_encoder.tobytes(),
                model.W_decoder.tobytes(),
                model.b_decoder.tobytes()
            ])

        # Calculate SHA256 hash
        hasher = hashlib.sha256()
        for w in weights:
            hasher.update(w)

        return hasher.hexdigest()[:16]

    def _save_training_metadata(self, hostname: str):
        """Save training metadata for tracking model versions and performance."""
        if hostname not in self.device_training_meta:
            return

        meta_path = os.path.join(self.save_dir, f"{hostname}_meta.json")

        try:
            metadata = {
                **self.device_training_meta[hostname],
                'version': self.model_versions.get(hostname, 1),
                'checksum': self.model_checksums.get(hostname, ''),
                'updated_at': datetime.now().isoformat()
            }

            with open(meta_path, 'w') as f:
                json.dump(metadata, f, indent=2)

        except Exception as e:
            logger.error(f"Failed to save metadata for {hostname}: {e}")

    def _load_training_metadata(self, hostname: str) -> bool:
        """Load training metadata from disk."""
        meta_path = os.path.join(self.save_dir, f"{hostname}_meta.json")

        if not os.path.exists(meta_path):
            return False

        try:
            with open(meta_path, 'r') as f:
                metadata = json.load(f)

            self.device_training_meta[hostname] = metadata
            self.model_versions[hostname] = metadata.get('version', 1)
            self.model_checksums[hostname] = metadata.get('checksum', '')

            return True
        except Exception as e:
            logger.error(f"Failed to load metadata for {hostname}: {e}")
            return False

    def train_device(self, hostname: str, features: np.ndarray,
                    epochs: int = 50, current_flow_count: int = 0, training_threshold: int = 500) -> Dict:
        """
        Train autoencoder for specific device with caching and versioning.
        
        Args:
            hostname: Device hostname
            features: Feature matrix for training
            epochs: Number of training epochs
            current_flow_count: Current total flow count for this device from AutoLearner
        """
        if len(features) < 5:
            logger.warning(f"Autoencoder training skipped for {hostname}: only {len(features)} samples (need 5+)")
            return {"status": "insufficient_data", "samples": len(features), "is_trained": False}

        # Check if this is initial training or retraining
        is_initial_training = hostname not in self.device_training_meta or not self.device_training_meta[hostname].get('first_trained')
        
        if is_initial_training:
            # Initial training: use configurable threshold
            if current_flow_count < training_threshold:
                logger.debug(f"[Autoencoder] Skipping initial training for {hostname}: {current_flow_count}/{training_threshold} flows (need {training_threshold} for initial training)")
                return {
                    "status": "skipped_initial_training",
                    "reason": "insufficient_data",
                    "current_flow_count": current_flow_count,
                    "required": training_threshold,
                    "is_trained": False
                }
        else:
            # Retraining: use configurable threshold for new flows since last training
            meta = self.device_training_meta[hostname]
            last_trained_count = meta.get('last_trained_flow_count', 0)
            flows_since_training = current_flow_count - last_trained_count

            if flows_since_training < training_threshold:
                logger.debug(f"[Autoencoder] Skipping retrain for {hostname}: {flows_since_training}/{training_threshold} new flows since last training")
                return {
                    "status": "skipped_retraining",
                    "reason": "insufficient_new_data",
                    "flows_since_training": flows_since_training,
                    "is_trained": self.device_models[hostname].is_trained if hostname in self.device_models else False
                }

        # Initialize or get existing model
        if hostname not in self.device_models:
            self.device_models[hostname] = SimpleAutoencoder(
                encoding_dim=min(8, features.shape[1] // 2)
            )
            self.device_scalers[hostname] = StandardScaler()
            self.device_training_meta[hostname] = {
                'first_trained': None,
                'last_trained': None,
                'flows_since_training': 0,
                'training_count': 0
            }
            self.model_versions[hostname] = 0

        prev_checksum = self.model_checksums.get(hostname, '')

        # Normalize features
        features_scaled = self.device_scalers[hostname].fit_transform(features)

        is_retraining = self.device_training_meta[hostname].get('training_count', 0) > 0
        actual_epochs = max(20, epochs // 2) if is_retraining else epochs

        # Train autoencoder
        logger.info(f"[Autoencoder] {'Retraining' if is_retraining else 'Training'} {hostname} with {len(features)} samples ({actual_epochs} epochs)...")
        result = self.device_models[hostname].train(features_scaled, epochs=actual_epochs)

        if result.get("status") == "insufficient_data":
            logger.warning(f"[Autoencoder] Training failed for {hostname}: insufficient data")
            return result

        # Triple-verify is_trained flag is actually set
        if not self.device_models[hostname].is_trained:
            logger.error(f"[Autoencoder] ❌ CRITICAL BUG: Training completed but is_trained=False for {hostname}!")
            self.device_models[hostname].is_trained = True
            logger.info(f"[Autoencoder] ✅ Manually set is_trained=True for {hostname}")

        new_checksum = self._calculate_model_checksum(hostname)
        if new_checksum != prev_checksum:
            self.model_versions[hostname] = self.model_versions.get(hostname, 0) + 1
            self.model_checksums[hostname] = new_checksum
            logger.info(f"[Autoencoder] Model version updated for {hostname}: v{self.model_versions[hostname]} (checksum: {new_checksum})")

        self.save_device_model(hostname)

        import time
        current_time = time.time()
        self.device_training_meta[hostname].update({
            'last_trained': current_time,
            'first_trained': self.device_training_meta[hostname].get('first_trained') or current_time,
            'flows_since_training': 0,
            'last_trained_flow_count': current_flow_count,  # Store count at training time for delta calculation
            'training_count': self.device_training_meta[hostname].get('training_count', 0) + 1,
            'last_training_samples': len(features),
            'last_training_epochs': actual_epochs
        })

        self._save_training_metadata(hostname)

        final_status = self.device_models[hostname].is_trained
        logger.info(
            f"[Autoencoder] ✅ Training complete for {hostname}: "
            f"threshold={result.get('threshold', 0):.6f}, samples={len(features)}, "
            f"version=v{self.model_versions[hostname]}, is_trained={final_status}"
        )

        return {
            **result,
            "hostname": hostname,
            "n_samples": len(features),
            "is_trained": final_status,
            "version": self.model_versions[hostname],
            "checksum": self.model_checksums[hostname]
        }

    def predict_device(self, hostname: str, features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict anomalies for device using its autoencoder.
        """
        if hostname not in self.device_models:
            raise ValueError(f"No trained model for device: {hostname}")

        if not self.device_models[hostname].is_trained:
            raise ValueError(f"Model for {hostname} not trained")

        # Normalize features
        features_scaled = self.device_scalers[hostname].transform(features)

        # Predict
        predictions, risk_scores = self.device_models[hostname].predict(features_scaled)

        return predictions, risk_scores

    def is_device_trained(self, hostname: str) -> bool:
        """Check if device has trained model."""
        return (hostname in self.device_models and
                self.device_models[hostname].is_trained)

    def get_device_status(self, hostname: str) -> Dict:
        """Get training status for device including version info."""
        if hostname not in self.device_models:
            logger.warning(f"[Autoencoder] get_device_status: {hostname} NOT in device_models")
            return {"trained": False, "threshold": None, "version": 0}

        model = self.device_models[hostname]
        logger.info(f"[Autoencoder] get_device_status for {hostname}: is_trained={model.is_trained}, threshold={model.threshold}")

        return {
            "trained": model.is_trained,
            "threshold": float(model.threshold) if model.threshold else None,
            "encoding_dim": model.encoding_dim,
            "version": self.model_versions.get(hostname, 0),
            "checksum": self.model_checksums.get(hostname, ''),
            "training_count": self.device_training_meta.get(hostname, {}).get('training_count', 0)
        }

    def update_device_threshold(self, hostname: str, recent_errors: List[float]):
        """Update adaptive threshold for device."""
        if hostname in self.device_models:
            self.device_models[hostname].update_threshold(recent_errors)
            self.save_device_model(hostname)

    def save_device_model(self, hostname: str):
        """Save device model to disk with integrity verification."""
        if hostname not in self.device_models:
            return

        model_path = os.path.join(self.save_dir, f"{hostname}_autoencoder.pkl")
        version = self.model_versions.get(hostname, 1)
        versioned_path = os.path.join(self.save_dir, f"{hostname}_autoencoder_v{version}.pkl")

        try:
            model_data = {
                'autoencoder': self.device_models[hostname],
                'scaler': self.device_scalers[hostname],
                'version': version,
                'checksum': self.model_checksums.get(hostname, ''),
                'saved_at': datetime.now().isoformat()
            }

            # Compute checksum of model weights for integrity verification
            model_bytes = pickle.dumps(model_data['autoencoder'])
            model_data['integrity_hash'] = hashlib.sha256(model_bytes).hexdigest()

            # Save current version
            with open(model_path, 'wb') as f:
                pickle.dump(model_data, f)

            # Save versioned copy for rollback capability
            with open(versioned_path, 'wb') as f:
                pickle.dump(model_data, f)

            logger.debug(f"Saved autoencoder for {hostname} (v{version})")
        except Exception as e:
            logger.error(f"Failed to save autoencoder for {hostname}: {e}")

    def load_device_model(self, hostname: str) -> bool:
        """Load device model from disk with integrity verification."""
        model_path = os.path.join(self.save_dir, f"{hostname}_autoencoder.pkl")

        if not os.path.exists(model_path):
            return False

        try:
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)

            if 'integrity_hash' in model_data and 'autoencoder' in model_data:
                model_bytes = pickle.dumps(model_data['autoencoder'])
                computed_hash = hashlib.sha256(model_bytes).hexdigest()
                if computed_hash != model_data['integrity_hash']:
                    logger.error(f"Integrity check failed for {hostname} autoencoder - model may be corrupted")
                    return False

            self.device_models[hostname] = model_data['autoencoder']
            self.device_scalers[hostname] = model_data['scaler']
            self.model_versions[hostname] = model_data.get('version', 1)
            self.model_checksums[hostname] = model_data.get('checksum', '')

            # Load metadata if available
            self._load_training_metadata(hostname)

            logger.info(f"Loaded autoencoder for {hostname} (v{self.model_versions[hostname]})")
            return True
        except Exception as e:
            logger.error(f"Failed to load autoencoder for {hostname}: {e}")
            return False

    def get_all_devices(self) -> List[str]:
        """Get list of devices with trained models."""
        return [h for h, m in self.device_models.items() if m.is_trained]

    def should_retrain(self, hostname: str, current_flow_count: int = 0) -> bool:
        """Check if device should be retrained based on 500 flow / 7 day thresholds.
        
        Args:
            hostname: The device hostname
            current_flow_count: The actual flow count from AutoLearner's device_flow_counts
        """
        if hostname not in self.device_training_meta:
            return True

        meta = self.device_training_meta[hostname]
        
        # Calculate flows since last training using the provided count
        last_trained_count = meta.get('last_trained_flow_count', 0)
        flows_since_training = current_flow_count - last_trained_count
        
        # Update the flows_since_training in meta for reporting purposes
        meta['flows_since_training'] = flows_since_training

        # Retrain if 500+ new verified flows accumulated
        if flows_since_training >= 500:
            return True

        # Retrain if last training was >7 days ago
        last_trained = meta.get('last_trained')
        if last_trained:
            import time
            days_since_training = (time.time() - last_trained) / 86400
            if days_since_training > 7:
                return True

        return False

    def get_training_status(self, hostname: str) -> Tuple[int, float]:
        """
        Get training status for logging purposes.

        Returns:
            Tuple of (flows_since_training, days_since_training)
        """
        if hostname not in self.device_training_meta:
            return (0, 0.0)

        meta = self.device_training_meta[hostname]
        flows_since = meta.get('flows_since_training', 0)

        last_trained = meta.get('last_trained')
        if last_trained:
            import time
            days_since = (time.time() - last_trained) / 86400
        else:
            days_since = 0.0

        return (flows_since, days_since)

    def get_model_staleness(self, hostname: str) -> Dict:
        """
        Check if model is stale and needs retraining.
        Returns staleness metrics.
        """
        if hostname not in self.device_training_meta:
            return {"is_stale": True, "reason": "never_trained"}

        meta = self.device_training_meta[hostname]
        flows_since = meta.get('flows_since_training', 0)
        last_trained = meta.get('last_trained')

        if not last_trained:
            return {"is_stale": True, "reason": "never_trained"}

        import time
        days_since = (time.time() - last_trained) / 86400

        is_stale = flows_since >= 500 or days_since > 7

        return {
            "is_stale": is_stale,
            "flows_since_training": flows_since,
            "days_since_training": round(days_since, 1),
            "version": self.model_versions.get(hostname, 0),
            "training_count": meta.get('training_count', 0),
            "reason": "flows_threshold" if flows_since >= 500 else "time_threshold" if days_since > 7 else "fresh"
        }
