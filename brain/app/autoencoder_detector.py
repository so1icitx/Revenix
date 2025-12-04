import numpy as np
from sklearn.preprocessing import StandardScaler
import pickle
import os
from typing import Dict, List, Tuple, Optional
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

        # Network weights
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
    Per-device autoencoder anomaly detector.
    Maintains separate autoencoders for each device.
    """

    def __init__(self, save_dir: str = "/app/models/autoencoders"):
        self.save_dir = save_dir
        self.device_models: Dict[str, SimpleAutoencoder] = {}
        self.device_scalers: Dict[str, StandardScaler] = {}
        os.makedirs(save_dir, exist_ok=True)

    def train_device(self, hostname: str, features: np.ndarray,
                    epochs: int = 50) -> Dict:
        """
        Train autoencoder for specific device.

        Args:
            hostname: Device identifier
            features: Training data (n_samples, n_features)
            epochs: Training epochs

        Returns:
            Training status dict
        """
        if len(features) < 5:
            logger.warning(f"Autoencoder training skipped for {hostname}: only {len(features)} samples (need 5+)")
            return {"status": "insufficient_data", "samples": len(features), "is_trained": False}

        # Initialize or get existing model
        if hostname not in self.device_models:
            self.device_models[hostname] = SimpleAutoencoder(
                encoding_dim=min(8, features.shape[1] // 2)
            )
            self.device_scalers[hostname] = StandardScaler()

        # Normalize features
        features_scaled = self.device_scalers[hostname].fit_transform(features)

        # Train autoencoder
        logger.info(f"[Autoencoder] Training {hostname} with {len(features)} samples...")
        result = self.device_models[hostname].train(features_scaled, epochs=epochs)

        if result.get("status") == "insufficient_data":
            logger.warning(f"[Autoencoder] Training failed for {hostname}: insufficient data")
            return result

        # Triple-verify is_trained flag is actually set
        if not self.device_models[hostname].is_trained:
            logger.error(f"[Autoencoder] ❌ CRITICAL BUG: Training completed but is_trained=False for {hostname}!")
            # Force set it since training completed successfully
            self.device_models[hostname].is_trained = True
            logger.info(f"[Autoencoder] ✅ Manually set is_trained=True for {hostname}")

        # Save model
        self.save_device_model(hostname)

        final_status = self.device_models[hostname].is_trained
        logger.info(f"[Autoencoder] ✅ Training complete for {hostname}: threshold={result.get('threshold', 0):.6f}, samples={len(features)}, is_trained={final_status}")

        logger.info(f"[Autoencoder] DEBUG: Model in dict? {hostname in self.device_models}, Can access? {self.device_models.get(hostname) is not None}")

        return {
            **result,
            "hostname": hostname,
            "n_samples": len(features),
            "is_trained": final_status  # Return the actual current status
        }

    def predict_device(self, hostname: str, features: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict anomalies for device using its autoencoder.

        Args:
            hostname: Device identifier
            features: Input features (n_samples, n_features)

        Returns:
            Tuple of (predictions, risk_scores)
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
        """Get training status for device."""
        if hostname not in self.device_models:
            logger.warning(f"[Autoencoder] get_device_status: {hostname} NOT in device_models")
            return {"trained": False, "threshold": None}

        model = self.device_models[hostname]
        logger.info(f"[Autoencoder] get_device_status for {hostname}: is_trained={model.is_trained}, threshold={model.threshold}")

        return {
            "trained": model.is_trained,
            "threshold": float(model.threshold) if model.threshold else None,
            "encoding_dim": model.encoding_dim
        }

    def update_device_threshold(self, hostname: str, recent_errors: List[float]):
        """Update adaptive threshold for device."""
        if hostname in self.device_models:
            self.device_models[hostname].update_threshold(recent_errors)
            self.save_device_model(hostname)

    def save_device_model(self, hostname: str):
        """Save device model to disk."""
        if hostname not in self.device_models:
            return

        model_path = os.path.join(self.save_dir, f"{hostname}_autoencoder.pkl")

        try:
            model_data = {
                'autoencoder': self.device_models[hostname],
                'scaler': self.device_scalers[hostname]
            }

            with open(model_path, 'wb') as f:
                pickle.dump(model_data, f)

            logger.debug(f"Saved autoencoder for {hostname}")
        except Exception as e:
            logger.error(f"Failed to save autoencoder for {hostname}: {e}")

    def load_device_model(self, hostname: str) -> bool:
        """Load device model from disk."""
        model_path = os.path.join(self.save_dir, f"{hostname}_autoencoder.pkl")

        if not os.path.exists(model_path):
            return False

        try:
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)

            self.device_models[hostname] = model_data['autoencoder']
            self.device_scalers[hostname] = model_data['scaler']

            logger.info(f"Loaded autoencoder for {hostname}")
            return True
        except Exception as e:
            logger.error(f"Failed to load autoencoder for {hostname}: {e}")
            return False

    def get_all_devices(self) -> List[str]:
        """Get list of devices with trained models."""
        return [h for h, m in self.device_models.items() if m.is_trained]
