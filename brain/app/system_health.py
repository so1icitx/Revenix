"""
System Health Score tracker for monitoring AI detection performance.
Tracks accuracy, model health, alert quality, and system performance.
"""
import time
import logging
from typing import Dict, List, Optional
from collections import deque
import numpy as np

logger = logging.getLogger(__name__)


class SystemHealthTracker:
    """
    Tracks comprehensive system health metrics for AI detection system.
    """

    def __init__(self, history_size: int = 1000):
        """
        Initialize health tracker.

        Args:
            history_size: Number of recent events to track
        """
        self.history_size = history_size

        # Detection metrics
        self.total_flows_processed = 0
        self.baseline_flows_collected = 0
        self.total_alerts_created = 0
        self.total_flows_whitelisted = 0

        # Model health
        self.model_predictions = {
            'isolation_forest': deque(maxlen=history_size),
            'autoencoder': deque(maxlen=history_size),
            'baseline_deviation': deque(maxlen=history_size),
            'device_profile': deque(maxlen=history_size)
        }

        # Alert quality tracking
        self.alert_history = deque(maxlen=history_size)
        self.false_positive_flags = deque(maxlen=history_size)

        # Performance metrics
        self.processing_times = deque(maxlen=100)
        self.start_time = time.time()

        # Ensemble metrics
        self.ensemble_agreements = deque(maxlen=history_size)
        self.model_agreement_rate = {}

        logger.info("[HealthTracker] System health monitoring initialized")

    def record_flow_processed(self, processing_time: float, is_alert: bool,
                             is_whitelisted: bool, ensemble_details: Optional[Dict] = None):
        """Record a processed flow with its outcome."""
        self.total_flows_processed += 1

        if is_alert:
            self.total_alerts_created += 1

        if is_whitelisted:
            self.total_flows_whitelisted += 1

        self.processing_times.append(processing_time)

        # Track ensemble agreement
        if ensemble_details:
            agreement = ensemble_details.get('anomaly_votes', 0) / max(ensemble_details.get('total_votes', 1), 1)
            self.ensemble_agreements.append(agreement)

    def record_model_prediction(self, model_name: str, prediction: int,
                                confidence: float, risk_score: float):
        """Record a model's prediction for health tracking."""
        if model_name in self.model_predictions:
            self.model_predictions[model_name].append({
                'prediction': prediction,
                'confidence': confidence,
                'risk_score': risk_score,
                'timestamp': time.time()
            })

    def record_alert_quality(self, alert_id: int, is_false_positive: bool = False):
        """Record alert quality feedback."""
        self.alert_history.append({
            'alert_id': alert_id,
            'timestamp': time.time(),
            'false_positive': is_false_positive
        })

        if is_false_positive:
            self.false_positive_flags.append(time.time())

    def calculate_health_score(self) -> Dict:
        """
        Calculate overall system health score (0-100).

        Returns:
            Dict with health score and breakdown
        """
        scores = {}

        # 1. Detection Accuracy (0-30 points)
        detection_score = self._calculate_detection_accuracy()
        scores['detection_accuracy'] = detection_score

        # 2. Model Health (0-25 points)
        model_health_score = self._calculate_model_health()
        scores['model_health'] = model_health_score

        # 3. Alert Quality (0-25 points)
        alert_quality_score = self._calculate_alert_quality()
        scores['alert_quality'] = alert_quality_score

        # 4. System Performance (0-20 points)
        performance_score = self._calculate_performance_score()
        scores['system_performance'] = performance_score

        # Calculate total (0-100)
        total_score = sum(scores.values())

        return {
            'overall_score': round(total_score, 1),
            'breakdown': scores,
            'grade': self._get_grade(total_score),
            'status': self._get_status(total_score)
        }

    def _calculate_detection_accuracy(self) -> float:
        """Calculate detection accuracy score (0-30)."""
        if self.total_flows_processed == 0:
            return 15.0  # Neutral score

        # Alert rate should be reasonable (1-10% is good)
        alert_rate = self.total_alerts_created / self.total_flows_processed

        if 0.01 <= alert_rate <= 0.10:
            # Optimal range
            rate_score = 15.0
        elif alert_rate < 0.01:
            # Too few alerts (might be missing threats)
            rate_score = 10.0
        else:
            # Too many alerts (likely false positives)
            rate_score = max(5.0, 15.0 - (alert_rate - 0.10) * 100)

        # Ensemble agreement score
        if len(self.ensemble_agreements) > 0:
            avg_agreement = np.mean(self.ensemble_agreements)
            # Higher agreement = better detection confidence
            agreement_score = avg_agreement * 15.0
        else:
            agreement_score = 10.0

        return min(30.0, rate_score + agreement_score)

    def _calculate_model_health(self) -> float:
        """Calculate model health score (0-25)."""
        model_scores = []

        for model_name, predictions in self.model_predictions.items():
            if len(predictions) == 0:
                continue

            # Check model is making confident predictions
            confidences = [p['confidence'] for p in predictions]
            avg_confidence = np.mean(confidences)

            # Check for reasonable risk distribution
            risk_scores = [p['risk_score'] for p in predictions]
            risk_std = np.std(risk_scores)

            # Healthy model: high average confidence, good risk distribution
            model_score = (avg_confidence * 0.6 + min(risk_std * 2, 1.0) * 0.4) * 100
            model_scores.append(model_score)

        if len(model_scores) == 0:
            return 15.0  # Neutral

        # Average model health, scaled to 25 points
        avg_health = np.mean(model_scores)
        return (avg_health / 100) * 25.0

    def _calculate_alert_quality(self) -> float:
        """Calculate alert quality score (0-25)."""
        if len(self.alert_history) == 0:
            return 20.0  # Neutral

        # Calculate false positive rate
        recent_fps = [a for a in self.alert_history if a['false_positive']]
        fp_rate = len(recent_fps) / len(self.alert_history)

        # Lower FP rate = higher score
        # 0% FP = 25 points, 50% FP = 0 points
        quality_score = max(0, 25.0 * (1.0 - fp_rate * 2))

        return quality_score

    def _calculate_performance_score(self) -> float:
        """Calculate system performance score (0-20)."""
        if len(self.processing_times) == 0:
            return 15.0  # Neutral

        # Calculate average processing time
        avg_time = np.mean(self.processing_times)

        # Target: <100ms per flow = excellent, >1s = poor
        if avg_time < 0.1:
            time_score = 10.0
        elif avg_time < 0.5:
            time_score = 8.0
        elif avg_time < 1.0:
            time_score = 5.0
        else:
            time_score = max(0, 10.0 - avg_time)

        # Calculate uptime
        uptime_hours = (time.time() - self.start_time) / 3600
        uptime_score = min(10.0, uptime_hours * 0.1)  # 100 hours = max score

        return time_score + uptime_score

    def _get_grade(self, score: float) -> str:
        """Convert score to letter grade."""
        if score >= 90:
            return "A+"
        elif score >= 85:
            return "A"
        elif score >= 80:
            return "B+"
        elif score >= 75:
            return "B"
        elif score >= 70:
            return "C+"
        elif score >= 65:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    def _get_status(self, score: float) -> str:
        """Get status message based on score."""
        if score >= 85:
            return "Excellent"
        elif score >= 75:
            return "Good"
        elif score >= 65:
            return "Fair"
        elif score >= 50:
            return "Poor"
        else:
            return "Critical"

    def get_statistics(self) -> Dict:
        """Get detailed system statistics."""
        health = self.calculate_health_score()

        uptime_seconds = time.time() - self.start_time

        total_flows = self.baseline_flows_collected + self.total_flows_processed

        stats = {
            'health_score': health,
            'metrics': {
                'total_flows': total_flows,
                'baseline_flows_collected': self.baseline_flows_collected,
                'total_flows_processed': self.total_flows_processed,
                'total_alerts_created': self.total_alerts_created,
                'total_flows_whitelisted': self.total_flows_whitelisted,
                'alert_rate': round(
                    self.total_alerts_created / max(self.total_flows_processed, 1) * 100, 2
                ),
                'whitelist_rate': round(
                    self.total_flows_whitelisted / max(self.total_flows_processed, 1) * 100, 2
                )
            },
            'performance': {
                'avg_processing_time_ms': round(
                    np.mean(self.processing_times) * 1000, 2
                ) if len(self.processing_times) > 0 else 0,
                'uptime_hours': round(uptime_seconds / 3600, 2),
                'flows_per_minute': round(
                    self.total_flows_processed / (uptime_seconds / 60), 2
                ) if uptime_seconds > 0 else 0
            },
            'model_status': self._get_model_status()
        }

        return stats

    def _get_model_status(self) -> Dict:
        """Get status of each model."""
        status = {}

        for model_name, predictions in self.model_predictions.items():
            if len(predictions) == 0:
                status[model_name] = {
                    'active': False,
                    'predictions': 0
                }
            else:
                confidences = [p['confidence'] for p in predictions]
                status[model_name] = {
                    'active': True,
                    'predictions': len(predictions),
                    'avg_confidence': round(np.mean(confidences), 3),
                    'last_prediction': predictions[-1]['timestamp']
                }

        return status

    def record_baseline_flow(self):
        """Record a flow collected for baseline training."""
        self.baseline_flows_collected += 1
