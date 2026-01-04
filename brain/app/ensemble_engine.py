"""
Ensemble Decision Engine for robust anomaly detection.
Combines multiple models with weighted voting and confidence scoring.
"""
import numpy as np
from typing import Dict, List, Tuple, Optional
import logging

logger = logging.getLogger(__name__)


class ModelVote:
    """Represents a single model's vote on whether traffic is anomalous."""

    def __init__(self, model_name: str, is_anomaly: bool, confidence: float,
                 risk_score: float, reason: str = ""):
        self.model_name = model_name
        self.is_anomaly = is_anomaly  # -1 or 1 from model
        self.confidence = confidence  # 0-1, how confident the model is
        self.risk_score = risk_score  # 0-1, normalized risk
        self.reason = reason

    def __repr__(self):
        return f"Vote({self.model_name}, anomaly={self.is_anomaly}, conf={self.confidence:.2f}, risk={self.risk_score:.2f})"


class EnsembleEngine:
    """
    Weighted ensemble voting system for anomaly detection.
    Combines predictions from multiple models with configurable weights.
    """

    def __init__(
        self,
        model_weights: Optional[Dict[str, float]] = None,
        min_agreement: int = 2,
        confidence_threshold: float = 0.7
    ):
        """
        Initialize ensemble engine.

        Args:
            model_weights: Weight for each model (higher = more trust)
            min_agreement: Minimum models that must agree for alert
            confidence_threshold: Minimum confidence for a vote to count
        """
        # Default weights: Autoencoder gets highest weight (most reliable)
        self.model_weights = model_weights or {
            'isolation_forest': 0.35,
            'autoencoder': 0.40,
            'baseline_deviation': 0.15,
            'device_profile': 0.10
        }

        self.min_agreement = min_agreement
        self.confidence_threshold = confidence_threshold

        logger.info(f"[Ensemble] Initialized with weights: {self.model_weights}")
        logger.info(f"[Ensemble] Minimum agreement required: {min_agreement} models")
        logger.info(f"[Ensemble] Confidence threshold: {confidence_threshold}")

    def vote(self, votes: List[ModelVote]) -> Tuple[bool, float, Dict]:
        """
        Perform ensemble voting on model predictions.

        Args:
            votes: List of votes from different models

        Returns:
            Tuple of (is_anomaly, final_risk_score, details)
        """
        if not votes:
            return False, 0.0, {"reason": "No votes provided"}

        # Filter out low-confidence votes
        high_confidence_votes = [
            v for v in votes
            if v.confidence >= self.confidence_threshold
        ]

        if len(high_confidence_votes) == 0:
            return False, 0.0, {
                "reason": "No high-confidence votes",
                "total_votes": len(votes),
                "filtered_votes": 0
            }

        # Calculate weighted scores
        weighted_anomaly_score = 0.0
        weighted_normal_score = 0.0
        total_weight = 0.0

        anomaly_votes = []
        normal_votes = []

        for vote in high_confidence_votes:
            weight = self.model_weights.get(vote.model_name, 0.1)

            # Weight by both model importance and prediction confidence
            effective_weight = weight * vote.confidence
            total_weight += effective_weight

            if vote.is_anomaly == -1:  # Anomaly detected
                weighted_anomaly_score += effective_weight * vote.risk_score
                anomaly_votes.append(vote)
            else:  # Normal
                weighted_normal_score += effective_weight * (1.0 - vote.risk_score)
                normal_votes.append(vote)

        # Normalize weighted scores
        if total_weight > 0:
            weighted_anomaly_score /= total_weight
            weighted_normal_score /= total_weight

        # Check agreement threshold
        num_anomaly_votes = len(anomaly_votes)
        is_anomaly = num_anomaly_votes >= self.min_agreement

        # Calculate final risk score
        if is_anomaly:
            # Use weighted anomaly score
            final_risk_score = weighted_anomaly_score
        else:
            # Low risk if not enough agreement
            final_risk_score = weighted_anomaly_score * 0.5  # Penalty for disagreement

        # Build detailed explanation
        details = {
            "is_anomaly": is_anomaly,
            "anomaly_votes": num_anomaly_votes,
            "normal_votes": len(normal_votes),
            "total_votes": len(high_confidence_votes),
            "agreement_met": num_anomaly_votes >= self.min_agreement,
            "weighted_anomaly_score": float(weighted_anomaly_score),
            "weighted_normal_score": float(weighted_normal_score),
            "final_risk_score": float(final_risk_score),
            "voting_models": [v.model_name for v in anomaly_votes],
            "dissenting_models": [v.model_name for v in normal_votes],
        }

        # Log decision
        if is_anomaly:
            logger.info(
                f"[Ensemble] 🚨 ANOMALY DETECTED - {num_anomaly_votes}/{len(high_confidence_votes)} "
                f"models agree (risk: {final_risk_score:.2f})"
            )
        else:
            logger.debug(
                f"[Ensemble] ✓ NORMAL - Only {num_anomaly_votes}/{len(high_confidence_votes)} "
                f"models flagged (need {self.min_agreement})"
            )

        return is_anomaly, final_risk_score, details

    def calculate_confidence(self, prediction: int, risk_score: float,
                           model_uncertainty: Optional[float] = None) -> float:
        """
        Calculate confidence score for a model's prediction.

        Args:
            prediction: 1 = normal, -1 = anomaly
            risk_score: 0-1 risk score from model
            model_uncertainty: Optional uncertainty measure

        Returns:
            Confidence score 0-1
        """
        # Base confidence on how extreme the risk score is
        if prediction == -1:  # Anomaly
            # High risk = high confidence
            base_confidence = risk_score
        else:  # Normal
            # Low risk = high confidence for normal
            base_confidence = 1.0 - risk_score

        # Adjust for model uncertainty if provided
        if model_uncertainty is not None:
            confidence = base_confidence * (1.0 - model_uncertainty)
        else:
            confidence = base_confidence

        return np.clip(confidence, 0.0, 1.0)

    def explain_decision(self, votes: List[ModelVote], details: Dict) -> str:
        """
        Generate human-readable explanation of ensemble decision.

        Args:
            votes: List of model votes
            details: Voting details from vote() method

        Returns:
            Explanation string
        """
        if not details.get("agreement_met", False):
            return (
                f"Flow classified as NORMAL. Only {details['anomaly_votes']} of "
                f"{details['total_votes']} models detected anomaly "
                f"(need {self.min_agreement} agreement)."
            )

        voting_models = details.get("voting_models", [])
        risk = details.get("final_risk_score", 0.0)

        explanation = (
            f"Flow classified as ANOMALY with {risk:.1%} confidence. "
            f"{len(voting_models)} models agree: {', '.join(voting_models)}."
        )

        # Add specific reasons from top voting models
        anomaly_votes = [v for v in votes if v.is_anomaly == -1]
        if anomaly_votes:
            top_vote = max(anomaly_votes, key=lambda v: v.risk_score)
            if top_vote.reason:
                explanation += f" Primary concern: {top_vote.reason}"

        return explanation

    def update_weights(self, performance_metrics: Dict[str, Dict]):
        """
        Adaptively update model weights based on performance.

        Args:
            performance_metrics: Dict of {model_name: {precision, recall, f1}}
        """
        for model_name, metrics in performance_metrics.items():
            if model_name not in self.model_weights:
                continue

            # Weight by F1 score (balance of precision and recall)
            f1_score = metrics.get('f1', 0.5)

            # Adjust weight based on performance
            current_weight = self.model_weights[model_name]
            new_weight = 0.7 * current_weight + 0.3 * f1_score

            self.model_weights[model_name] = np.clip(new_weight, 0.05, 0.5)

        # Normalize weights to sum to 1.0
        total = sum(self.model_weights.values())
        if total > 0:
            self.model_weights = {
                k: v / total for k, v in self.model_weights.items()
            }

        logger.info(f"[Ensemble] Updated model weights: {self.model_weights}")
