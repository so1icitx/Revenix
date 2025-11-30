import asyncio
import aiohttp
import logging
import os
import time
from typing import List, Dict, Optional
import numpy as np
from .anomaly_detector import AnomalyDetector
from .features import FlowFeatureExtractor
from .device_profiler import DeviceProfiler
from .rule_recommender import RuleRecommender
from .threat_explainer import ThreatExplainer  # Added threat explainer
from .threat_classifier import ThreatClassifier  # Added threat classifier import
from .baseline_tracker import BaselineTracker  # Import baseline tracker

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AutoLearner:
    """
    Automatically learns from network flows and detects threats.
    Continuously trains on baseline and flags anomalies.
    """

    def __init__(
        self,
        anomaly_detector: AnomalyDetector,
        feature_extractor: FlowFeatureExtractor,
        device_profiler: DeviceProfiler,
        api_url: str = "http://api:8000",
        check_interval: int = 60,
        training_threshold: int = 100,
        alert_threshold: float = 0.75,
        retrain_interval: int = 3600,
        model_save_path: str = "/app/models/anomaly_model.pkl"
    ):
        self.api_url = api_url
        self.check_interval = check_interval
        self.training_threshold = training_threshold
        self.alert_threshold = alert_threshold
        self.retrain_interval = retrain_interval
        self.model_save_path = model_save_path

        self.feature_extractor = feature_extractor
        self.anomaly_detector = anomaly_detector
        self.device_profiler = device_profiler
        self.rule_recommender = RuleRecommender()
        self.threat_explainer = ThreatExplainer()
        self.threat_classifier = ThreatClassifier()

        self.baseline_tracker = BaselineTracker()

        self.flows_seen = 0
        self.last_flow_id = None
        self.last_retrain_time = 0
        self.baseline_flows = []
        self.device_flows = {}

    async def start(self):
        """Start the auto-learning loop."""
        logger.info("[AutoLearner] Starting AI auto-learning system...")
        logger.info(f"[AutoLearner] Training threshold: {self.training_threshold} flows")
        logger.info(f"[AutoLearner] Alert threshold: {self.alert_threshold}")
        self.load_model_if_exists()

        while True:
            try:
                await self.process_flows()
                await asyncio.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"[AutoLearner] Error: {e}")
                await asyncio.sleep(self.check_interval)

    def load_model_if_exists(self):
        """Load existing model from disk if available."""
        if os.path.exists(self.model_save_path):
            try:
                self.anomaly_detector.load_model(self.model_save_path)
                logger.info(f"[AutoLearner] ✓ Loaded existing model from {self.model_save_path}")
            except Exception as e:
                logger.warning(f"[AutoLearner] Could not load model: {e}")

    def save_model(self):
        """Save current model to disk."""
        os.makedirs(os.path.dirname(self.model_save_path), exist_ok=True)
        try:
            self.anomaly_detector.save_model(self.model_save_path)
            logger.info(f"[AutoLearner] ✓ Model saved to {self.model_save_path}")
        except Exception as e:
            logger.error(f"[AutoLearner] Failed to save model: {e}")

    async def process_flows(self):
        """Fetch flows, train if needed, then analyze for threats."""
        async with aiohttp.ClientSession() as session:
            flows = await self.fetch_flows(session)

            if not flows or len(flows) == 0:
                logger.info("[AutoLearner] No new flows to process")
                return

            logger.info(f"[AutoLearner] Processing {len(flows)} flows")

            self.baseline_flows.extend(flows)
            if len(self.baseline_flows) > 1000:
                self.baseline_flows = self.baseline_flows[-1000:]

            self._group_flows_by_device(flows)

            await self._train_device_profiles()

            if not self.anomaly_detector.is_trained:
                self.flows_seen += len(flows)
                logger.info(f"[AutoLearner] Collected {self.flows_seen}/{self.training_threshold} baseline flows")

                if self.flows_seen >= self.training_threshold:
                    await self.train_baseline(self.baseline_flows[:self.training_threshold])
                    self.save_model()
                    self.last_retrain_time = time.time()
            else:
                await self.analyze_threats(session, flows)

                current_time = time.time()
                if current_time - self.last_retrain_time >= self.retrain_interval:
                    logger.info("[AutoLearner] Retraining model with recent flows...")
                    await self.train_baseline(self.baseline_flows[-1000:])
                    self.save_model()
                    logger.info("[AutoLearner] ✓ Model retrained! Adapted to network changes")
                    self.last_retrain_time = current_time

    def _group_flows_by_device(self, flows: List[Dict]):
        """Group flows by hostname for per-device analysis."""
        for flow in flows:
            hostname = flow.get('hostname', 'unknown')
            if hostname not in self.device_flows:
                self.device_flows[hostname] = []
            self.device_flows[hostname].append(flow)

            if len(self.device_flows[hostname]) > 200:
                self.device_flows[hostname] = self.device_flows[hostname][-200:]

        for hostname, device_flow_list in self.device_flows.items():
            self.baseline_tracker.update_baseline(hostname, device_flow_list[-50:])  # Use recent flows

    async def _train_device_profiles(self):
        """Train individual profiles for each device."""
        for hostname, flows in self.device_flows.items():
            profile_status = self.device_profiler.get_profile_status(hostname)

            if not profile_status['trained'] and len(flows) >= 30:
                try:
                    features = self.feature_extractor.extract_features_batch(flows)
                    feature_names = self.feature_extractor.get_feature_names()

                    self.device_profiler.train_device(hostname, features, feature_names)
                    logger.info(f"[AutoLearner] ✓ Trained profile for device: {hostname} ({len(flows)} flows)")
                except Exception as e:
                    logger.error(f"[AutoLearner] Failed to train profile for {hostname}: {e}")

    async def fetch_flows(self, session: aiohttp.ClientSession) -> List[Dict]:
        """Fetch recent flows from API."""
        try:
            async with session.get(f"{self.api_url}/flows/recent") as resp:
                if resp.status == 200:
                    flows = await resp.json()
                    return flows
                else:
                    logger.error(f"[AutoLearner] Failed to fetch flows: {resp.status}")
                    return []
        except Exception as e:
            logger.error(f"[AutoLearner] Error fetching flows: {e}")
            return []

    async def train_baseline(self, flows: List[Dict]):
        """Train model on baseline normal traffic."""
        logger.info(f"[AutoLearner] Training baseline on {len(flows)} flows...")

        try:
            features = self.feature_extractor.extract_features_batch(flows)
            feature_names = self.feature_extractor.get_feature_names()

            result = self.anomaly_detector.train(features, feature_names)

            logger.info(f"[AutoLearner] ✓ Baseline trained! Model ready to detect threats.")
            logger.info(f"[AutoLearner] Features: {result['n_features']}, Samples: {result['n_samples']}")
        except Exception as e:
            logger.error(f"[AutoLearner] Training failed: {e}")

    async def analyze_threats(self, session: aiohttp.ClientSession, flows: List[Dict]):
        """Analyze flows for anomalies and create alerts."""
        try:
            features = self.feature_extractor.extract_features_batch(flows)

            predictions, risk_scores = self.anomaly_detector.predict(features)

            alerts_created = 0
            whitelisted_count = 0

            for i, flow in enumerate(flows):
                risk_score = float(risk_scores[i])
                is_anomaly = predictions[i] == -1

                device_risk_score = await self._check_device_profile(flow, features[i])
                if device_risk_score is not None:
                    risk_score = max(risk_score, device_risk_score)

                hostname = flow.get('hostname', 'unknown')
                baseline_deviation = self.baseline_tracker.get_deviation_score(hostname, flow)

                # Combine ML score with baseline deviation
                risk_score = max(risk_score, baseline_deviation)

                features_dict = self.feature_extractor.extract_features(flow)
                threat_category, threat_confidence, classification_reason = self.threat_classifier.classify_threat(
                    flow, features_dict, risk_score
                )

                if threat_category is None:
                    whitelisted_count += 1
                    continue

                final_risk_score = max(risk_score, threat_confidence)

                if final_risk_score >= self.alert_threshold:
                    baseline_info = self.baseline_tracker.get_baseline_info(hostname)
                    await self.create_alert(
                        session, flow, final_risk_score, is_anomaly,
                        threat_category=threat_category,
                        threat_reason=classification_reason,
                        baseline_info=baseline_info
                    )
                    alerts_created += 1

            if alerts_created > 0:
                logger.info(f"[AutoLearner] 🚨 Created {alerts_created} alerts ({whitelisted_count} flows whitelisted)")
            else:
                logger.info(f"[AutoLearner] ✓ Analyzed {len(flows)} flows - {whitelisted_count} whitelisted, {len(flows) - whitelisted_count} normal")

        except Exception as e:
            logger.error(f"[AutoLearner] Analysis failed: {e}")

    async def _check_device_profile(self, flow: Dict, features: np.ndarray) -> Optional[float]:
        """Check device-specific anomaly score."""
        hostname = flow.get('hostname', 'unknown')
        profile_status = self.device_profiler.get_profile_status(hostname)

        if not profile_status['trained']:
            return None

        try:
            features_2d = features.reshape(1, -1)
            _, device_risk_scores = self.device_profiler.predict_device(hostname, features_2d)
            return float(device_risk_scores[0])
        except Exception as e:
            logger.error(f"[AutoLearner] Device profile check failed for {hostname}: {e}")
            return None

    async def create_alert(
        self,
        session: aiohttp.ClientSession,
        flow: Dict,
        risk_score: float,
        is_anomaly: bool,
        threat_category: Optional[str] = None,
        threat_reason: Optional[str] = None,
        baseline_info: Optional[Dict] = None  # Added baseline info
    ):
        """Send alert to API and recommend firewall rules."""
        try:
            features_dict = self.feature_extractor.extract_features(flow)
            hostname = flow.get('hostname', 'unknown')
            profile_status = self.device_profiler.get_profile_status(hostname)

            if threat_reason:
                detailed_reason = threat_reason
            else:
                detailed_reason = self.threat_explainer.explain_threat(
                    flow=flow,
                    risk_score=risk_score,
                    features=features_dict,
                    device_profile_trained=profile_status.get('trained', False),
                    baseline_comparison=baseline_info
                )

            if threat_category:
                severity = self.threat_classifier.get_threat_severity(threat_category, risk_score)
            else:
                severity = self._get_severity_from_score(risk_score)

            mitigations = self.threat_explainer.get_mitigation_recommendations(
                flow, risk_score, threat_category or "anomalous_behavior"
            )

            full_reason = detailed_reason
            if mitigations:
                full_reason += f" Recommended action: {mitigations[0]}"

            alert = {
                "flow_id": flow.get("flow_id", ""),
                "hostname": flow.get("hostname", ""),
                "src_ip": flow.get("src_ip", ""),
                "dst_ip": flow.get("dst_ip", ""),
                "protocol": flow.get("protocol", "TCP"),
                "risk_score": risk_score,
                "severity": severity,
                "reason": full_reason,
                "threat_category": threat_category
            }

            async with session.post(
                f"{self.api_url}/alerts/create",
                json=alert
            ) as resp:
                if resp.status in [200, 201]:
                    category_str = f"[{threat_category.upper()}]" if threat_category else ""
                    brief_summary = detailed_reason.split('.')[0]
                    logger.info(f"[AutoLearner] {category_str} Alert: {brief_summary}... (risk: {risk_score:.2f})")

                    alert_data = await resp.json()
                    alert_id = alert_data.get("alert_id")

                    if alert_id:
                        await self.recommend_rules_for_alert(
                            session, alert_id, flow, risk_score, detailed_reason
                        )
                else:
                    logger.error(f"[AutoLearner] Failed to create alert: {resp.status}")
        except Exception as e:
            logger.error(f"[AutoLearner] Error creating alert: {e}")

    async def recommend_rules_for_alert(
        self,
        session: aiohttp.ClientSession,
        alert_id: int,
        flow: Dict,
        risk_score: float,
        reason: str
    ):
        """Generate and submit rule recommendations for an alert."""
        try:
            rules = self.rule_recommender.recommend_rules(flow, risk_score, reason)

            if not rules:
                return

            for rule in rules:
                rule_data = {
                    "alert_id": alert_id,
                    **rule
                }

                async with session.post(
                    f"{self.api_url}/rules/create",
                    json=rule_data
                ) as resp:
                    if resp.status in [200, 201]:
                        logger.info(
                            f"[RuleEngine] Recommended: {rule['action']} {rule['target']} "
                            f"(confidence: {rule['confidence']:.2f})"
                        )
                    else:
                        logger.error(f"[RuleEngine] Failed to create rule: {resp.status}")

        except Exception as e:
            logger.error(f"[RuleEngine] Error recommending rules: {e}")

    def _get_severity_from_score(self, risk_score: float) -> str:
        """Fallback severity calculation from risk score."""
        if risk_score >= 0.9:
            return "critical"
        elif risk_score >= 0.8:
            return "high"
        elif risk_score >= 0.7:
            return "medium"
        else:
            return "low"

# Global auto-learner instance
auto_learner = None

async def start_auto_learner(anomaly_detector, feature_extractor, device_profiler):
    """Start the auto-learning background task."""
    global auto_learner
    auto_learner = AutoLearner(
        anomaly_detector=anomaly_detector,
        feature_extractor=feature_extractor,
        device_profiler=device_profiler,
        api_url="http://api:8000",
        check_interval=60,
        training_threshold=100,
        alert_threshold=0.75,
        retrain_interval=3600,
        model_save_path="/app/models/anomaly_model.pkl"
    )
    await auto_learner.start()
