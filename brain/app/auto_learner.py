import asyncio
import aiohttp
import logging
import os
import time
from typing import List, Dict
from .anomaly_detector import AnomalyDetector
from .features import FlowFeatureExtractor

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
        api_url: str = "http://api:8000",
        check_interval: int = 60,
        training_threshold: int = 100,
        alert_threshold: float = 0.6,
        retrain_interval: int = 3600,  # Retrain every hour
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

        self.flows_seen = 0
        self.last_flow_id = None
        self.last_retrain_time = 0
        self.baseline_flows = []  # Store flows for retraining

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
                    await self.retrain_model()
                    self.last_retrain_time = current_time

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
            for i, flow in enumerate(flows):
                risk_score = float(risk_scores[i])
                is_anomaly = predictions[i] == -1

                if risk_score >= self.alert_threshold:
                    await self.create_alert(session, flow, risk_score, is_anomaly)
                    alerts_created += 1

            if alerts_created > 0:
                logger.info(f"[AutoLearner] 🚨 Created {alerts_created} alerts for suspicious flows")
            else:
                logger.info(f"[AutoLearner] ✓ Analyzed {len(flows)} flows - all normal")

        except Exception as e:
            logger.error(f"[AutoLearner] Analysis failed: {e}")

    async def create_alert(
        self,
        session: aiohttp.ClientSession,
        flow: Dict,
        risk_score: float,
        is_anomaly: bool
    ):
        """Send alert to API."""
        try:
            reason = self.build_threat_reason(flow, risk_score, is_anomaly)

            alert = {
                "flow_id": flow.get("flow_id", ""),
                "hostname": flow.get("hostname", ""),
                "src_ip": flow.get("src_ip", ""),
                "dst_ip": flow.get("dst_ip", ""),
                "protocol": flow.get("protocol", "TCP"),
                "risk_score": risk_score,
                "reason": reason
            }

            async with session.post(
                f"{self.api_url}/alerts/create",
                json=alert
            ) as resp:
                if resp.status in [200, 201]:
                    logger.info(f"[AutoLearner] Alert created: {reason} (risk: {risk_score:.2f})")
                else:
                    logger.error(f"[AutoLearner] Failed to create alert: {resp.status}")
        except Exception as e:
            logger.error(f"[AutoLearner] Error creating alert: {e}")

    async def retrain_model(self):
        """Retrain model on recent flows to adapt to network changes."""
        if len(self.baseline_flows) < 50:
            logger.info("[AutoLearner] Not enough flows for retraining, skipping...")
            return

        logger.info(f"[AutoLearner] 🔄 Retraining model on {len(self.baseline_flows)} recent flows...")

        try:
            features = self.feature_extractor.extract_features_batch(self.baseline_flows)
            feature_names = self.feature_extractor.get_feature_names()

            result = self.anomaly_detector.train(features, feature_names)

            logger.info(f"[AutoLearner] ✓ Model retrained! Adapted to network changes.")
            logger.info(f"[AutoLearner] New baseline: {result['n_samples']} flows")

            self.save_model()
        except Exception as e:
            logger.error(f"[AutoLearner] Retraining failed: {e}")

    def build_threat_reason(self, flow: Dict, risk_score: float, is_anomaly: bool) -> str:
        """Generate human-readable threat explanation."""
        features = self.feature_extractor.extract_features(flow)

        reasons = []

        if features.get('packets_per_sec', 0) > 100:
            reasons.append("High packet rate")

        if features.get('bytes_per_packet', 0) > 5000:
            reasons.append("Large packet size")

        if features.get('port_range', 0) > 10:
            reasons.append("Multiple ports (port scan?)")

        if features.get('src_port_entropy', 0) > 2.0:
            reasons.append("Random source ports")

        if not reasons:
            if is_anomaly:
                reasons.append("Unusual traffic pattern")
            else:
                reasons.append("Suspicious behavior detected")

        return ", ".join(reasons)

# Global auto-learner instance
auto_learner = None

async def start_auto_learner(anomaly_detector, feature_extractor):
    """Start the auto-learning background task."""
    global auto_learner
    auto_learner = AutoLearner(
        anomaly_detector=anomaly_detector,
        feature_extractor=feature_extractor,
        api_url="http://api:8000",
        check_interval=60,
        training_threshold=100,
        alert_threshold=0.6,
        retrain_interval=3600,
        model_save_path="/app/models/anomaly_model.pkl"
    )
    await auto_learner.start()
