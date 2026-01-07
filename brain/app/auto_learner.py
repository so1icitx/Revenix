import asyncio
import aiohttp
import logging
import os
import time
from typing import List, Dict, Optional
import numpy as np
from concurrent.futures import ThreadPoolExecutor
import concurrent.futures
from .anomaly_detector import AnomalyDetector
from .features import FlowFeatureExtractor
from .device_profiler import DeviceProfiler
from .rule_recommender import RuleRecommender
from .threat_explainer import ThreatExplainer  # Added threat explainer
from .threat_classifier import ThreatClassifier  # Added threat classifier import
from .baseline_tracker import BaselineTracker  # Import baseline tracker
from .autoencoder_detector import AutoencoderDetector  # Added autoencoder import
from .ensemble_engine import EnsembleEngine, ModelVote  # Added ensemble imports
from .self_healing import SelfHealingSystem  # Added self-healing import
from .system_health import SystemHealthTracker  # Added system health tracker
from .sequential_detector import SequentialPatternDetector  # Sequential pattern detection
from .simple_explainer import SimpleExplainer  # NEW: Human-readable explanations

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
        training_threshold: int = 200,  # Lowered for faster initial training
        alert_threshold: float = 0.85,  # Higher default to reduce false positives
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
        self.simple_explainer = SimpleExplainer()  # NEW: Simple, clear explanations

        self.baseline_tracker = BaselineTracker()

        self.autoencoder_detector = AutoencoderDetector()

        # Will be updated with LSTM after initialization
        self.ensemble_engine = EnsembleEngine(
            model_weights={
                'isolation_forest': 0.25,
                'autoencoder': 0.30,
                'baseline_deviation': 0.15,
                'device_profile': 0.10,
                'lstm_sequential': 0.20  # NEW: LSTM for sequential patterns
            },
            min_agreement=2,  # Require at least 2 models to agree
            confidence_threshold=0.65  # Only count high-confidence votes
        )

        # OPTIMIZED: Smart Self-Healing with balanced thresholds
        self.self_healing = SelfHealingSystem(
            # Immediate block at 95% confidence (realistic and effective!)
            immediate_block_threshold=0.95,
            
            # Suspicious tracking (3 strikes → 60min block)
            suspicious_threshold=0.70,  # Lowered to catch more threats
            suspicious_strikes_to_block=3,
            suspicious_block_duration_minutes=60,
            
            # Benign tracking (3 times → 60min whitelist)
            benign_threshold=0.30,
            benign_confirmations_to_whitelist=3,
            benign_whitelist_duration_minutes=60,
            
            # Long-term trust
            trust_threshold_days=7,
            min_good_flows=100,
            block_threshold_alerts=3,
            block_duration_hours=24,
            confidence_multiplier=1.2,
            auto_block_enabled=True
        )

        self.health_tracker = SystemHealthTracker(history_size=1000)

        # Sequential Pattern Detector (5th model!)
        self.sequential_detector = SequentialPatternDetector(
            sequence_length=100,      # Track last 100 flows per IP
            timeout_seconds=300,     # 5-minute window
            enable_detailed_logging=True
        )
        logger.info("[AutoLearner] ✅ Sequential Pattern Detector initialized (5th model!)")

        self.last_flow_id = None
        self.last_retrain_time = 0
        self.baseline_flows = []
        self.device_flows = {}
        self.device_flow_counts = {}
        # Use set for O(1) membership lookup (deque is O(n)!)
        # OrderedDict tracks insertion order for FIFO eviction
        from collections import OrderedDict
        self._seen_flow_ids_order = OrderedDict()  # Tracks order for eviction
        self._max_seen_flow_ids = 10000
        
        # Global unique flow count for initial training (sum of all device counts)
        self.global_unique_flow_count = 0
        
        # Thread pool for parallel ML processing
        self.executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ML-Worker")
        
        # Config reload tracking
        self.last_config_reload = 0
        self.config_reload_interval = 120  # Reload config every 2 minutes

    async def start(self):
        """Start the auto-learning loop."""
        logger.info("[AutoLearner] Starting AI auto-learning system...")
        logger.info(f"[AutoLearner] Training threshold: {self.training_threshold} flows")
        logger.info(f"[AutoLearner] Alert threshold: {self.alert_threshold}")
        self.load_model_if_exists()

        # Sync self-healing state from database
        if self.self_healing.use_database:
            logger.info("[AutoLearner] Syncing self-healing state from database...")
            await self.self_healing._sync_from_database()
            logger.info("[AutoLearner] Self-healing state synced successfully")

        # Load config from database IMMEDIATELY at startup (before any training)
        logger.info("[AutoLearner] Loading configuration from database at startup...")
        await self.reload_config()
        logger.info(f"[AutoLearner] ✅ Configuration loaded. Final training threshold: {self.training_threshold} flows (will train at this threshold)")

        while True:
            try:
                # Periodically reload configuration from database
                current_time = time.time()
                if current_time - self.last_config_reload > self.config_reload_interval:
                    await self.reload_config()
                    self.last_config_reload = current_time
                
                await self.process_flows()
                await asyncio.sleep(self.check_interval)
            except Exception as e:
                logger.error(f"[AutoLearner] Error: {e}")
                await asyncio.sleep(self.check_interval)

    async def reload_config(self):
        """Reload configuration from database/API (feedback loop integration)."""
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(f"{self.api_url}/self-healing/model-config") as resp:
                    if resp.status == 200:
                        config = await resp.json()

                        def extract_value(key):
                            if key not in config:
                                return None
                            entry = config[key]
                            if isinstance(entry, dict):
                                return entry.get("value")
                            return entry
                        
                        # Extract training_threshold FIRST (most important for preventing early training)
                        value = extract_value('training_threshold')
                        logger.info(f"[AutoLearner] 🔍 Extracted training_threshold: {value} (type: {type(value).__name__}), current: {self.training_threshold}")
                        if value is not None:
                            old_training = self.training_threshold
                            try:
                                new_training = int(value)
                                self.training_threshold = new_training
                                if old_training != new_training:
                                    logger.info(f"[AutoLearner] 🔧 Updated training_threshold: {old_training} → {new_training}")
                                else:
                                    logger.info(f"[AutoLearner] Training threshold unchanged: {new_training} (already correct)")
                            except (ValueError, TypeError) as e:
                                logger.error(f"[AutoLearner] ❌ Failed to convert training_threshold '{value}' to int: {e}")
                        else:
                            logger.warning(f"[AutoLearner] ⚠️ training_threshold not found in config! Available keys: {list(config.keys())}")
                        
                        value = extract_value('alert_threshold')
                        if value is not None:
                            old_threshold = self.alert_threshold
                            self.alert_threshold = float(value)
                            if abs(old_threshold - self.alert_threshold) > 0.01:
                                logger.info(f"[AutoLearner] 🔧 Updated alert_threshold: {old_threshold:.2f} → {self.alert_threshold:.2f}")
                        
                        value = extract_value('contamination_rate_global') or extract_value('contamination')
                        if value is not None:
                            old_contamination = self.anomaly_detector.contamination
                            new_contamination = float(value)
                            if abs(old_contamination - new_contamination) > 0.001:
                                self.anomaly_detector.contamination = new_contamination
                                logger.info(f"[AutoLearner] 🔧 Updated contamination: {old_contamination:.3f} → {new_contamination:.3f}")

                        value = extract_value('auto_block_threshold')
                        if value is not None:
                            new_threshold = float(value)
                            if abs(self.self_healing.immediate_block_threshold - new_threshold) > 0.001:
                                logger.info(f"[SelfHealing] Updated auto-block threshold: {self.self_healing.immediate_block_threshold:.2f} → {new_threshold:.2f}")
                                self.self_healing.immediate_block_threshold = new_threshold
                        
                        logger.info(f"[AutoLearner] ✅ Config reload complete. Current training_threshold: {self.training_threshold}")

                        value = extract_value('suspicious_threshold')
                        if value is not None:
                            new_suspicious = float(value)
                            if abs(self.self_healing.suspicious_threshold - new_suspicious) > 0.001:
                                logger.info(f"[SelfHealing] Updated suspicious threshold: {self.self_healing.suspicious_threshold:.2f} → {new_suspicious:.2f}")
                                self.self_healing.suspicious_threshold = new_suspicious

                        value = extract_value('auto_block_enabled')
                        if value is not None:
                            new_state = bool(value)
                            if self.self_healing.auto_block_enabled != new_state:
                                state = "enabled" if new_state else "disabled"
                                logger.info(f"[SelfHealing] Auto-block {state}")
                                self.self_healing.auto_block_enabled = new_state

                        value = extract_value('block_duration_minutes')
                        if value is not None:
                            minutes = max(1, int(value))
                            if minutes != self.self_healing.suspicious_block_duration_minutes:
                                logger.info(f"[SelfHealing] Updated block duration: {self.self_healing.suspicious_block_duration_minutes}m → {minutes}m")
                                self.self_healing.suspicious_block_duration_minutes = minutes
                                self.self_healing.benign_whitelist_duration_minutes = minutes
                                self.self_healing.block_duration_hours = max(1, minutes / 60)

                        logger.debug("[AutoLearner] ✅ Configuration reloaded from API")
                    else:
                        logger.debug(f"[AutoLearner] Config reload failed: HTTP {resp.status}")
        except Exception as e:
            logger.debug(f"[AutoLearner] Error reloading config: {e}")  # Don't spam errors
    
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
            flows = await self.fetch_unanalyzed_flows(session)

            if not flows or len(flows) == 0:
                logger.info("[AutoLearner] No new flows to process")
                return

            logger.info(f"[AutoLearner] Processing {len(flows)} flows")

            self.baseline_flows.extend(flows)
            if len(self.baseline_flows) > 1000:
                self.baseline_flows = self.baseline_flows[-1000:]

            self._group_flows_by_device(flows)

            await self._train_device_profiles()

            is_if_trained = self.anomaly_detector.is_trained
            logger.info(f"[AutoLearner] IF trained status: {is_if_trained}")

            if not is_if_trained:
                # Update global unique count from device counts
                self.global_unique_flow_count = sum(self.device_flow_counts.values())
                
                for _ in flows:
                    self.health_tracker.record_baseline_flow()

                logger.info(f"[AutoLearner] Collected {self.global_unique_flow_count}/{self.training_threshold} UNIQUE flows for initial training (across all devices)")

                if self.global_unique_flow_count >= self.training_threshold:
                    logger.info(f"[AutoLearner] 🎯 Threshold reached! Training global Isolation Forest with {len(self.baseline_flows[:self.training_threshold])} flows...")
                    await self.train_baseline(self.baseline_flows[:self.training_threshold])
                    self.save_model()
                    self.last_retrain_time = time.time()
                    logger.info(f"[AutoLearner] ✅ Global IF training complete. is_trained={self.anomaly_detector.is_trained}")
            else:
                logger.info(f"[AutoLearner] Models trained, analyzing {len(flows)} flows for threats...")
                await self.analyze_threats(session, flows)

                current_time = time.time()
                if current_time - self.last_retrain_time >= self.retrain_interval:
                    logger.info("[AutoLearner] Retraining model with verified safe flows...")
                    training_flows = await self.fetch_training_safe_flows(session)
                    if len(training_flows) >= 100:
                        await self.train_baseline(training_flows[-1000:])
                        self.save_model()
                        logger.info("[AutoLearner] ✓ Model retrained on verified data")
                    else:
                        logger.warning(f"[AutoLearner] Insufficient verified flows for retraining: {len(training_flows)}/100")

    def _filter_training_safe_flows(self, flows: List[Dict]) -> List[Dict]:
        """
        Filter flows safe for training.
        Only include flows that are:
        1. Verified benign (manually labeled), OR
        2. >24 hours old with no associated alerts
        """
        safe_flows = []
        current_time = time.time()

        for flow in flows:
            # Check if verified benign
            if flow.get('verified_benign') is True:
                safe_flows.append(flow)
                continue

            # Check if flow is old enough (>24 hours)
            flow_timestamp = flow.get('timestamp')
            if flow_timestamp:
                try:
                    from datetime import datetime
                    if isinstance(flow_timestamp, str):
                        flow_time = datetime.fromisoformat(flow_timestamp.replace('Z', '+00:00')).timestamp()
                    else:
                        flow_time = flow_timestamp

                    age_hours = (current_time - flow_time) / 3600

                    # If >24hrs old and not marked as training_excluded, consider safe
                    if age_hours > 24 and not flow.get('training_excluded', False):
                        safe_flows.append(flow)
                except Exception as e:
                    logger.debug(f"Could not parse flow timestamp: {e}")
                    continue

        return safe_flows

    async def fetch_unanalyzed_flows(self, session: aiohttp.ClientSession) -> List[Dict]:
        """Fetch flows that haven't been analyzed yet."""
        try:
            async with session.get(f"{self.api_url}/flows/unanalyzed") as resp:
                if resp.status == 200:
                    flows = await resp.json()
                    return flows
                else:
                    logger.error(f"[AutoLearner] Failed to fetch flows: {resp.status}")
                    return []
        except Exception as e:
            logger.error(f"[AutoLearner] Error fetching flows: {e}")
            return []

    async def fetch_training_safe_flows(self, session: aiohttp.ClientSession) -> List[Dict]:
        """Fetch flows safe for training (verified benign or >24hrs old)."""
        try:
            async with session.get(f"{self.api_url}/flows/training-safe") as resp:
                if resp.status == 200:
                    flows = await resp.json()
                    logger.info(f"[AutoLearner] Fetched {len(flows)} training-safe flows")
                    return flows
                else:
                    logger.error(f"[AutoLearner] Failed to fetch training-safe flows: {resp.status}")
                    return []
        except Exception as e:
            logger.error(f"[AutoLearner] Error fetching training-safe flows: {e}")
            return []

    def _group_flows_by_device(self, flows: List[Dict]):
        """Group flows by hostname for per-device analysis."""
        for flow in flows:
            hostname = flow.get('hostname', 'unknown')
            flow_id = flow.get('flow_id', flow.get('id'))  # Use flow_id or id
            
            # Initialize device structures if needed
            if hostname not in self.device_flows:
                self.device_flows[hostname] = []
            if hostname not in self.device_flow_counts:
                self.device_flow_counts[hostname] = 0
            
            # Only count unique flows (prevent double-counting)
            # Using OrderedDict for O(1) lookup + FIFO eviction
            if flow_id and flow_id not in self._seen_flow_ids_order:
                self.device_flow_counts[hostname] += 1
                self._seen_flow_ids_order[flow_id] = True
                
                # Evict oldest entries if over limit (FIFO)
                while len(self._seen_flow_ids_order) > self._max_seen_flow_ids:
                    self._seen_flow_ids_order.popitem(last=False)

            self.device_flows[hostname].append(flow)

            # Keep only recent flows in memory
            if len(self.device_flows[hostname]) > 200:
                self.device_flows[hostname] = self.device_flows[hostname][-200:]

        # Update baselines for all devices
        for hostname, device_flow_list in self.device_flows.items():
            self.baseline_tracker.update_baseline(hostname, device_flow_list[-50:])

    async def _train_device_profiles(self):
        """Train individual profiles for each device."""
        for hostname, flows in self.device_flows.items():
            profile_status = self.device_profiler.get_profile_status(hostname)

            if not profile_status['trained'] and len(flows) >= 25:
                try:
                    features = self.feature_extractor.extract_features_batch(flows)
                    feature_names = self.feature_extractor.get_feature_names()

                    self.device_profiler.train_device(hostname, features, feature_names)
                    logger.info(f"[AutoLearner] ✓ Trained Isolation Forest for device: {hostname} ({len(flows)} flows)")
                except Exception as e:
                    logger.error(f"[AutoLearner] Failed to train profile for {hostname}: {e}")

            autoencoder_status = self.autoencoder_detector.get_device_status(hostname)
            flow_count = self.device_flow_counts.get(hostname, len(flows))

            # Initial training: train if not trained yet and have enough flows (use training_threshold)
            if not autoencoder_status['trained'] and flow_count >= self.training_threshold:
                try:
                    logger.info(f"[AutoLearner] ⏳ Training autoencoder for {hostname} with {len(flows)} flows in memory (total flows analyzed: {flow_count}/{self.training_threshold})...")
                    features = self.feature_extractor.extract_features_batch(flows)
                    result = self.autoencoder_detector.train_device(hostname, features, epochs=30, current_flow_count=flow_count, training_threshold=self.training_threshold)

                    post_training_status = self.autoencoder_detector.get_device_status(hostname)

                    if post_training_status['trained']:
                        logger.info(f"[AutoLearner] ✅ Autoencoder TRAINED successfully for {hostname}: threshold={post_training_status.get('threshold', 0):.4f}")
                    else:
                        logger.error(f"[AutoLearner] ❌ Autoencoder training FAILED for {hostname}")
                except Exception as e:
                    logger.error(f"[AutoLearner] ❌ Failed to train autoencoder for {hostname}: {e}", exc_info=True)

            # Retraining: check if should_retrain before retraining
            elif autoencoder_status['trained']:
                # Pass the actual flow count from device_flow_counts for consistency
                should_do_retrain = self.autoencoder_detector.should_retrain(hostname, flow_count)

                if should_do_retrain:
                    try:
                        meta = self.autoencoder_detector.device_training_meta.get(hostname, {})
                        flows_since = meta.get('flows_since_training', 0)
                        days_since = meta.get('days_since_training', 0.0)
                        logger.info(f"[AutoLearner] 🔄 Retraining autoencoder for {hostname}: {flows_since} verified flows accumulated, {days_since:.1f} days since last training")

                        features = self.feature_extractor.extract_features_batch(flows)
                        result = self.autoencoder_detector.train_device(hostname, features, epochs=20, current_flow_count=flow_count)  # Use 20 epochs for retraining (incremental learning)

                        if result.get('status') == 'trained':
                            logger.info(f"[AutoLearner] ✅ Autoencoder RETRAINED for {hostname}: threshold={result.get('threshold', 0):.4f}")
                    except Exception as e:
                        logger.error(f"[AutoLearner] Failed to retrain autoencoder for {hostname}: {e}")
                else:
                    meta = self.autoencoder_detector.device_training_meta.get(hostname, {})
                    flows_since = meta.get('flows_since_training', 0)
                    days_since = meta.get('days_since_training', 0.0)
                    logger.info(f"[AutoLearner] ⏭️ Skipping retrain for {hostname}: {flows_since}/500 flows, {days_since:.1f}/7.0 days")

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
            flow_ids = [flow['id'] for flow in flows]

            result = self.anomaly_detector.train(features, feature_names, flow_ids)

            logger.info(f"[AutoLearner] ✓ Baseline trained! Model ready to detect threats.")
            logger.info(f"[AutoLearner] Features: {result['n_features']}, Samples: {result['n_samples']}")
        except Exception as e:
            logger.error(f"[AutoLearner] Training failed: {e}")

    async def analyze_threats(self, session: aiohttp.ClientSession, flows: List[Dict]):
        """Analyze flows for anomalies and create alerts with parallel processing."""
        try:
            batch_start_time = time.time()

            # Parallel feature extraction for better performance
            # Split flows into chunks for parallel processing
            chunk_size = max(1, len(flows) // 4)  # Process in 4 chunks
            flow_chunks = [flows[i:i + chunk_size] for i in range(0, len(flows), chunk_size)]
            
            # Extract features in parallel
            loop = asyncio.get_event_loop()
            feature_futures = [
                loop.run_in_executor(
                    self.executor,
                    self.feature_extractor.extract_features_batch,
                    chunk
                )
                for chunk in flow_chunks if chunk
            ]
            
            # Wait for all feature extraction to complete
            feature_chunks = await asyncio.gather(*feature_futures)
            features = np.vstack(feature_chunks) if len(feature_chunks) > 1 else feature_chunks[0]

            predictions, risk_scores = self.anomaly_detector.predict(features)

            alerts_created = 0
            whitelisted_count = 0
            trusted_skipped = 0
            blocked_skipped = 0

            for i, flow in enumerate(flows):
                flow_start_time = time.time()

                src_ip = flow.get('src_ip', '')
                hostname = flow.get('hostname', 'unknown')  # Get hostname for flow counting
                flow_id = flow.get('id')

                if flow.get('analyzed_at') is not None:
                    logger.debug(f"[AutoLearner] Skipping already analyzed flow {flow_id}")
                    continue

                await self._mark_flow_analyzed(session, flow_id)

                # Skip analysis for trusted or temporarily whitelisted IPs
                if self.self_healing.is_trusted_or_whitelisted(src_ip):
                    trusted_skipped += 1
                    self.self_healing.track_flow(flow, False, 0.0)
                    flow_time = time.time() - flow_start_time
                    self.health_tracker.record_flow_processed(flow_time, False, True, None)
                    continue

                if self.self_healing.is_blocked(src_ip):
                    blocked_skipped += 1
                    continue

                risk_score = float(risk_scores[i])
                is_anomaly = predictions[i] == -1

                votes = []

                # Vote 1: Isolation Forest (global model)
                if_confidence = self.ensemble_engine.calculate_confidence(
                    predictions[i], risk_score
                )
                votes.append(ModelVote(
                    model_name='isolation_forest',
                    is_anomaly=predictions[i],
                    confidence=if_confidence,
                    risk_score=risk_score,
                    reason="Global traffic pattern anomaly"
                ))
                self.health_tracker.record_model_prediction(
                    'isolation_forest', predictions[i], if_confidence, risk_score
                )

                # Vote 2: Device-specific profile
                device_risk_score = await self._check_device_profile(flow, features[i])
                if device_risk_score is not None:
                    device_prediction = -1 if device_risk_score > 0.7 else 1
                    device_confidence = self.ensemble_engine.calculate_confidence(
                        device_prediction, device_risk_score
                    )
                    votes.append(ModelVote(
                        model_name='device_profile',
                        is_anomaly=device_prediction,
                        confidence=device_confidence,
                        risk_score=device_risk_score,
                        reason="Device-specific behavior anomaly"
                    ))
                    self.health_tracker.record_model_prediction(
                        'device_profile', device_prediction, device_confidence, device_risk_score
                    )

                # Vote 3: Autoencoder
                autoencoder_risk = await self._check_autoencoder(flow, features[i])
                if autoencoder_risk is not None:
                    ae_prediction = -1 if autoencoder_risk > 0.7 else 1
                    ae_confidence = self.ensemble_engine.calculate_confidence(
                        ae_prediction, autoencoder_risk
                    )
                    votes.append(ModelVote(
                        model_name='autoencoder',
                        is_anomaly=ae_prediction,
                        confidence=ae_confidence,
                        risk_score=autoencoder_risk,
                        reason="Traffic reconstruction error"
                    ))
                    self.health_tracker.record_model_prediction(
                        'autoencoder', ae_prediction, ae_confidence, autoencoder_risk
                    )

                # Vote 4: Baseline deviation
                baseline_deviation = self.baseline_tracker.get_deviation_score(hostname, flow)

                if baseline_deviation > 0.3:  # Only vote if significant deviation
                    baseline_prediction = -1 if baseline_deviation > 0.6 else 1
                    baseline_confidence = self.ensemble_engine.calculate_confidence(
                        baseline_prediction, baseline_deviation
                    )
                    votes.append(ModelVote(
                        model_name='baseline_deviation',
                        is_anomaly=baseline_prediction,
                        confidence=baseline_confidence,
                        risk_score=baseline_deviation,
                        reason="Deviation from device baseline behavior"
                    ))
                    self.health_tracker.record_model_prediction(
                        'baseline_deviation', baseline_prediction, baseline_confidence, baseline_deviation
                    )

                # Sequential Pattern Detection (5th Model!)
                seq_result = self.sequential_detector.add_flow(flow)
                seq_pattern_name = None
                seq_confidence = 0.0
                pattern_description = ""
                
                if seq_result:
                    pattern_name, seq_confidence, pattern_description = seq_result
                    seq_pattern_name = pattern_name
                    seq_risk = seq_confidence  # Confidence = Risk for sequential patterns
                    
                    logger.warning(f"[AutoLearner] 🔥 Sequential Pattern: pattern={pattern_name}, confidence={seq_confidence}")
                    
                    votes.append(ModelVote(
                        model_name='sequential_pattern',
                        is_anomaly=-1,  # Detected attack pattern
                        confidence=seq_confidence,
                        risk_score=seq_risk,
                        reason=f"{pattern_name.replace('_', ' ').title()}: {pattern_description}"
                    ))
                    self.health_tracker.record_model_prediction(
                        'sequential_pattern', -1, seq_confidence, seq_risk
                    )
                    logger.info(
                        f"[AutoLearner] 🎯 Sequential detected {pattern_name} "
                        f"from {src_ip} (confidence: {seq_confidence:.0%})"
                    )

                is_ensemble_anomaly, final_risk_score, ensemble_details = self.ensemble_engine.vote(votes)

                self.self_healing.track_flow(flow, is_ensemble_anomaly, final_risk_score)

                # Classify threat type
                features_dict = self.feature_extractor.extract_features(flow)
                
                # If sequential detector detected a pattern, use that as the threat category
                if seq_pattern_name:
                    threat_category = seq_pattern_name
                    threat_confidence = seq_confidence
                    classification_reason = pattern_description
                    logger.warning(f"[AutoLearner] ✅ Using sequential pattern '{threat_category}' for {src_ip}")
                else:
                    threat_category, threat_confidence, classification_reason = self.threat_classifier.classify_threat(
                        flow, features_dict, final_risk_score
                    )
                    logger.warning(f"[AutoLearner] Using classifier threat category '{threat_category}' for {src_ip}")

                if threat_category is None:
                    whitelisted_count += 1
                    logger.debug(f"[AutoLearner] Threat category is None, skipping alert for {src_ip}")
                    flow_time = time.time() - flow_start_time
                    self.health_tracker.record_flow_processed(flow_time, False, True, ensemble_details)
                    continue

                # Only create alert if ensemble agrees AND meets threshold
                # EXCEPTION: Port scans and network scans always create alerts (critical reconnaissance)
                is_critical_pattern = seq_pattern_name in ['port_scan', 'network_scan', 'brute_force']
                
                if is_critical_pattern:
                    logger.warning(f"[AutoLearner] 🚨 Critical pattern detected: {seq_pattern_name} from {src_ip}, creating alert!")
                
                if (is_ensemble_anomaly and final_risk_score >= self.alert_threshold) or is_critical_pattern:
                    baseline_info = self.baseline_tracker.get_baseline_info(hostname)

                    ensemble_explanation = self.ensemble_engine.explain_decision(votes, ensemble_details)

                    await self._mark_flow_training_excluded(session, flow_id)

                    try:
                        await self.create_alert(
                            session, flow, final_risk_score, is_ensemble_anomaly,
                            threat_category=threat_category,
                            threat_reason=f"{classification_reason}. {ensemble_explanation}",
                            baseline_info=baseline_info,
                            ensemble_details=ensemble_details
                        )
                        alerts_created += 1
                        logger.info(f"[AutoLearner] ✅ Alert created for flow {flow_id} (risk: {final_risk_score:.2f})")
                    except Exception as alert_error:
                        logger.error(f"[AutoLearner] ❌ Failed to create alert: {alert_error}", exc_info=True)

                    flow_time = time.time() - flow_start_time
                    self.health_tracker.record_flow_processed(flow_time, True, False, ensemble_details)
                else:
                    flow_time = time.time() - flow_start_time
                    self.health_tracker.record_flow_processed(flow_time, False, False, ensemble_details)

            logger.info(f"[AutoLearner] Batch complete: {alerts_created} alerts, {whitelisted_count} whitelisted, {trusted_skipped} trusted, {blocked_skipped} blocked")

        except Exception as e:
            logger.error(f"[AutoLearner] Analysis failed: {e}", exc_info=True)

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

    async def _check_autoencoder(self, flow: Dict, features: np.ndarray) -> Optional[float]:
        """
        Check autoencoder reconstruction error for anomaly detection.
        Added autoencoder-based anomaly detection
        """
        hostname = flow.get('hostname', 'unknown')

        if not self.autoencoder_detector.is_device_trained(hostname):
            return None

        try:
            features_2d = features.reshape(1, -1)
            _, autoencoder_risk_scores = self.autoencoder_detector.predict_device(hostname, features_2d)
            return float(autoencoder_risk_scores[0])
        except Exception as e:
            logger.error(f"[AutoLearner] Autoencoder check failed for {hostname}: {e}")
            return None

    async def create_alert(
        self,
        session: aiohttp.ClientSession,
        flow: Dict,
        risk_score: float,
        is_anomaly: bool,
        threat_category: Optional[str] = None,
        threat_reason: Optional[str] = None,
        baseline_info: Optional[Dict] = None,
        ensemble_details: Optional[Dict] = None  # Added ensemble details
    ):
        """Send alert to API and recommend firewall rules."""
        try:
            self.self_healing.track_alert(flow)

            # NEW: Generate simple, human-readable explanation!
            src_ip = flow.get('src_ip', 'unknown')
            dst_ip = flow.get('dst_ip', 'unknown')
            protocol = flow.get('protocol', 'TCP')
            
            # Check if LSTM detected this
            lstm_pattern = None
            if ensemble_details and 'lstm_sequential' in ensemble_details.get('voting_models', []):
                # Extract LSTM pattern from the vote reason
                for model_info in ensemble_details.get('model_votes', []):
                    if model_info.get('model') == 'lstm_sequential':
                        reason = model_info.get('reason', '')
                        if 'Port Scan' in reason:
                            lstm_pattern = 'port_scan'
                        elif 'Network Scan' in reason or 'reconnaissance' in reason.lower():
                            lstm_pattern = 'network_scan'
                        elif 'C2' in reason or 'beacon' in reason.lower():
                            lstm_pattern = 'c2_beacon'
                        elif 'exfiltration' in reason.lower():
                            lstm_pattern = 'data_exfiltration'
                        elif 'Brute Force' in reason:
                            lstm_pattern = 'brute_force'
            
            # Generate simple, clear explanation
            full_reason = self.simple_explainer.explain_threat(
                threat_category=threat_category,
                risk_score=risk_score,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                voting_details=ensemble_details,
                lstm_pattern=lstm_pattern
            )

            severity = self.threat_classifier.get_threat_severity(threat_category, risk_score) if threat_category else self._get_severity_from_score(risk_score)

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
            
            logger.warning(f"[AutoLearner] 📤 Sending alert to API: threat_category={threat_category}, src_ip={src_ip}")

            async with session.post(
                f"{self.api_url}/alerts/create",
                json=alert
            ) as resp:
                if resp.status in [200, 201]:
                    category_str = f"[{threat_category.upper()}]" if threat_category else ""
                    brief_summary = full_reason.split('.')[0] if full_reason else "Threat detected"
                    logger.info(f"[AutoLearner] {category_str} Alert: {brief_summary}... (risk: {risk_score:.2f})")

                    alert_data = await resp.json()
                    alert_id = alert_data.get("alert_id")

                    if alert_id:
                        await self.recommend_rules_for_alert(
                            session, alert_id, flow, risk_score, full_reason
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
            src_ip = flow.get('src_ip', '')
            adjusted_risk = self.self_healing.adjust_confidence(src_ip, risk_score)

            rules = self.rule_recommender.recommend_rules(flow, adjusted_risk, reason)

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

    async def _mark_flow_analyzed(self, session: aiohttp.ClientSession, flow_id: int):
        """Mark flow as analyzed to prevent re-processing."""
        if not flow_id:
            return

        try:
            async with session.post(
                f"{self.api_url}/flows/{flow_id}/mark-analyzed",
                json={"analysis_version": 1}
            ) as resp:
                if resp.status != 200:
                    logger.warning(f"Failed to mark flow {flow_id} as analyzed (status={resp.status})")
        except Exception as e:
            logger.error(f"Error marking flow analyzed: {e}")

    async def _mark_flow_training_excluded(self, session: aiohttp.ClientSession, flow_id: int):
        """Mark flow as excluded from training (triggered alert)."""
        if not flow_id:
            return

        try:
            async with session.post(
                f"{self.api_url}/flows/{flow_id}/exclude-from-training"
            ) as resp:
                if resp.status != 200:
                    logger.warning(f"Failed to mark flow {flow_id} as training-excluded (status={resp.status})")
        except Exception as e:
            logger.error(f"Error marking flow training-excluded: {e}")

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
        training_threshold=200,  # Lowered for faster initial training
        alert_threshold=0.70,    # Lowered to 70% for better detection
        retrain_interval=3600,
        model_save_path="/app/models/anomaly_model.pkl"
    )
    await auto_learner.start()
