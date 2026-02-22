"""
FEEDBACK LOOP SYSTEM
Phase 1 Week 1 Day 5-7: Learning from User Feedback

This system implements continuous learning by:
1. Processing user feedback on AI decisions (false positives, missed threats)
2. Dynamically adjusting detection thresholds based on feedback patterns
3. Tracking rule effectiveness and auto-disabling bad rules
4. Updating model contamination rates per device type
"""

import logging
import asyncio
from typing import Dict, List, Optional
from collections import defaultdict
import aiohttp
import time
from .internal_api import get_api_base_url, get_internal_headers

logger = logging.getLogger(__name__)

API_URL = get_api_base_url()
INTERNAL_HEADERS = get_internal_headers()

class FeedbackLoopSystem:
    """
    Processes user feedback to improve AI decision-making.
    Implements dynamic threshold adjustment and rule management.
    """
    
    def __init__(
        self,
        sync_interval: int = 300,  # Check for feedback every 5 minutes
        min_samples_for_adjustment: int = 10,
        adjustment_rate: float = 0.05,  # Max 5% adjustment per cycle
        rule_deprecation_threshold: float = 0.3  # Deprecate rules with effectiveness < 30%
    ):
        self.sync_interval = sync_interval
        self.min_samples_for_adjustment = min_samples_for_adjustment
        self.adjustment_rate = adjustment_rate
        self.rule_deprecation_threshold = rule_deprecation_threshold
        
        # Track feedback statistics
        self.feedback_stats = {
            'false_positives': 0,
            'missed_threats': 0,
            'correct_detections': 0,
            'severity_corrections': 0,
            'category_corrections': 0
        }
        
        # Track threshold adjustments
        self.current_thresholds = {
            'global_contamination': 0.01,
            'alert_threshold': 0.85,
            'servers_contamination': 0.005,
            'iot_contamination': 0.02,
            'workstations_contamination': 0.015
        }
        
        logger.info("[FeedbackLoop] Feedback loop system initialized")
        logger.info(f"[FeedbackLoop] Min samples for adjustment: {min_samples_for_adjustment}")
        logger.info(f"[FeedbackLoop] Adjustment rate: {adjustment_rate * 100}%")
    
    async def fetch_recent_feedback(self, hours: int = 24) -> List[Dict]:
        """Fetch recent feedback from the database."""
        try:
            async with aiohttp.ClientSession(headers=INTERNAL_HEADERS) as session:
                # We'll add this endpoint to the API
                async with session.get(f"{API_URL}/self-healing/feedback/recent?hours={hours}") as resp:
                    if resp.status == 200:
                        return await resp.json()
                    else:
                        logger.error(f"[FeedbackLoop] Failed to fetch feedback: HTTP {resp.status}")
                        return []
        except Exception as e:
            logger.error(f"[FeedbackLoop] Error fetching feedback: {e}")
            return []
    
    async def fetch_model_config(self) -> Dict:
        """Fetch current model configuration from database."""
        try:
            async with aiohttp.ClientSession(headers=INTERNAL_HEADERS) as session:
                async with session.get(f"{API_URL}/self-healing/model-config") as resp:
                    if resp.status == 200:
                        config = await resp.json()
                        # Extract values
                        return {
                            'global_contamination': config.get('contamination_rate_global', {}).get('value', 0.01),
                            'servers_contamination': config.get('contamination_rate_servers', {}).get('value', 0.005),
                            'iot_contamination': config.get('contamination_rate_iot', {}).get('value', 0.02),
                            'workstations_contamination': config.get('contamination_rate_workstations', {}).get('value', 0.015),
                            'alert_threshold': config.get('alert_threshold', {}).get('value', 0.85)
                        }
                    return {}
        except Exception as e:
            logger.error(f"[FeedbackLoop] Error fetching model config: {e}")
            return {}
    
    async def update_model_config(self, config_key: str, new_value: float):
        """Update a model configuration value."""
        try:
            async with aiohttp.ClientSession(headers=INTERNAL_HEADERS) as session:
                async with session.post(
                    f"{API_URL}/self-healing/model-config/{config_key}",
                    params={"new_value": str(new_value), "updated_by": "feedback_loop"}
                ) as resp:
                    if resp.status == 200:
                        logger.info(f"[FeedbackLoop] ✓ Updated {config_key} to {new_value}")
                        return True
                    else:
                        logger.error(f"[FeedbackLoop] Failed to update {config_key}: HTTP {resp.status}")
                        return False
        except Exception as e:
            logger.error(f"[FeedbackLoop] Error updating model config: {e}")
            return False
    
    async def analyze_feedback_patterns(self, feedback_list: List[Dict]) -> Dict:
        """
        Analyze feedback patterns to determine if threshold adjustments are needed.
        
        Returns:
        {
            'false_positive_rate': float,
            'missed_threat_rate': float,
            'accuracy': float,
            'suggested_adjustments': dict
        }
        """
        if not feedback_list:
            return {'false_positive_rate': 0.0, 'missed_threat_rate': 0.0, 'accuracy': 0.0}
        
        # Count feedback types
        false_positives = sum(1 for f in feedback_list if f['feedback_type'] == 'false_positive')
        missed_threats = sum(1 for f in feedback_list if f['feedback_type'] == 'missed_threat')
        correct = sum(1 for f in feedback_list if f['feedback_type'] == 'correct')
        
        total_feedback = len(feedback_list)
        
        false_positive_rate = false_positives / total_feedback
        missed_threat_rate = missed_threats / total_feedback
        accuracy = correct / total_feedback
        
        logger.info(f"[FeedbackLoop] Feedback analysis (last 24h):")
        logger.info(f"[FeedbackLoop]   False Positives: {false_positives} ({false_positive_rate*100:.1f}%)")
        logger.info(f"[FeedbackLoop]   Missed Threats: {missed_threats} ({missed_threat_rate*100:.1f}%)")
        logger.info(f"[FeedbackLoop]   Correct: {correct} ({accuracy*100:.1f}%)")
        
        suggested_adjustments = {}
        
        # If too many false positives, increase contamination (make model less sensitive)
        if false_positive_rate > 0.15 and total_feedback >= self.min_samples_for_adjustment:
            current_contamination = self.current_thresholds.get('global_contamination', 0.01)
            adjustment = min(current_contamination * self.adjustment_rate, 0.005)  # Max +0.5% per cycle
            suggested_adjustments['global_contamination'] = current_contamination + adjustment
            logger.warning(f"[FeedbackLoop] ⚠️ High false positive rate detected!")
            logger.info(f"[FeedbackLoop] Suggesting contamination increase: {current_contamination:.4f} -> {suggested_adjustments['global_contamination']:.4f}")
        
        # If too many missed threats, decrease contamination (make model more sensitive)
        if missed_threat_rate > 0.10 and total_feedback >= self.min_samples_for_adjustment:
            current_contamination = self.current_thresholds.get('global_contamination', 0.01)
            adjustment = min(current_contamination * self.adjustment_rate, 0.005)
            suggested_adjustments['global_contamination'] = max(0.001, current_contamination - adjustment)
            logger.warning(f"[FeedbackLoop] ⚠️ High missed threat rate detected!")
            logger.info(f"[FeedbackLoop] Suggesting contamination decrease: {current_contamination:.4f} -> {suggested_adjustments['global_contamination']:.4f}")
        
        # Adjust alert threshold if needed
        if false_positive_rate > 0.20:
            current_threshold = self.current_thresholds.get('alert_threshold', 0.85)
            suggested_adjustments['alert_threshold'] = min(0.95, current_threshold + 0.02)
            logger.info(f"[FeedbackLoop] Suggesting alert threshold increase: {current_threshold:.2f} -> {suggested_adjustments['alert_threshold']:.2f}")
        
        if missed_threat_rate > 0.15:
            current_threshold = self.current_thresholds.get('alert_threshold', 0.85)
            suggested_adjustments['alert_threshold'] = max(0.70, current_threshold - 0.02)
            logger.info(f"[FeedbackLoop] Suggesting alert threshold decrease: {current_threshold:.2f} -> {suggested_adjustments['alert_threshold']:.2f}")
        
        return {
            'false_positive_rate': false_positive_rate,
            'missed_threat_rate': missed_threat_rate,
            'accuracy': accuracy,
            'total_feedback': total_feedback,
            'suggested_adjustments': suggested_adjustments
        }
    
    async def apply_threshold_adjustments(self, adjustments: Dict):
        """Apply suggested threshold adjustments to the system."""
        if not adjustments:
            logger.info("[FeedbackLoop] No adjustments needed")
            return
        
        logger.info(f"[FeedbackLoop] 🔧 Applying {len(adjustments)} threshold adjustments...")
        
        for config_key, new_value in adjustments.items():
            success = await self.update_model_config(config_key, new_value)
            if success:
                self.current_thresholds[config_key] = new_value
        
        logger.info("[FeedbackLoop] ✅ Threshold adjustments applied successfully")
    
    async def evaluate_rule_effectiveness(self) -> List[Dict]:
        """
        Evaluate firewall rule effectiveness and identify underperforming rules.
        
        Returns list of rules that should be deprecated.
        """
        try:
            async with aiohttp.ClientSession(headers=INTERNAL_HEADERS) as session:
                # Fetch rule effectiveness data
                async with session.get(f"{API_URL}/self-healing/rule-effectiveness") as resp:
                    if resp.status == 200:
                        rules = await resp.json()
                    else:
                        return []
                
                # Identify underperforming rules
                to_deprecate = []
                for rule in rules:
                    effectiveness = rule.get('effectiveness_score', 0.5)
                    times_triggered = rule.get('times_triggered', 0)
                    
                    # Only deprecate rules that have been triggered enough times to be statistically significant
                    if times_triggered >= 20 and effectiveness < self.rule_deprecation_threshold:
                        to_deprecate.append(rule)
                        logger.warning(
                            f"[FeedbackLoop] 🗑️ Marking rule #{rule['rule_id']} for deprecation: "
                            f"effectiveness={effectiveness:.2f}, triggered={times_triggered}"
                        )
                
                # Deprecate bad rules
                for rule in to_deprecate:
                    await session.post(
                        f"{API_URL}/self-healing/rules/{rule['rule_id']}/deprecate"
                    )
                
                if to_deprecate:
                    logger.info(f"[FeedbackLoop] Deprecated {len(to_deprecate)} underperforming rules")
                
                return to_deprecate
        
        except Exception as e:
            logger.error(f"[FeedbackLoop] Error evaluating rule effectiveness: {e}")
            return []
    
    async def process_feature_feedback(self, feedback_list: List[Dict]):
        """
        Analyze which features contribute to false positives/negatives.
        Update feature importance scores in the database.
        """
        try:
            # Group feedback by feature patterns
            feature_feedback = defaultdict(lambda: {'fp': 0, 'tp': 0, 'fn': 0})
            
            for feedback in feedback_list:
                features_at_time = feedback.get('features_at_time', {})
                feedback_type = feedback['feedback_type']
                
                for feature_name, feature_value in features_at_time.items():
                    if feedback_type == 'false_positive':
                        feature_feedback[feature_name]['fp'] += 1
                    elif feedback_type == 'correct':
                        feature_feedback[feature_name]['tp'] += 1
                    elif feedback_type == 'missed_threat':
                        feature_feedback[feature_name]['fn'] += 1
            
            # Update feature feedback in database
            async with aiohttp.ClientSession(headers=INTERNAL_HEADERS) as session:
                for feature_name, counts in feature_feedback.items():
                    await session.post(
                        f"{API_URL}/self-healing/feature-feedback/update",
                        json={
                            "feature_name": feature_name,
                            "false_positive_count": counts['fp'],
                            "true_positive_count": counts['tp'],
                            "false_negative_count": counts['fn']
                        }
                    )
            
            logger.info(f"[FeedbackLoop] Updated feature feedback for {len(feature_feedback)} features")
        
        except Exception as e:
            logger.error(f"[FeedbackLoop] Error processing feature feedback: {e}")
    
    async def run_feedback_loop(self):
        """
        Main feedback loop: continuously process feedback and adjust thresholds.
        """
        logger.info("[FeedbackLoop] 🔄 Starting continuous feedback loop...")
        
        cycle_count = 0
        while True:
            try:
                cycle_count += 1
                logger.info(f"[FeedbackLoop] ===== Feedback Loop Cycle #{cycle_count} =====")
                
                # Fetch current configuration
                config = await self.fetch_model_config()
                if config:
                    self.current_thresholds.update(config)
                
                # Fetch recent feedback (last 24 hours)
                feedback_list = await self.fetch_recent_feedback(hours=24)
                
                if not feedback_list:
                    logger.info("[FeedbackLoop] No recent feedback to process")
                else:
                    logger.info(f"[FeedbackLoop] Processing {len(feedback_list)} feedback entries")
                    
                    # Analyze feedback patterns
                    analysis = await self.analyze_feedback_patterns(feedback_list)
                    
                    # Apply threshold adjustments if needed
                    if analysis.get('suggested_adjustments'):
                        await self.apply_threshold_adjustments(analysis['suggested_adjustments'])
                    
                    # Process feature feedback
                    await self.process_feature_feedback(feedback_list)
                
                # Evaluate rule effectiveness
                await self.evaluate_rule_effectiveness()
                
                logger.info(f"[FeedbackLoop] Cycle #{cycle_count} complete. Next cycle in {self.sync_interval}s")
                await asyncio.sleep(self.sync_interval)
            
            except Exception as e:
                logger.error(f"[FeedbackLoop] Error in feedback loop: {e}")
                import traceback
                traceback.print_exc()
                await asyncio.sleep(self.sync_interval)
    
    def get_stats(self) -> Dict:
        """Get feedback loop statistics."""
        return {
            'feedback_stats': self.feedback_stats,
            'current_thresholds': self.current_thresholds
        }


# Global instance
feedback_loop_system = None

async def start_feedback_loop_system():
    """Start the feedback loop system."""
    global feedback_loop_system
    
    feedback_loop_system = FeedbackLoopSystem(
        sync_interval=300,  # 5 minutes
        min_samples_for_adjustment=10,
        adjustment_rate=0.05  # 5% max adjustment
    )
    
    await feedback_loop_system.run_feedback_loop()

def get_feedback_loop_system() -> FeedbackLoopSystem:
    """Get the global feedback loop system instance."""
    return feedback_loop_system
