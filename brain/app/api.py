from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator, Field
from typing import List, Dict, Optional
import logging
import re
import ipaddress
from .features import FlowFeatureExtractor
from .anomaly_detector import AnomalyDetector
from .device_profiler import DeviceProfiler
from .baseline_tracker import BaselineTracker
from .autoencoder_detector import AutoencoderDetector
from .auth import get_current_user, get_optional_user, require_role, is_public_endpoint
from .rate_limiter import RateLimitMiddleware  # Import rate limiter
import numpy as np
import asyncio

from . import auto_learner as auto_learner_module

app = FastAPI(
    title="Revenix Brain API",
    description="ML-powered threat detection engine",
    version="1.0.0"
)

app.add_middleware(RateLimitMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
feature_extractor = FlowFeatureExtractor()
anomaly_detector = AnomalyDetector(contamination=0.1)
device_profiler = DeviceProfiler(save_dir="/app/models/profiles")
baseline_tracker = BaselineTracker(save_dir="/app/models/baselines")
autoencoder_detector = AutoencoderDetector(save_dir="/app/models/autoencoders")

logger = logging.getLogger(__name__)


class Flow(BaseModel):
    flow_id: str = ""
    packets: int = Field(..., ge=0, le=10000000)  # Reasonable limits
    bytes: int = Field(..., ge=0, le=10000000000)  # 10GB max
    start_ts: float = Field(..., ge=0)
    end_ts: float = Field(..., ge=0)
    src_port: int = Field(..., ge=0, le=65535)
    dst_port: int = Field(..., ge=0, le=65535)
    protocol: str
    src_ip: str = ""
    dst_ip: str = ""
    hostname: str = ""
    
    @validator('protocol')
    def validate_protocol(cls, v):
        allowed = {'tcp', 'udp', 'icmp', 'TCP', 'UDP', 'ICMP', '6', '17', '1'}
        if v not in allowed:
            raise ValueError(f'Protocol must be one of: tcp, udp, icmp')
        return v.lower() if v.isalpha() else v
    
    @validator('src_ip', 'dst_ip')
    def validate_ip(cls, v):
        if v:  # Only validate if not empty
            try:
                ipaddress.ip_address(v)
            except ValueError:
                raise ValueError(f'Invalid IP address: {v}')
        return v
    
    @validator('hostname')
    def validate_hostname(cls, v):
        if v and len(v) > 255:
            raise ValueError('Hostname too long (max 255 chars)')
        # Basic sanitization - alphanumeric, dots, hyphens only
        if v and not re.match(r'^[a-zA-Z0-9.-]+$', v):
            raise ValueError('Hostname contains invalid characters')
        return v


class TrainingRequest(BaseModel):
    flows: List[Flow]

class PredictionResponse(BaseModel):
    flow_id: str
    is_anomaly: bool
    risk_score: float
    features: Dict[str, float]


@app.on_event("startup")
async def startup_event():
    """Start the auto-learning, firewall sync, and feedback loop background tasks."""
    from .auto_learner import start_auto_learner
    from .firewall_manager import start_firewall_manager
    from .feedback_loop import start_feedback_loop_system
    
    asyncio.create_task(start_auto_learner(anomaly_detector, feature_extractor, device_profiler))
    asyncio.create_task(start_firewall_manager())
    asyncio.create_task(start_feedback_loop_system())


# =============================================================================
# PUBLIC ENDPOINTS (No authentication required)
# =============================================================================

@app.get("/health")
def health():
    """Health check endpoint - no auth required"""
    return {
        "status": "Revenix Brain OK",
        "model_trained": anomaly_detector.is_trained
    }

@app.get("/devices/profiles")
async def get_device_profiles():
    """Get device profiles with baseline and autoencoder information."""
    active_autoencoder = auto_learner_module.auto_learner.autoencoder_detector if auto_learner_module.auto_learner else autoencoder_detector
    active_auto_learner = auto_learner_module.auto_learner

    profiles = []
    global_if_trained = active_auto_learner.anomaly_detector.is_trained if active_auto_learner else anomaly_detector.is_trained
    global_training_threshold = active_auto_learner.training_threshold if active_auto_learner else 500
    global_unique_flows = active_auto_learner.global_unique_flow_count if active_auto_learner else 0
    device_if_training_threshold = 25

    # Include all known devices, not just already-trained profiles.
    hostnames = set(device_profiler.profiles.keys())
    hostnames.update(active_autoencoder.device_models.keys())
    if active_auto_learner:
        hostnames.update(active_auto_learner.device_flow_counts.keys())
        hostnames.update(active_auto_learner.device_flows.keys())

    for hostname in sorted(hostnames):
        profile_status = device_profiler.get_profile_status(hostname)
        baseline_info = baseline_tracker.get_baseline_info(hostname)
        autoencoder_status = active_autoencoder.get_device_status(hostname)
        total_flows_for_device = active_auto_learner.device_flow_counts.get(hostname, 0) if active_auto_learner else 0
        device_if_trained = bool(profile_status.get("trained", False))

        training_progress = {
            "isolation_forest": {
                "status": "trained" if device_if_trained else "collecting_baseline",
                "current_flows": total_flows_for_device,
                "required_flows": device_if_training_threshold,
                "trained": device_if_trained
            },
            "autoencoder": {
                "status": "not_started",
                "current_flows": total_flows_for_device,
                "required_flows": global_training_threshold,
                "trained": False
            },
            # Keep global model progress visible to avoid confusion.
            "global_isolation_forest": {
                "status": "trained" if global_if_trained else "collecting_baseline",
                "current_flows": global_unique_flows,
                "required_flows": global_training_threshold,
                "trained": global_if_trained
            },
            "lstm_sequential": {
                "status": "active",
                "patterns_detected": ["port_scan", "network_scan", "c2_beacon", "data_exfiltration", "brute_force"],
                "trained": True
            }
        }

        if autoencoder_status.get('trained'):
            flows_since, days_since = active_autoencoder.get_training_status(hostname)
            training_progress["autoencoder"] = {
                "status": "trained_monitoring_for_retrain",
                "current_flows": flows_since,
                "required_flows": global_training_threshold,
                "trained": True,
                "days_since_training": round(days_since, 1),
                "version": autoencoder_status.get('version', 1)
            }
        elif hostname in active_autoencoder.device_models:
            training_progress["autoencoder"] = {
                "status": "training",
                "trained": False
            }

        profile = {
            "hostname": hostname,
            "trained": device_if_trained,
            "global_model_trained": global_if_trained,
            "flow_count": total_flows_for_device,
            "baseline": baseline_info,
            "autoencoder": autoencoder_status,
            "training_progress": training_progress
        }
        profiles.append(profile)

    total_system_flows = sum(active_auto_learner.device_flow_counts.values()) if active_auto_learner else 0
    global_current_flows = global_unique_flows if global_unique_flows > 0 else total_system_flows
    
    return {
        "profiles": profiles,
        "total_devices": len(hostnames),
        "totalFlows": total_system_flows,
        "global_training": {
            "trained": global_if_trained,
            "current_flows": global_current_flows,
            "required_flows": global_training_threshold
        }
    }


# =============================================================================
# PROTECTED ENDPOINTS (Authentication required)
# =============================================================================

@app.post("/admin/reload-config")
async def admin_reload_config(user: dict = Depends(require_role("admin"))):
    """Force auto-learner to reload dynamic config. Requires admin role."""
    try:
        if auto_learner_module.auto_learner:
            await auto_learner_module.auto_learner.reload_config()
            logger.info(f"[Auth] Config reloaded by user: {user.get('username', 'unknown')}")
            return {"status": "reloaded"}
        return {"status": "auto_learner_not_ready"}
    except Exception as exc:
        logger.error(f"[Admin] Failed to reload config: {exc}")
        raise HTTPException(status_code=500, detail="Failed to reload config")


@app.post("/extract_features")
def extract_features(flow: Flow, user: dict = Depends(get_current_user)):
    """Extract ML features from a single network flow."""
    flow_dict = flow.dict()
    features = feature_extractor.extract_features(flow_dict)
    return {
        "features": features,
        "feature_names": feature_extractor.get_feature_names()
    }


@app.post("/extract_features_batch")
def extract_features_batch(flows: List[Flow], user: dict = Depends(get_current_user)):
    """Extract features from multiple flows."""
    flow_dicts = [f.dict() for f in flows]
    features_array = feature_extractor.extract_features_batch(flow_dicts)
    return {
        "features": features_array.tolist(),
        "feature_names": feature_extractor.get_feature_names(),
        "n_flows": len(flows),
        "n_features": len(feature_extractor.get_feature_names())
    }


@app.post("/train")
def train_model(request: TrainingRequest, user: dict = Depends(require_role("admin"))):
    """
    Train anomaly detection model on baseline traffic.
    Requires admin role.
    """
    if len(request.flows) < 10:
        raise HTTPException(
            status_code=400,
            detail="Need at least 10 flows to train model"
        )

    flow_dicts = [f.dict() for f in request.flows]
    features = feature_extractor.extract_features_batch(flow_dicts)
    feature_names = feature_extractor.get_feature_names()
    flow_ids = list(range(len(features)))  # Generate flow IDs for training tracking
    result = anomaly_detector.train(features, feature_names, flow_ids)
    
    logger.info(f"[Auth] Model trained by user: {user.get('username', 'unknown')}")

    return {
        "status": "success",
        "message": f"Model trained on {len(request.flows)} flows",
        **result
    }


@app.post("/predict", response_model=List[PredictionResponse])
def predict_anomalies(flows: List[Flow], user: dict = Depends(get_current_user)):
    """
    Analyze flows and detect anomalies.
    Returns risk scores and anomaly predictions.
    """
    if not anomaly_detector.is_trained:
        raise HTTPException(
            status_code=400,
            detail="Model not trained. Call /train first with baseline flows."
        )

    if len(flows) == 0:
        return []

    flow_dicts = [f.dict() for f in flows]
    features = feature_extractor.extract_features_batch(flow_dicts)
    predictions, risk_scores = anomaly_detector.predict(features)

    results = []
    for i, flow in enumerate(flows):
        flow_features = feature_extractor.extract_features(flow.dict())
        results.append(PredictionResponse(
            flow_id=flow.flow_id or f"flow-{i}",
            is_anomaly=bool(predictions[i] == -1),
            risk_score=float(risk_scores[i]),
            features=flow_features
        ))

    return results


@app.get("/model/status")
def model_status(user: dict = Depends(get_current_user)):
    """Get current model training status."""
    return {
        "is_trained": anomaly_detector.is_trained,
        "n_features": len(anomaly_detector.feature_names) if anomaly_detector.is_trained else 0,
        "feature_names": anomaly_detector.feature_names if anomaly_detector.is_trained else []
    }


@app.get("/devices/{hostname}/profile")
def get_device_profile(hostname: str, user: dict = Depends(get_current_user)):
    """Get training status for specific device."""
    status = device_profiler.get_profile_status(hostname)
    if not status['exists']:
        raise HTTPException(status_code=404, detail=f"No profile found for {hostname}")

    baseline_info = baseline_tracker.get_baseline_info(hostname)
    if baseline_info:
        status['baseline'] = baseline_info

    autoencoder_status = autoencoder_detector.get_device_status(hostname)
    status['autoencoder'] = autoencoder_status

    return status


@app.get("/devices/{hostname}/baseline")
def get_device_baseline(hostname: str, user: dict = Depends(get_current_user)):
    """Get behavioral baseline for specific device."""
    baseline_info = baseline_tracker.get_baseline_info(hostname)
    if not baseline_info:
        raise HTTPException(status_code=404, detail=f"No baseline found for {hostname}")
    return baseline_info


@app.get("/autoencoders/status")
def get_autoencoders_status(user: dict = Depends(get_current_user)):
    """Get status of all trained autoencoders."""
    devices = autoencoder_detector.get_all_devices()

    statuses = []
    for hostname in devices:
        status = autoencoder_detector.get_device_status(hostname)
        statuses.append({
            "hostname": hostname,
            **status
        })

    return {
        "trained_devices": len(devices),
        "autoencoders": statuses
    }


@app.get("/autoencoders/{hostname}")
def get_device_autoencoder(hostname: str, user: dict = Depends(get_current_user)):
    """Get autoencoder details for specific device."""
    status = autoencoder_detector.get_device_status(hostname)

    if not status['trained']:
        raise HTTPException(
            status_code=404,
            detail=f"No trained autoencoder for device: {hostname}"
        )

    return {
        "hostname": hostname,
        **status
    }


@app.get("/self-healing/stats")
def get_self_healing_stats(user: dict = Depends(get_current_user)):
    """Get self-healing system statistics."""
    if not auto_learner_module.auto_learner:
        raise HTTPException(status_code=503, detail="Auto-learner not initialized")

    stats = auto_learner_module.auto_learner.self_healing.get_stats()
    return stats


@app.get("/self-healing/trusted")
def get_trusted_ips(user: dict = Depends(get_current_user)):
    """Get list of auto-whitelisted trusted IPs."""
    if not auto_learner_module.auto_learner:
        raise HTTPException(status_code=503, detail="Auto-learner not initialized")

    trusted = auto_learner_module.auto_learner.self_healing.get_trusted_ips()
    return {
        "trusted_ips": trusted,
        "count": len(trusted)
    }


@app.get("/self-healing/blocked")
def get_blocked_ips(user: dict = Depends(get_current_user)):
    """Get list of auto-blocked IPs with expiration times."""
    if not auto_learner_module.auto_learner:
        raise HTTPException(status_code=503, detail="Auto-learner not initialized")

    blocked = auto_learner_module.auto_learner.self_healing.get_blocked_ips()
    return {
        "blocked_ips": blocked,
        "count": len(blocked)
    }


@app.get("/system/health")
def get_system_health(user: dict = Depends(get_current_user)):
    """Get comprehensive system health score and metrics."""
    if not auto_learner_module.auto_learner:
        raise HTTPException(status_code=503, detail="Auto-learner not initialized")

    health = auto_learner_module.auto_learner.health_tracker.calculate_health_score()
    stats = auto_learner_module.auto_learner.health_tracker.get_statistics()

    return {
        "health": health,
        "statistics": stats
    }


@app.get("/system/metrics")
def get_system_metrics(user: dict = Depends(get_current_user)):
    """Get detailed system metrics for monitoring."""
    if not auto_learner_module.auto_learner:
        raise HTTPException(status_code=503, detail="Auto-learner not initialized")

    stats = auto_learner_module.auto_learner.health_tracker.get_statistics()
    return stats
