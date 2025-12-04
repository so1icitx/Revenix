from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict
from .features import FlowFeatureExtractor
from .anomaly_detector import AnomalyDetector
from .device_profiler import DeviceProfiler  # Import device profiler
from .baseline_tracker import BaselineTracker  # Import baseline tracker
from .autoencoder_detector import AutoencoderDetector  # Added autoencoder import
import numpy as np
import asyncio

from . import auto_learner as auto_learner_module

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins in development
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize components
feature_extractor = FlowFeatureExtractor()
anomaly_detector = AnomalyDetector(contamination=0.1)
device_profiler = DeviceProfiler(save_dir="/app/models/profiles")
baseline_tracker = BaselineTracker(save_dir="/app/models/baselines")
autoencoder_detector = AutoencoderDetector(save_dir="/app/models/autoencoders")  # Initialize autoencoder detector

class Flow(BaseModel):
    flow_id: str = ""
    packets: int
    bytes: int
    start_ts: float
    end_ts: float
    src_port: int
    dst_port: int
    protocol: str
    src_ip: str = ""
    dst_ip: str = ""
    hostname: str = ""

class TrainingRequest(BaseModel):
    flows: List[Flow]

class PredictionResponse(BaseModel):
    flow_id: str
    is_anomaly: bool
    risk_score: float
    features: Dict[str, float]

@app.on_event("startup")
async def startup_event():
    """Start the auto-learning background task."""
    from .auto_learner import start_auto_learner
    asyncio.create_task(start_auto_learner(anomaly_detector, feature_extractor, device_profiler))

@app.get("/health")
def health():
    return {
        "status": "Revenix Brain OK",
        "model_trained": anomaly_detector.is_trained
    }

@app.post("/extract_features")
def extract_features(flow: Flow):
    """Extract ML features from a single network flow."""
    flow_dict = flow.dict()
    features = feature_extractor.extract_features(flow_dict)

    return {
        "features": features,
        "feature_names": feature_extractor.get_feature_names()
    }

@app.post("/extract_features_batch")
def extract_features_batch(flows: List[Flow]):
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
def train_model(request: TrainingRequest):
    """
    Train anomaly detection model on baseline traffic.
    Use normal traffic flows to establish baseline behavior.
    """
    if len(request.flows) < 10:
        raise HTTPException(
            status_code=400,
            detail="Need at least 10 flows to train model"
        )

    # Extract features from flows
    flow_dicts = [f.dict() for f in request.flows]
    features = feature_extractor.extract_features_batch(flow_dicts)
    feature_names = feature_extractor.get_feature_names()

    # Train model
    result = anomaly_detector.train(features, feature_names)

    return {
        "status": "success",
        "message": f"Model trained on {len(request.flows)} flows",
        **result
    }

@app.post("/predict", response_model=List[PredictionResponse])
def predict_anomalies(flows: List[Flow]):
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

    # Extract features
    flow_dicts = [f.dict() for f in flows]
    features = feature_extractor.extract_features_batch(flow_dicts)

    # Predict anomalies
    predictions, risk_scores = anomaly_detector.predict(features)

    # Build response
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
def model_status():
    """Get current model training status."""
    return {
        "is_trained": anomaly_detector.is_trained,
        "n_features": len(anomaly_detector.feature_names) if anomaly_detector.is_trained else 0,
        "feature_names": anomaly_detector.feature_names if anomaly_detector.is_trained else []
    }

@app.get("/devices/profiles")
async def get_device_profiles():
    """
    Get device profiles with baseline and autoencoder information.
    """
    active_autoencoder = auto_learner_module.auto_learner.autoencoder_detector if auto_learner_module.auto_learner else autoencoder_detector

    profiles = []

    for hostname in device_profiler.profiles.keys():
        profile_status = device_profiler.get_profile_status(hostname)
        baseline_info = baseline_tracker.get_baseline_info(hostname)

        autoencoder_status = active_autoencoder.get_device_status(hostname)

        profile = {
            "hostname": hostname,
            "trained": profile_status.get('trained', False),  # Isolation Forest trained status
            "flow_count": profile_status.get('flow_count', 0),
            "baseline": baseline_info,
            "autoencoder": autoencoder_status
        }
        profiles.append(profile)

    return {
        "profiles": profiles,
        "total_devices": len(device_profiler.profiles)
    }

@app.get("/devices/{hostname}/profile")
def get_device_profile(hostname: str):
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
def get_device_baseline(hostname: str):
    """Get behavioral baseline for specific device."""
    baseline_info = baseline_tracker.get_baseline_info(hostname)
    if not baseline_info:
        raise HTTPException(status_code=404, detail=f"No baseline found for {hostname}")
    return baseline_info

@app.get("/autoencoders/status")
def get_autoencoders_status():
    """
    Get status of all trained autoencoders.
    """
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
def get_device_autoencoder(hostname: str):
    """
    Get autoencoder details for specific device.
    """
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
