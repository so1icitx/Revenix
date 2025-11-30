from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Dict
from .features import FlowFeatureExtractor
from .anomaly_detector import AnomalyDetector
from .device_profiler import DeviceProfiler  # Import device profiler
from .baseline_tracker import BaselineTracker  # Import baseline tracker
import numpy as np
import asyncio

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
baseline_tracker = BaselineTracker(save_dir="/app/models/baselines")  # Initialize baseline tracker

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
def list_device_profiles():
    """List all device behavior profiles."""
    profiles = device_profiler.list_profiles()

    # Enrich with baseline data
    for profile in profiles:
        hostname = profile['hostname']
        baseline_info = baseline_tracker.get_baseline_info(hostname)
        if baseline_info:
            profile['baseline'] = {
                'avg_bytes_per_flow': baseline_info.get('avg_bytes_per_flow', 0),
                'avg_packets_per_flow': baseline_info.get('avg_packets_per_flow', 0),
                'common_destinations_count': len(baseline_info.get('common_destinations', {})),
                'common_ports_count': len(baseline_info.get('common_ports', {}))
            }

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

    return status

@app.get("/devices/{hostname}/baseline")
def get_device_baseline(hostname: str):
    """Get behavioral baseline for specific device."""
    baseline_info = baseline_tracker.get_baseline_info(hostname)
    if not baseline_info:
        raise HTTPException(status_code=404, detail=f"No baseline found for {hostname}")
    return baseline_info
