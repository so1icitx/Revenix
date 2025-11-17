from fastapi import FastAPI
from pydantic import BaseModel
from typing import List, Dict
from .features import FlowFeatureExtractor

app = FastAPI()

# Initialize feature extractor
feature_extractor = FlowFeatureExtractor()

class Flow(BaseModel):
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

@app.get("/health")
def health():
    return {"status": "Revenix Brain OK"}

@app.post("/extract_features")
def extract_features(flow: Flow):
    """
    Extract ML features from a single network flow.
    Returns feature dictionary with calculated metrics.
    """
    flow_dict = flow.dict()
    features = feature_extractor.extract_features(flow_dict)

    return {
        "features": features,
        "feature_names": feature_extractor.get_feature_names()
    }

@app.post("/extract_features_batch")
def extract_features_batch(flows: List[Flow]):
    """
    Extract features from multiple flows.
    Returns 2D array of features ready for ML model.
    """
    flow_dicts = [f.dict() for f in flows]
    features_array = feature_extractor.extract_features_batch(flow_dicts)

    return {
        "features": features_array.tolist(),
        "feature_names": feature_extractor.get_feature_names(),
        "n_flows": len(flows),
        "n_features": len(feature_extractor.get_feature_names())
    }
