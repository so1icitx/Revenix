import os
from typing import Optional

DEFAULT_API_BASE_URL = "http://api:8000"
API_BASE_URL = os.environ.get("API_BASE_URL", DEFAULT_API_BASE_URL).rstrip("/")
INTERNAL_SERVICE_TOKEN = os.environ.get("INTERNAL_SERVICE_TOKEN", "").strip()


def get_api_base_url() -> str:
    return API_BASE_URL


def get_internal_headers(extra_headers: Optional[dict[str, str]] = None) -> dict[str, str]:
    headers: dict[str, str] = {}
    if INTERNAL_SERVICE_TOKEN:
        headers["X-Internal-Token"] = INTERNAL_SERVICE_TOKEN
    if extra_headers:
        headers.update(extra_headers)
    return headers
