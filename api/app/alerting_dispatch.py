import asyncio
import json
import logging
import os
import smtplib
import ssl
from datetime import datetime
from email.message import EmailMessage
from typing import Any

import httpx
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)

_SMTP_CONFIG_KEYS = {
    "smtp_host",
    "smtp_port",
    "smtp_username",
    "smtp_password",
    "smtp_use_tls",
    "smtp_use_ssl",
    "from",
    "to",
    "routing_key",
}


def _parse_json_value(value: Any, default: Any):
    if value is None:
        return default
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str):
        try:
            return json.loads(value)
        except Exception:
            return default
    return default


def _normalize_headers(raw_headers: Any) -> dict:
    parsed = _parse_json_value(raw_headers, {})
    if not isinstance(parsed, dict):
        return {}
    return parsed


def _normalize_events(raw_events: Any) -> set[str]:
    parsed = _parse_json_value(raw_events, ["critical", "high"])
    if isinstance(parsed, str):
        parsed = [parsed]
    if not isinstance(parsed, list):
        parsed = ["critical", "high"]
    normalized = {str(event).strip().lower() for event in parsed if str(event).strip()}
    return normalized or {"critical", "high"}


def _matches_event(subscribed_events: set[str], event_name: str) -> bool:
    if not subscribed_events:
        return False
    event = (event_name or "").strip().lower()
    return event in subscribed_events or "*" in subscribed_events or "all" in subscribed_events


def _to_http_headers(headers: dict) -> dict[str, str]:
    http_headers: dict[str, str] = {}
    for key, value in (headers or {}).items():
        k = str(key).strip()
        if not k:
            continue
        if k.lower() in _SMTP_CONFIG_KEYS:
            continue
        http_headers[k] = str(value)
    return http_headers


def _is_http_url(url: str) -> bool:
    return url.startswith("http://") or url.startswith("https://")


def _to_float(value: Any) -> float | None:
    try:
        if value is None:
            return None
        return float(value)
    except Exception:
        return None


def _coerce_bool(value: Any, default: bool = False) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "y", "on"}


def _pagerduty_severity(severity: str) -> str:
    normalized = (severity or "info").lower()
    if normalized == "critical":
        return "critical"
    if normalized == "high":
        return "error"
    if normalized == "medium":
        return "warning"
    return "info"


def _compose_alert_message(alert: dict) -> str:
    severity = str(alert.get("severity", "unknown")).upper()
    src_ip = alert.get("src_ip", "unknown")
    dst_ip = alert.get("dst_ip", "unknown")
    category = alert.get("threat_category", "UNKNOWN")
    reason = alert.get("reason", "No reason provided")
    risk_score = _to_float(alert.get("risk_score"))
    risk_text = f"{risk_score:.2f}" if risk_score is not None else "n/a"
    hostname = alert.get("hostname", "unknown")

    return (
        f"[REVENIX {severity}] Threat detected\n"
        f"Source: {src_ip}\n"
        f"Destination: {dst_ip}\n"
        f"Host: {hostname}\n"
        f"Category: {category}\n"
        f"Risk Score: {risk_text}\n"
        f"Reason: {reason}"
    )


def _base_event_payload(alert: dict) -> dict:
    return {
        "event": str(alert.get("severity", "info")).lower(),
        "alert": {
            "id": alert.get("id"),
            "flow_id": alert.get("flow_id"),
            "hostname": alert.get("hostname"),
            "src_ip": alert.get("src_ip"),
            "dst_ip": alert.get("dst_ip"),
            "src_port": alert.get("src_port"),
            "dst_port": alert.get("dst_port"),
            "protocol": alert.get("protocol"),
            "risk_score": alert.get("risk_score"),
            "severity": alert.get("severity"),
            "reason": alert.get("reason"),
            "threat_category": alert.get("threat_category"),
            "timestamp": alert.get("timestamp"),
        },
    }


def create_test_alert_payload() -> dict:
    now_iso = datetime.utcnow().isoformat() + "Z"
    return {
        "id": None,
        "flow_id": "test-alert",
        "hostname": "revenix-test",
        "src_ip": "198.51.100.23",
        "dst_ip": "192.168.1.10",
        "src_port": 44321,
        "dst_port": 443,
        "protocol": "TCP",
        "risk_score": 0.95,
        "severity": "critical",
        "reason": "This is a Revenix test alert notification",
        "threat_category": "TEST",
        "timestamp": now_iso,
    }


def _resolve_recipients(url: str, headers: dict) -> list[str]:
    recipients: list[str] = []
    header_to = headers.get("to")
    if isinstance(header_to, list):
        recipients.extend([str(item).strip() for item in header_to if str(item).strip()])
    elif isinstance(header_to, str):
        recipients.extend([entry.strip() for entry in header_to.split(",") if entry.strip()])

    normalized_url = (url or "").strip()
    if normalized_url.startswith("mailto:"):
        mailto_value = normalized_url[len("mailto:"):].strip()
        recipients.extend([entry.strip() for entry in mailto_value.split(",") if entry.strip()])
    elif "@" in normalized_url and "://" not in normalized_url:
        recipients.append(normalized_url)

    unique: list[str] = []
    seen: set[str] = set()
    for recipient in recipients:
        lowered = recipient.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        unique.append(recipient)
    return unique


def _send_smtp_email_sync(
    smtp_host: str,
    smtp_port: int,
    smtp_username: str | None,
    smtp_password: str | None,
    smtp_use_tls: bool,
    smtp_use_ssl: bool,
    sender: str,
    recipients: list[str],
    subject: str,
    body: str,
) -> None:
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = ", ".join(recipients)
    message.set_content(body)

    if smtp_use_ssl:
        context = ssl.create_default_context()
        with smtplib.SMTP_SSL(smtp_host, smtp_port, context=context, timeout=15) as server:
            if smtp_username:
                server.login(smtp_username, smtp_password or "")
            server.send_message(message)
        return

    with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
        if smtp_use_tls:
            context = ssl.create_default_context()
            server.starttls(context=context)
        if smtp_username:
            server.login(smtp_username, smtp_password or "")
        server.send_message(message)


async def _send_email_alert(url: str, headers: dict, alert: dict) -> tuple[bool, int | None, str | None]:
    if _is_http_url(url):
        payload = _base_event_payload(alert)
        payload["subject"] = f"[Revenix] {str(alert.get('severity', 'info')).upper()} alert"
        payload["message"] = _compose_alert_message(alert)
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url,
                    json=payload,
                    headers=_to_http_headers(headers),
                    timeout=10.0,
                )
            return 200 <= response.status_code < 300, response.status_code, None
        except Exception as exc:
            return False, None, str(exc)

    recipients = _resolve_recipients(url, headers)
    if not recipients:
        return False, None, "No recipient email configured (use mailto:address or plain address)"

    smtp_host = str(headers.get("smtp_host") or os.getenv("SMTP_HOST") or "").strip()
    smtp_port_raw = headers.get("smtp_port") or os.getenv("SMTP_PORT") or 587
    try:
        smtp_port = int(smtp_port_raw)
    except Exception:
        smtp_port = 587
    smtp_username = str(headers.get("smtp_username") or os.getenv("SMTP_USERNAME") or "").strip() or None
    smtp_password = str(headers.get("smtp_password") or os.getenv("SMTP_PASSWORD") or "").strip() or None
    smtp_use_tls = _coerce_bool(headers.get("smtp_use_tls"), _coerce_bool(os.getenv("SMTP_USE_TLS"), True))
    smtp_use_ssl = _coerce_bool(headers.get("smtp_use_ssl"), _coerce_bool(os.getenv("SMTP_USE_SSL"), False))
    sender = str(headers.get("from") or os.getenv("SMTP_FROM") or "revenix@localhost").strip()

    if not smtp_host:
        return False, None, "SMTP_HOST is not configured for email delivery"

    subject = f"[Revenix] {str(alert.get('severity', 'info')).upper()} alert"
    body = _compose_alert_message(alert)
    try:
        await asyncio.to_thread(
            _send_smtp_email_sync,
            smtp_host,
            smtp_port,
            smtp_username,
            smtp_password,
            smtp_use_tls,
            smtp_use_ssl,
            sender,
            recipients,
            subject,
            body,
        )
        return True, 200, None
    except Exception as exc:
        return False, None, str(exc)


async def send_alert_to_webhook(url: str, webhook_type: str, headers: Any, alert: dict) -> tuple[bool, int | None, str | None]:
    normalized_headers = _normalize_headers(headers)
    normalized_type = (webhook_type or "webhook").strip().lower()

    if normalized_type == "email":
        return await _send_email_alert(url, normalized_headers, alert)

    payload = _base_event_payload(alert)
    message = _compose_alert_message(alert)

    if normalized_type == "slack":
        payload = {"text": message, "username": "Revenix Security"}
    elif normalized_type == "discord":
        payload = {"content": message}
    elif normalized_type == "pagerduty":
        routing_key = str(normalized_headers.get("routing_key") or os.getenv("PAGERDUTY_ROUTING_KEY") or "").strip()
        if not routing_key:
            return False, None, "PagerDuty routing_key missing in webhook headers"
        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "payload": {
                "summary": message[:1024],
                "severity": _pagerduty_severity(str(alert.get("severity", "info"))),
                "source": str(alert.get("hostname") or alert.get("src_ip") or "revenix"),
                "custom_details": _base_event_payload(alert)["alert"],
            },
        }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json=payload,
                headers=_to_http_headers(normalized_headers),
                timeout=10.0,
            )
        success = 200 <= response.status_code < 300
        error = None if success else f"HTTP {response.status_code}"
        return success, response.status_code, error
    except Exception as exc:
        return False, None, str(exc)


async def dispatch_alert_notifications(session: AsyncSession, alert: dict) -> dict:
    """
    Dispatch a persisted alert to all enabled integrations that match the alert severity.
    This function is non-critical: failures are logged and should not break alert creation.
    """
    alert_event = str(alert.get("severity", "info")).strip().lower()
    alert_id = alert.get("id")

    summary = {
        "attempted": 0,
        "sent": 0,
        "failed": 0,
        "matched_integrations": 0,
    }

    try:
        result = await session.execute(
            text("""
                SELECT id, name, url, type, events, headers
                FROM alerting_webhooks
                WHERE enabled = TRUE
                ORDER BY id ASC
            """)
        )
        rows = result.fetchall()
    except Exception as exc:
        logger.error(f"[Alerting] Failed loading integrations: {exc}")
        return summary

    for row in rows:
        webhook_id, _name, url, webhook_type, events, headers = row
        subscribed_events = _normalize_events(events)
        if not _matches_event(subscribed_events, alert_event):
            continue

        summary["matched_integrations"] += 1
        summary["attempted"] += 1
        success = False
        response_code: int | None = None
        error_message: str | None = None

        try:
            success, response_code, error_message = await send_alert_to_webhook(
                str(url),
                str(webhook_type),
                headers,
                alert,
            )
        except Exception as exc:
            success = False
            error_message = str(exc)

        if success:
            summary["sent"] += 1
        else:
            summary["failed"] += 1

        try:
            await session.execute(
                text("""
                    UPDATE alerting_webhooks
                    SET
                        last_triggered_at = NOW(),
                        trigger_count = trigger_count + 1,
                        last_error = :last_error,
                        updated_at = NOW()
                    WHERE id = :webhook_id
                """),
                {
                    "webhook_id": webhook_id,
                    "last_error": None if success else (error_message or "delivery failed"),
                },
            )
        except Exception as exc:
            logger.warning(f"[Alerting] Failed updating webhook stats for {webhook_id}: {exc}")

        try:
            await session.execute(
                text("""
                    INSERT INTO alert_notifications (alert_id, webhook_id, status, response_code, error_message)
                    VALUES (:alert_id, :webhook_id, :status, :response_code, :error_message)
                """),
                {
                    "alert_id": alert_id,
                    "webhook_id": webhook_id,
                    "status": "sent" if success else "failed",
                    "response_code": response_code,
                    "error_message": None if success else error_message,
                },
            )
        except Exception as exc:
            logger.warning(f"[Alerting] Failed writing notification log for webhook {webhook_id}: {exc}")

    try:
        await session.commit()
    except Exception as exc:
        logger.warning(f"[Alerting] Failed committing notification updates: {exc}")
        try:
            await session.rollback()
        except Exception:
            pass

    return summary
