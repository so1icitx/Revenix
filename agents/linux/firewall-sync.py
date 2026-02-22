#!/usr/bin/env python3
"""
Revenix Linux firewall sync sidecar.

Continuously syncs blocked IPs from API `/self-healing/blocked-ips` into
local nftables or iptables rules so endpoint blocking is enforced on agent hosts.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import shutil
import signal
import subprocess
import sys
import time
from typing import Iterable
from urllib import error, request

LOGGER = logging.getLogger("revenix-firewall-sync")

RUNNING = True


def parse_bool_env(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def parse_int_env(name: str, default: int, minimum: int = 1, maximum: int = 3600) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        return default
    return max(minimum, min(value, maximum))


def run_cmd(args: list[str], *, check: bool = False, timeout: int = 10) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=check,
    )


def has_command(command: str) -> bool:
    return shutil.which(command) is not None


def detect_backend(override: str) -> str:
    if override in {"simulation", "nftables", "iptables"}:
        return override
    if has_command("nft"):
        return "nftables"
    if has_command("iptables"):
        return "iptables"
    return "simulation"


def init_nftables() -> bool:
    run_cmd(["nft", "add", "table", "inet", "revenix"], check=False)
    run_cmd(
        ["nft", "add", "set", "inet", "revenix", "blocked_ips", "{ type ipv4_addr; flags interval; }"],
        check=False,
    )
    run_cmd(
        ["nft", "add", "chain", "inet", "revenix", "input", "{ type filter hook input priority 0; policy accept; }"],
        check=False,
    )
    run_cmd(
        ["nft", "add", "chain", "inet", "revenix", "output", "{ type filter hook output priority 0; policy accept; }"],
        check=False,
    )
    run_cmd(
        ["nft", "add", "rule", "inet", "revenix", "input", "ip", "saddr", "@blocked_ips", "counter", "drop"],
        check=False,
    )
    run_cmd(
        ["nft", "add", "rule", "inet", "revenix", "output", "ip", "daddr", "@blocked_ips", "counter", "drop"],
        check=False,
    )
    result = run_cmd(["nft", "list", "set", "inet", "revenix", "blocked_ips"], check=False)
    return result.returncode == 0


def init_iptables() -> bool:
    run_cmd(["iptables", "-N", "REVENIX_SYNC"], check=False)

    for chain in ("INPUT", "OUTPUT"):
        exists = run_cmd(["iptables", "-C", chain, "-j", "REVENIX_SYNC"], check=False)
        if exists.returncode != 0:
            run_cmd(["iptables", "-I", chain, "-j", "REVENIX_SYNC"], check=False)

    result = run_cmd(["iptables", "-L", "REVENIX_SYNC"], check=False)
    return result.returncode == 0


def apply_nftables_rules(blocked_ips: Iterable[str]) -> bool:
    flush = run_cmd(["nft", "flush", "set", "inet", "revenix", "blocked_ips"], check=False)
    if flush.returncode != 0:
        LOGGER.error("Failed to flush nftables set: %s", (flush.stderr or "").strip())
        return False

    success = True
    for ip in sorted(blocked_ips):
        result = run_cmd(
            ["nft", "add", "element", "inet", "revenix", "blocked_ips", f"{{ {ip} }}"],
            check=False,
        )
        if result.returncode != 0:
            success = False
            LOGGER.error("Failed to add nftables element %s: %s", ip, (result.stderr or "").strip())
    return success


def apply_iptables_rules(blocked_ips: Iterable[str]) -> bool:
    flush = run_cmd(["iptables", "-F", "REVENIX_SYNC"], check=False)
    if flush.returncode != 0:
        LOGGER.error("Failed to flush REVENIX_SYNC chain: %s", (flush.stderr or "").strip())
        return False

    success = True
    for ip in sorted(blocked_ips):
        inbound = run_cmd(["iptables", "-A", "REVENIX_SYNC", "-s", ip, "-j", "DROP"], check=False)
        outbound = run_cmd(["iptables", "-A", "REVENIX_SYNC", "-d", ip, "-j", "DROP"], check=False)
        if inbound.returncode != 0 or outbound.returncode != 0:
            success = False
            LOGGER.error(
                "Failed to add iptables rules for %s: inbound=%s outbound=%s",
                ip,
                (inbound.stderr or "").strip(),
                (outbound.stderr or "").strip(),
            )
    return success


def build_headers(internal_token: str, bearer_token: str) -> dict[str, str]:
    headers = {"Accept": "application/json"}
    if internal_token:
        headers["X-Internal-Token"] = internal_token
    elif bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"
    return headers


def fetch_blocked_ips(api_url: str, headers: dict[str, str]) -> set[str] | None:
    url = f"{api_url}/self-healing/blocked-ips"
    req = request.Request(url, headers=headers, method="GET")
    try:
        with request.urlopen(req, timeout=15) as resp:
            if resp.status != 200:
                LOGGER.error("Blocked IP fetch failed with HTTP %s", resp.status)
                return None
            body = resp.read().decode("utf-8")
    except error.HTTPError as exc:
        LOGGER.error("Blocked IP fetch failed with HTTP %s", exc.code)
        return None
    except error.URLError as exc:
        LOGGER.error("Blocked IP fetch error: %s", exc.reason)
        return None
    except Exception as exc:  # noqa: BLE001
        LOGGER.error("Blocked IP fetch error: %s", exc)
        return None

    try:
        payload = json.loads(body)
    except json.JSONDecodeError as exc:
        LOGGER.error("Blocked IP response is not valid JSON: %s", exc)
        return None

    if not isinstance(payload, list):
        LOGGER.error("Blocked IP response is not a list")
        return None

    blocked: set[str] = set()
    for entry in payload:
        if not isinstance(entry, dict):
            continue
        ip_value = str(entry.get("ip", "")).strip()
        if not ip_value:
            continue
        try:
            ip_obj = ipaddress.ip_address(ip_value)
        except ValueError:
            continue
        if ip_obj.version == 4:
            blocked.add(str(ip_obj))
    return blocked


def handle_signal(_: int, __) -> None:  # type: ignore[no-untyped-def]
    global RUNNING
    RUNNING = False


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    api_url = os.environ.get("API_URL", "http://localhost:8000").rstrip("/")
    sync_enabled = parse_bool_env("FIREWALL_SYNC_ENABLED", True)
    sync_interval = parse_int_env("FIREWALL_SYNC_INTERVAL", 30, minimum=5, maximum=3600)
    backend_override = os.environ.get("FIREWALL_BACKEND", "auto").strip().lower()
    internal_token = os.environ.get("INTERNAL_SERVICE_TOKEN", "").strip()
    bearer_token = os.environ.get("API_BEARER_TOKEN", "").strip()
    headers = build_headers(internal_token, bearer_token)

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    if not sync_enabled:
        LOGGER.info("FIREWALL_SYNC_ENABLED=false, exiting firewall sync process.")
        return 0

    backend = detect_backend(backend_override)
    LOGGER.info("Selected firewall backend: %s", backend)
    LOGGER.info("Sync interval: %ss", sync_interval)
    LOGGER.info("API URL: %s", api_url)

    if backend == "nftables":
        if not init_nftables():
            LOGGER.warning("nftables initialization failed, switching to simulation mode.")
            backend = "simulation"
    elif backend == "iptables":
        if not init_iptables():
            LOGGER.warning("iptables initialization failed, switching to simulation mode.")
            backend = "simulation"
    else:
        LOGGER.warning("No supported firewall backend available, running in simulation mode.")

    last_applied_count = -1

    while RUNNING:
        blocked_ips = fetch_blocked_ips(api_url, headers)
        if blocked_ips is not None:
            if backend == "nftables":
                if apply_nftables_rules(blocked_ips):
                    if len(blocked_ips) != last_applied_count:
                        LOGGER.info("Applied %d blocked IPs via nftables.", len(blocked_ips))
                    last_applied_count = len(blocked_ips)
            elif backend == "iptables":
                if apply_iptables_rules(blocked_ips):
                    if len(blocked_ips) != last_applied_count:
                        LOGGER.info("Applied %d blocked IPs via iptables.", len(blocked_ips))
                    last_applied_count = len(blocked_ips)
            else:
                if len(blocked_ips) != last_applied_count:
                    LOGGER.info("[Simulation] API currently reports %d blocked IPs.", len(blocked_ips))
                last_applied_count = len(blocked_ips)

        for _ in range(sync_interval):
            if not RUNNING:
                break
            time.sleep(1)

    LOGGER.info("Firewall sync stopping.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
