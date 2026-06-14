"""
Instance tracker — lightweight telemetry to know how many live EntraGuard
deployments exist. Sends a minimal heartbeat to a central endpoint.

What is sent:
  - A stable anonymous instance ID (SHA256 hash of SECRET_KEY — no secrets exposed)
  - Version string
  - Uptime timestamp
  - Hostname (can be overridden or disabled)

No tenant data, no findings, no credentials are ever sent.
Disable entirely with TELEMETRY_ENABLED=false in .env
"""

import os
import hashlib
import asyncio
import logging
import httpx
import socket
from datetime import datetime, timezone

log = logging.getLogger(__name__)

TELEMETRY_ENABLED  = os.getenv("TELEMETRY_ENABLED", "true").lower() == "true"
TELEMETRY_ENDPOINT = os.getenv("TELEMETRY_ENDPOINT", "https://telemetry.entra-guard.app/heartbeat")
SECRET_KEY         = os.getenv("SECRET_KEY", "changeme")
INSTANCE_NAME      = os.getenv("INSTANCE_NAME", "")
APP_VERSION        = "2.0"

# Stable anonymous ID — hash of secret key, never the key itself
INSTANCE_ID = hashlib.sha256(SECRET_KEY.encode()).hexdigest()[:16]

# Track startup time
_started_at = datetime.now(timezone.utc).isoformat()


async def send_heartbeat():
    """Send a minimal heartbeat to the telemetry endpoint"""
    if not TELEMETRY_ENABLED:
        return

    payload = {
        "instance_id": INSTANCE_ID,
        "version": APP_VERSION,
        "started_at": _started_at,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "instance_name": INSTANCE_NAME or "",
        "hostname": socket.gethostname() if os.getenv("TELEMETRY_INCLUDE_HOSTNAME", "false").lower() == "true" else "",
    }

    try:
        async with httpx.AsyncClient() as client:
            await client.post(TELEMETRY_ENDPOINT, json=payload, timeout=5)
        log.debug(f"Heartbeat sent: instance_id={INSTANCE_ID}")
    except Exception as e:
        log.debug(f"Heartbeat failed (non-critical): {e}")


async def heartbeat_loop():
    """Send heartbeat every 6 hours"""
    await asyncio.sleep(5)  # Wait for app to fully start
    while True:
        await send_heartbeat()
        await asyncio.sleep(6 * 3600)


def get_instance_info() -> dict:
    """Return instance info for the /health endpoint"""
    return {
        "instance_id": INSTANCE_ID,
        "version": APP_VERSION,
        "started_at": _started_at,
        "telemetry_enabled": TELEMETRY_ENABLED,
        "instance_name": INSTANCE_NAME or "EntraGuard",
    }
