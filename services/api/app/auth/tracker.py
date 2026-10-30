"""
Instance tracker — lightweight telemetry to know how many live EntraGuard
deployments exist. Sends a minimal heartbeat to a central endpoint.

What is sent:
  - A stable anonymous instance ID (random, persisted in the data volume)
  - Version string
  - Uptime timestamp
  - Hostname (can be overridden or disabled)

No tenant data, no findings, no credentials are ever sent.
Opt-in: enable with TELEMETRY_ENABLED=true in .env (off by default).
"""

import os
import uuid
import asyncio
import logging
import httpx
import socket
from datetime import datetime, timezone

log = logging.getLogger(__name__)

# Default matches docker-compose.yml (false) — telemetry is opt-in.
TELEMETRY_ENABLED  = os.getenv("TELEMETRY_ENABLED", "false").lower() == "true"
TELEMETRY_ENDPOINT = os.getenv("TELEMETRY_ENDPOINT", "https://telemetry.entra-guard.app/heartbeat")
INSTANCE_NAME      = os.getenv("INSTANCE_NAME", "")
APP_VERSION        = "2.0"
INSTANCE_ID_FILE   = os.getenv("INSTANCE_ID_FILE", "/app/data/instance_id")


def _load_instance_id() -> str:
    # Previously sha256(SECRET_KEY)[:16], published on the unauthenticated
    # /health endpoint — an offline oracle for guessing a weak SECRET_KEY
    # (and thus forging JWTs). Use a random ID persisted next to users.json.
    try:
        with open(INSTANCE_ID_FILE) as f:
            existing = f.read().strip()
            if existing:
                return existing
    except OSError:
        pass
    new_id = uuid.uuid4().hex[:16]
    try:
        os.makedirs(os.path.dirname(INSTANCE_ID_FILE), exist_ok=True)
        with open(INSTANCE_ID_FILE, "w") as f:
            f.write(new_id)
    except OSError as e:
        log.debug(f"Could not persist instance id (non-critical): {e}")
    return new_id


INSTANCE_ID = _load_instance_id()

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
