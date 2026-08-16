"""Telemetry ingest — the first code that runs after the device trust boundary.

AWS IoT Core has already proven the device holds a valid certificate and is
publishing to a topic its policy permits. That authenticates the *connection*;
it says nothing about whether the payload is sensible. This function therefore
treats every field as untrusted input, exactly as the patient API does:
validate first, store second, alert third.
"""
import json
import os
import time
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
sns = boto3.client("sns")

table = dynamodb.Table(os.environ["TELEMETRY_TABLE"])
ALERT_TOPIC = os.environ["ALERT_TOPIC"]
MIN_SAFE_C = float(os.environ.get("MIN_SAFE_C", 2))
MAX_SAFE_C = float(os.environ.get("MAX_SAFE_C", 8))

RETENTION_DAYS = 30

# A DHT11 cannot physically report outside roughly this band. A reading beyond
# it means a faulty sensor or a forged payload, not a real refrigerator.
PLAUSIBLE_C = (-40.0, 80.0)
PLAUSIBLE_RH = (0.0, 100.0)

DEVICE_ID_MAX = 64


class RejectedReading(Exception):
    """Payload failed validation; it is logged and dropped, never stored."""


def log_event(event, **fields):
    """One structured line per event, parsed by CloudWatch metric filters."""
    print(json.dumps({"event": event, **fields}))


def validate(payload, device_id):
    if not isinstance(payload, dict):
        raise RejectedReading("payload is not an object")

    if not device_id or len(device_id) > DEVICE_ID_MAX:
        raise RejectedReading("missing or oversized device id")

    if "temperature_c" not in payload:
        raise RejectedReading("temperature_c absent")

    try:
        temperature = float(payload["temperature_c"])
    except (TypeError, ValueError):
        raise RejectedReading("temperature_c is not numeric")

    if not PLAUSIBLE_C[0] <= temperature <= PLAUSIBLE_C[1]:
        raise RejectedReading("temperature_c outside physically plausible range")

    humidity = None
    if payload.get("humidity_pct") is not None:
        try:
            humidity = float(payload["humidity_pct"])
        except (TypeError, ValueError):
            raise RejectedReading("humidity_pct is not numeric")
        if not PLAUSIBLE_RH[0] <= humidity <= PLAUSIBLE_RH[1]:
            raise RejectedReading("humidity_pct outside plausible range")

    return temperature, humidity


def handler(event, _context):
    # topic(3) in the IoT rule puts the device name here. It comes from the
    # topic the device was authorised to publish on, not from the payload —
    # so a device cannot claim to be a different unit by editing its JSON.
    device_id = str(event.get("device_id", "")).strip()

    try:
        temperature, humidity = validate(event, device_id)
    except RejectedReading as exc:
        log_event("TELEMETRY_REJECTED", device_id=device_id or "unknown", reason=str(exc))
        return {"status": "rejected", "reason": str(exc)}

    now = datetime.now(timezone.utc)
    in_range = MIN_SAFE_C <= temperature <= MAX_SAFE_C

    item = {
        "device_id": device_id,
        "reading_time": now.isoformat(),
        "temperature_c": str(temperature),
        "in_range": in_range,
        "expires_at": int(time.time()) + RETENTION_DAYS * 86400,
    }
    if humidity is not None:
        item["humidity_pct"] = str(humidity)

    try:
        table.put_item(Item=item)
    except ClientError as exc:
        print(f"[STORE-FAIL] {device_id}: {exc}")
        return {"status": "error"}

    if in_range:
        log_event("TELEMETRY_OK", device_id=device_id, temperature_c=temperature)
        return {"status": "ok", "in_range": True}

    direction = "above" if temperature > MAX_SAFE_C else "below"
    log_event("TELEMETRY_ALERT", device_id=device_id,
              temperature_c=temperature, direction=direction)

    try:
        sns.publish(
            TopicArn=ALERT_TOPIC,
            Subject=f"SecureHealth: {device_id} out of range",
            Message=(
                f"Storage unit {device_id} reported {temperature:.1f} C at "
                f"{now.isoformat()}, which is {direction} the safe range of "
                f"{MIN_SAFE_C:.0f}-{MAX_SAFE_C:.0f} C.\n\n"
                "Check the unit before the contents are compromised."
            ),
        )
    except ClientError as exc:                      # alerting must not lose the reading
        print(f"[ALERT-FAIL] {device_id}: {exc}")

    return {"status": "ok", "in_range": False}
