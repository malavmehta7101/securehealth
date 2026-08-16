"""Recent telemetry readings for the SecureHealth dashboard.

Sits behind the same Cognito authorizer as the patient API, so the existing
staff accounts apply. Equipment readings are operational data rather than
PHI, so every authenticated role may view them - unlike clinical fields,
there is nothing here to redact.
"""
import json
import os
from datetime import datetime, timezone

import boto3

dynamodb = boto3.resource("dynamodb")
table = dynamodb.Table(os.environ["TELEMETRY_TABLE"])
MIN_SAFE_C = float(os.environ.get("MIN_SAFE_C", 2))
MAX_SAFE_C = float(os.environ.get("MAX_SAFE_C", 8))

DEFAULT_DEVICE = "securehealth-fridge-01"
MAX_LIMIT = 200

HEADERS = {
    "Content-Type": "application/json",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
}


def response(status, body):
    return {"statusCode": status, "headers": HEADERS, "body": json.dumps(body, default=str)}


def handler(event, _context):
    claims = (event.get("requestContext") or {}).get("authorizer", {}).get("claims", {})
    user = claims.get("cognito:username", "unknown")

    params = event.get("queryStringParameters") or {}

    device_id = (params.get("device") or DEFAULT_DEVICE).strip()
    if len(device_id) > 64:
        return response(400, {"error": "validation_failed", "message": "Invalid device id."})

    try:
        limit = int(params.get("limit", 50))
    except ValueError:
        return response(400, {"error": "validation_failed", "message": "limit must be a number."})
    limit = max(1, min(limit, MAX_LIMIT))

    result = table.query(
        KeyConditionExpression="device_id = :d",
        ExpressionAttributeValues={":d": device_id},
        ScanIndexForward=False,          # newest first
        Limit=limit,
    )
    readings = result.get("Items", [])

    latest = readings[0] if readings else None
    breaches = sum(1 for r in readings if not r.get("in_range", True))

    status = "unknown"
    if latest:
        age = (datetime.now(timezone.utc)
               - datetime.fromisoformat(latest["reading_time"])).total_seconds()
        if age > 900:
            status = "stale"          # no reading in 15 minutes: the device may be offline
        else:
            status = "ok" if latest.get("in_range") else "alert"

    print(json.dumps({
        "event": "TELEMETRY_READ", "user": user,
        "device_id": device_id, "returned": len(readings),
    }))

    return response(200, {
        "device_id": device_id,
        "status": status,
        "safe_range_c": {"min": MIN_SAFE_C, "max": MAX_SAFE_C},
        "latest": latest,
        "breaches_in_window": breaches,
        "count": len(readings),
        "readings": readings,
    })
