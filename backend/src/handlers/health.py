"""SecureHealth /health handler.

Phase 1 gate: proves the full security path works end-to-end -
API Gateway rejects unauthenticated calls (401 before this code ever runs),
and for valid tokens this function extracts the caller's role from Cognito
group claims and writes an audit event. Every later handler follows the
same three steps: identify -> authorize -> audit.
"""
import json
import os
import uuid
from datetime import datetime, timezone

import boto3

dynamodb = boto3.resource("dynamodb")
audit_table = dynamodb.Table(os.environ["AUDIT_TABLE"])

KNOWN_ROLES = ("Admin", "Doctor", "Receptionist")


def get_identity(event):
    """Extract username and role from the Cognito authorizer claims.

    Never trust request headers or body for identity - only the validated
    JWT claims that API Gateway's Cognito authorizer injects.
    """
    claims = (event.get("requestContext", {}) or {}).get("authorizer", {}).get("claims", {})
    username = claims.get("cognito:username", "unknown")
    groups = claims.get("cognito:groups", "")
    if isinstance(groups, str):
        groups = [g.strip() for g in groups.split(",") if g.strip()]
    # Deny-by-default: a user in no known group gets role None -> handlers must refuse.
    role = next((r for r in KNOWN_ROLES if r in groups), None)
    return username, role


def write_audit(username, role, action, outcome, patient_id=None):
    now = datetime.now(timezone.utc)
    item = {
        "day": now.strftime("%Y-%m-%d"),
        "event_time": f"{now.isoformat()}#{uuid.uuid4().hex[:8]}",
        "user": username,
        "role": role or "NONE",
        "action": action,
        "outcome": outcome,
    }
    if patient_id:
        item["patient_id"] = patient_id
    audit_table.put_item(Item=item)


def response(status, body):
    return {
        "statusCode": status,
        "headers": {
            "Content-Type": "application/json",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Cache-Control": "no-store",
        },
        "body": json.dumps(body),
    }


def handler(event, _context):
    username, role = get_identity(event)
    if role is None:
        write_audit(username, role, "HEALTH_CHECK", "DENIED_NO_ROLE")
        return response(403, {"error": "forbidden", "message": "No role assigned to this account."})

    write_audit(username, role, "HEALTH_CHECK", "OK")
    return response(200, {
        "service": "securehealth",
        "status": "ok",
        "user": username,
        "role": role,
    })
