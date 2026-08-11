"""SecureHealth audit log reader — Admin only.

GET /audit?limit=n&day=YYYY-MM-DD

The audit table is append-only by design: no handler in this application
exposes an update or delete path, and the Lambda roles hold write-only
permissions on it.
"""
from datetime import datetime, timezone

import common as c


def handler(event, _context):
    username, role = c.get_identity(event)

    if role is None:
        c.write_audit(username, role, "AUDIT_READ", "DENIED_NO_ROLE")
        return c.error(403, "forbidden", "No role assigned to this account.")

    # Only Admin may read the audit trail — attempts by others are themselves audited.
    if not c.is_allowed(role, "audit:read"):
        c.write_audit(username, role, "AUDIT_READ", "DENIED_ROLE")
        return c.error(403, "forbidden", "Only administrators may view the audit log.")

    params = event.get("queryStringParameters") or {}

    try:
        limit = int(params.get("limit", 50))
    except ValueError:
        return c.error(400, "validation_failed", "Parameter 'limit' must be a number.")
    limit = max(1, min(limit, 200))

    day = params.get("day") or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    if not c.DATE_RE.match(day):
        return c.error(400, "validation_failed", "Parameter 'day' must be YYYY-MM-DD.")

    resp = c.audit_table.query(
        KeyConditionExpression="#d = :day",
        ExpressionAttributeNames={"#d": "day"},
        ExpressionAttributeValues={":day": day},
        ScanIndexForward=False,          # newest first
        Limit=limit,
    )
    events = resp.get("Items", [])

    c.write_audit(username, role, "AUDIT_READ", "OK", detail=f"{len(events)} entries for {day}")
    return c.ok({"day": day, "count": len(events), "events": events})
