"""SecureHealth shared security module.

Every handler follows the same pipeline:
    identify() -> authorize() -> validate() -> act -> audit()

Design note (encryption): clinical fields are encrypted with AES-256-GCM by AWS
KMS using the project's customer-managed key. The plaintext key never leaves
KMS, and the Lambda role is granted only Encrypt/Decrypt on that one key. This
also keeps the deployment dependency-free (boto3 ships in the Lambda runtime),
so `sam build` needs no native wheels.
"""
import base64
import hashlib
import json
import os
import re
import uuid
from datetime import datetime, date, timezone

import boto3
from botocore.exceptions import ClientError

dynamodb = boto3.resource("dynamodb")
kms = boto3.client("kms")

patients_table = dynamodb.Table(os.environ["PATIENTS_TABLE"])
audit_table = dynamodb.Table(os.environ["AUDIT_TABLE"])
KMS_KEY_ID = os.environ["KMS_KEY_ID"]

# ----------------------------------------------------------------------------
# Roles / RBAC  (deny-by-default: a role not listed for an action is refused)
# ----------------------------------------------------------------------------
ADMIN, DOCTOR, RECEPTIONIST = "Admin", "Doctor", "Receptionist"
KNOWN_ROLES = (ADMIN, DOCTOR, RECEPTIONIST)

PERMISSIONS = {
    "patient:create": {ADMIN, DOCTOR},
    "patient:read": {ADMIN, DOCTOR, RECEPTIONIST},
    "patient:update": {ADMIN, DOCTOR},
    "audit:read": {ADMIN},
}

# Fields a Receptionist may never see or write
CLINICAL_FIELDS = ("clinical_notes", "allergies")


def get_identity(event):
    """Read username + role from validated Cognito authorizer claims only.

    Request headers and body are attacker-controlled and are never trusted
    for identity.
    """
    claims = (event.get("requestContext") or {}).get("authorizer", {}).get("claims", {})
    username = claims.get("cognito:username", "unknown")
    groups = claims.get("cognito:groups", "")
    if isinstance(groups, str):
        groups = [g.strip() for g in groups.split(",") if g.strip()]
    role = next((r for r in KNOWN_ROLES if r in groups), None)
    return username, role


def is_allowed(role, action):
    return role in PERMISSIONS.get(action, set())


# ----------------------------------------------------------------------------
# Input validation (server-side whitelist — the UI is not a control)
# ----------------------------------------------------------------------------
NAME_RE = re.compile(r"^[A-Za-z][A-Za-z '\-]{0,49}$")
DIGITS10_RE = re.compile(r"^\d{10}$")
EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$", re.I)

ALLOWED_FIELDS = {
    "first_name", "last_name", "date_of_birth", "health_card",
    "email", "phone", "clinical_notes", "allergies",
}
REQUIRED_FIELDS = {"first_name", "last_name", "date_of_birth", "health_card"}

MAX_BODY_BYTES = 10_000
MAX_NOTES = 2000      # kept under the KMS 4KB plaintext limit
MAX_ALLERGIES = 500


class ValidationError(Exception):
    """Raised with a safe, non-echoing message."""


def _check_field(name, value):
    if not isinstance(value, str):
        raise ValidationError(f"Field '{name}' must be text.")
    value = value.strip()

    if name in ("first_name", "last_name"):
        if not NAME_RE.match(value):
            raise ValidationError(f"Field '{name}' must be 1-50 letters, spaces, hyphens or apostrophes.")
    elif name == "date_of_birth":
        if not DATE_RE.match(value):
            raise ValidationError("Field 'date_of_birth' must be YYYY-MM-DD.")
        try:
            dob = date.fromisoformat(value)
        except ValueError:
            raise ValidationError("Field 'date_of_birth' is not a real date.")
        if dob > date.today() or dob.year < 1900:
            raise ValidationError("Field 'date_of_birth' must be between 1900 and today.")
    elif name == "health_card":
        if not DIGITS10_RE.match(value):
            raise ValidationError("Field 'health_card' must be exactly 10 digits.")
    elif name == "phone":
        if value and not DIGITS10_RE.match(value):
            raise ValidationError("Field 'phone' must be exactly 10 digits.")
    elif name == "email":
        if value and (len(value) > 254 or not EMAIL_RE.match(value)):
            raise ValidationError("Field 'email' is not a valid address.")
    elif name == "clinical_notes":
        if len(value) > MAX_NOTES:
            raise ValidationError(f"Field 'clinical_notes' exceeds {MAX_NOTES} characters.")
    elif name == "allergies":
        if len(value) > MAX_ALLERGIES:
            raise ValidationError(f"Field 'allergies' exceeds {MAX_ALLERGIES} characters.")
    return value


def parse_body(event, require_all=True):
    """Parse and whitelist-validate a JSON body. Unknown fields are rejected."""
    raw = event.get("body") or ""
    if len(raw.encode("utf-8")) > MAX_BODY_BYTES:
        raise ValidationError("Request body is too large.")
    try:
        data = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        raise ValidationError("Body must be valid JSON.")
    if not isinstance(data, dict):
        raise ValidationError("Body must be a JSON object.")

    unknown = set(data) - ALLOWED_FIELDS
    if unknown:
        # Name the field but never echo its value back.
        raise ValidationError(f"Unknown field(s): {', '.join(sorted(unknown))}.")
    if require_all:
        missing = REQUIRED_FIELDS - set(data)
        if missing:
            raise ValidationError(f"Missing required field(s): {', '.join(sorted(missing))}.")

    return {k: _check_field(k, v) for k, v in data.items()}


def valid_patient_id(pid):
    return bool(pid and UUID_RE.match(pid))


# ----------------------------------------------------------------------------
# Encryption (AES-256-GCM via AWS KMS) and integrity (SHA-256)
# ----------------------------------------------------------------------------
def encrypt_field(plaintext, patient_id):
    """Encrypt one clinical field. The encryption context binds the ciphertext
    to this patient, so a blob copied onto another record fails to decrypt."""
    if plaintext is None or plaintext == "":
        return ""
    resp = kms.encrypt(
        KeyId=KMS_KEY_ID,
        Plaintext=plaintext.encode("utf-8"),
        EncryptionContext={"patient_id": patient_id, "app": "securehealth"},
    )
    return base64.b64encode(resp["CiphertextBlob"]).decode("ascii")


def decrypt_field(ciphertext_b64, patient_id):
    if not ciphertext_b64:
        return ""
    resp = kms.decrypt(
        CiphertextBlob=base64.b64decode(ciphertext_b64),
        EncryptionContext={"patient_id": patient_id, "app": "securehealth"},
    )
    return resp["Plaintext"].decode("utf-8")


def compute_integrity(record):
    """SHA-256 over the canonical PLAINTEXT record.

    Hashing plaintext (not ciphertext) means tampering is detected whether an
    attacker edits a clear field like first_name or swaps an encrypted blob.
    """
    canonical = {k: record.get(k, "") for k in sorted(ALLOWED_FIELDS | {"patient_id"})}
    blob = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


class IntegrityError(Exception):
    pass


def to_storage(record):
    """Plaintext record -> item stored in DynamoDB (clinical fields encrypted)."""
    pid = record["patient_id"]
    item = {k: v for k, v in record.items() if k not in CLINICAL_FIELDS}
    item["integrity"] = compute_integrity(record)
    for f in CLINICAL_FIELDS:
        item[f + "_enc"] = encrypt_field(record.get(f, ""), pid)
    return item


def from_storage(item):
    """Stored item -> plaintext record, verifying integrity. Raises on tamper."""
    pid = item["patient_id"]
    record = {k: v for k, v in item.items() if not k.endswith("_enc") and k != "integrity"}
    for f in CLINICAL_FIELDS:
        record[f] = decrypt_field(item.get(f + "_enc", ""), pid)
    if compute_integrity(record) != item.get("integrity"):
        raise IntegrityError(f"Integrity check failed for record {pid}")
    return record


def redact_for(role, record):
    """Receptionists see demographics only."""
    if role != RECEPTIONIST:
        return record
    out = dict(record)
    for f in CLINICAL_FIELDS:
        out[f] = "[REDACTED]"
    return out


# ----------------------------------------------------------------------------
# Audit logging (append-only)
# ----------------------------------------------------------------------------
def write_audit(username, role, action, outcome, patient_id=None, detail=None):
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
    if detail:
        item["detail"] = detail[:300]
    try:
        audit_table.put_item(Item=item)
    except ClientError as exc:                      # never let logging break the request
        print(f"[AUDIT-FAIL] {action}/{outcome}: {exc}")


# ----------------------------------------------------------------------------
# HTTP responses
# ----------------------------------------------------------------------------
SECURITY_HEADERS = {
    "Content-Type": "application/json",
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cache-Control": "no-store",
    "Access-Control-Allow-Origin": "*",           # tightened to the Amplify domain for the demo
    "Access-Control-Allow-Headers": "Content-Type,Authorization",
    "Access-Control-Allow-Methods": "GET,POST,PUT,OPTIONS",
}


def ok(body, status=200):
    return {"statusCode": status, "headers": SECURITY_HEADERS, "body": json.dumps(body, default=str)}


def error(status, code, message):
    """Client-safe error: never leaks stack traces, SQL, or internal detail."""
    return {
        "statusCode": status,
        "headers": SECURITY_HEADERS,
        "body": json.dumps({"error": code, "message": message}),
    }


def new_patient_id():
    return str(uuid.uuid4())


def now_iso():
    return datetime.now(timezone.utc).isoformat()
