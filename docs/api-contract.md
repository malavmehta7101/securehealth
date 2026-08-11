# SecureHealth REST API Contract v1.0

**Source of truth** for frontend ↔ backend integration. Base URL comes from the
SAM stack output `ApiUrl`. All endpoints require `Authorization: Bearer <Cognito IdToken>`
unless noted. All requests/responses are JSON over HTTPS.

## Roles
| Cognito group | May do |
|---|---|
| Admin | Everything + audit log + user management |
| Doctor | Full clinical read/write |
| Receptionist | Demographics only — clinical fields are REDACTED on read, forbidden on write |

RBAC is enforced **server-side in Lambda from the token's `cognito:groups` claim**,
deny-by-default. The UI hiding a button is not a control.

## Endpoints

| # | Method & Path | Roles | Purpose |
|---|---|---|---|
| 1 | GET /health | any authenticated | Deployment/auth smoke test — returns caller's role |
| 2 | POST /patients | Admin, Doctor | Create patient record |
| 3 | GET /patients?q={text} | all | Search by name/health card (Receptionist: redacted) |
| 4 | GET /patients/{id} | all | Fetch one record (Receptionist: redacted) |
| 5 | PUT /patients/{id} | Admin, Doctor | Update record (re-encrypts, re-hashes) |
| 6 | GET /audit?limit={n} | Admin | Read audit log entries, newest first |

## Patient record schema

```json
{
  "patient_id": "uuid — server-generated",
  "first_name": "string 1-50, letters/space/hyphen/apostrophe only",
  "last_name":  "string 1-50, same whitelist",
  "date_of_birth": "YYYY-MM-DD, not in future, after 1900-01-01",
  "health_card": "string, 10 digits (fictional OHIP-style)",
  "email": "RFC 5322 basic pattern, max 254",
  "phone": "string, 10 digits",
  "clinical_notes": "string max 2000 — ENCRYPTED at rest (AES-256-GCM via KMS)",
  "allergies":      "string max 500 — ENCRYPTED at rest",
  "integrity": "server-managed SHA-256 hex — never accepted from client",
  "created_at": "ISO 8601, server-set",
  "updated_at": "ISO 8601, server-set"
}
```

**Receptionist redaction:** `clinical_notes` and `allergies` are replaced with
`"[REDACTED]"` in every response; PUT containing those fields returns 403.

## Validation rules (server-side, whitelist)
- Reject unknown fields (400).
- Every field validated against the pattern above BEFORE any DB access.
- IDs in paths must be valid UUIDv4 (400 otherwise).
- Max request body 10 KB.

## Error format (all non-2xx)

```json
{ "error": "short_machine_code", "message": "human readable, no internal detail" }
```

| Code | Meaning |
|---|---|
| 400 | Validation failure (message says which field, never echoes the value) |
| 401 | Missing/invalid/expired token (API Gateway authorizer) |
| 403 | Authenticated but role not permitted, or integrity check failed on write |
| 404 | Record not found |
| 409 | Integrity verification failed on read (tamper detected — also audited + alarmed) |
| 429 | Throttled |

## Audit events (written server-side on EVERY call)
`{ event_id, timestamp, user, role, action, patient_id?, outcome }`
Actions: LOGIN_SUCCESS, LOGIN_FAIL (from Cognito triggers, Phase 2),
PATIENT_CREATE, PATIENT_READ, PATIENT_SEARCH, PATIENT_UPDATE,
ACCESS_DENIED, TAMPER_DETECTED, AUDIT_READ.
