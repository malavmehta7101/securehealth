# Phase 2 — security implementation notes

Written for the report's "Security Features Implemented" section.

## 1. Authentication & access control
Amazon Cognito user pool, MFA enforced (TOTP), 12-character password policy,
admin-only account creation, short-lived JWTs. Roles come from Cognito groups
and are read **only** from the validated `cognito:groups` claim in
`common.get_identity()` — request headers and bodies are never trusted for identity.

RBAC is **deny-by-default**: `common.PERMISSIONS` maps an action to the set of
roles allowed; anything not listed is refused. A user with no recognised group
gets 403. Every denial is written to the audit log.

## 2. Input validation
`common.parse_body()` enforces a whitelist: unknown fields are rejected outright
(blocks mass-assignment, e.g. an injected `is_admin`), and each field is checked
against a strict pattern (names: letters/space/hyphen/apostrophe only; health
card and phone: exactly 10 digits; DOB: real date between 1900 and today; email:
RFC-style pattern). Body size is capped at 10 KB. Rejections are audited and the
error message never echoes the submitted value back to the client.

## 3. Encryption (symmetric, AES-256)
`clinical_notes` and `allergies` are encrypted with AES-256-GCM by AWS KMS using
the project's customer-managed key before they reach DynamoDB; the table itself
is additionally encrypted at rest with the same CMK. The plaintext key never
leaves KMS, and the Lambda execution roles hold `kms:Encrypt`/`kms:Decrypt` on
that single key ARN and nothing else.

Each ciphertext is bound to its record with an **encryption context**
(`patient_id` + app name), so a blob copied from one patient onto another fails
to decrypt — this defeats a cut-and-paste attack that a plain ciphertext swap
would otherwise allow.

Design note: encryption is delegated to KMS rather than performed in application
code with a library key. This keeps key material out of the function's memory and
removes the native-dependency build step. The trade-off is a 4 KB plaintext limit
per call, which is why `clinical_notes` is capped at 2000 characters.

## 4. Hashing & integrity checks
`common.compute_integrity()` takes a SHA-256 hash over the canonical JSON of the
**plaintext** record (all fields, sorted keys). It is stored alongside the record
and re-verified on every read in `from_storage()`.

Hashing plaintext rather than ciphertext means tampering is caught in both
directions: editing a clear field (e.g. `first_name`) in the DynamoDB console,
or swapping an encrypted blob, both produce a mismatch. On mismatch the API
returns 409, refuses to serve the record, logs `TAMPER_DETECTED`, and prints a
`[SECURITY-ALERT]` line to CloudWatch. In list results a bad record is skipped
and counted rather than breaking the whole response.

## 5. Secure API & communication
REST API behind API Gateway with a Cognito authorizer (401 before any Lambda code
runs), per-method throttling (20 req/s, burst 40) as a DoS control, TLS 1.2+ on
all traffic, and security headers on every response (HSTS, `X-Content-Type-Options`,
`X-Frame-Options`, `Cache-Control: no-store`). Errors return a machine code plus a
generic message; stack traces and internal detail go to CloudWatch only.

## 6. Logging & monitoring
Append-only DynamoDB audit table (partitioned by day, sorted by timestamp)
recording user, role, action, outcome and record id for every create, read,
search, update, denial, validation rejection and tamper alert. No handler exposes
an update or delete path for it. Admin-only `GET /audit` surfaces it in the UI.
Lambda and API Gateway logs go to CloudWatch; CloudTrail records API and
infrastructure activity including every KMS key use.

## Known limitations (state these in the report — they read as maturity)
- Patient search uses a DynamoDB `Scan`; a GSI on `last_name` is the production choice.
- CORS is `*` for the demo; it should be pinned to the Amplify domain.
- Audit immutability relies on application design plus IAM; S3 Object Lock export
  would make it cryptographically tamper-evident.
- Rate limiting is per-method, not per-user; AWS WAF would add per-identity limits.
- The frontend CSP permits `unsafe-inline` and `unsafe-eval` because the Next.js
  development server requires them for hot module replacement and injected
  styles. A production build (`npm run build && npm start`) with nonce-based CSP
  removes both; this was verified as the only remaining ZAP finding after the
  header remediation, and all four original findings (missing CSP, missing
  anti-clickjacking header, `X-Powered-By` leak, missing `nosniff`) were fixed
  in `frontend/next.config.js`.