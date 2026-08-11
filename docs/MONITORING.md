# SecureHealth — Logging & Monitoring

Owner: Zawad. Covers the *Logging & Monitoring* control for the report and the
monitoring portion of the demo.

## Three layers

| Layer | What it records | Where it lives |
|---|---|---|
| Application audit trail | Every PHI access, change, denial, validation rejection and tamper alert, with user, role, action, record id and timestamp | `securehealth-audit` DynamoDB table (append-only), Admin-only `GET /audit` |
| Operational logs | Lambda execution logs, API Gateway access logs, structured `SECURITY_EVENT` lines | CloudWatch Logs (Lambda default retention) |
| Infrastructure trail | Every AWS API call, including every use of the KMS key | AWS CloudTrail (account default) |

## How metrics are produced

`common.emit_security_event()` prints one JSON line per security event:

```json
{"event":"SECURITY_EVENT","action":"PATIENT_CREATE","outcome":"DENIED_ROLE",
 "role":"Receptionist","user":"reception1","denied":true,"blocked":false,"alert":false}
```

CloudWatch **metric filters** parse those lines into custom metrics under the
`SecureHealth/Security` namespace. Metrics are derived from logs rather than
pushed with `PutMetricData` so that monitoring adds no latency to the request
path and cannot fail a user's call.

| Metric | Source filter | Meaning |
|---|---|---|
| `TamperDetections` | `action = TAMPER_DETECTED` | A record failed SHA-256 verification |
| `DeniedAccessAttempts` | `denied IS TRUE` | RBAC refused an operation |
| `ValidationRejections` | `action = VALIDATION_REJECT` | Malicious or malformed input blocked |
| `PhiAccessEvents` | successful reads and searches | Volume of PHI access — baseline for spotting spikes |
| `AuditReadDenied` | denied audit reads | Someone tried to read the audit trail without Admin |

## Alarms

All six publish to the `securehealth-security-alerts` SNS topic.

| Alarm | Threshold | Rationale |
|---|---|---|
| `SecureHealth-RecordTamperDetected` | ≥ 1 in 5 min | One integrity failure is already an incident — no tolerance band |
| `SecureHealth-RepeatedAccessDenials` | ≥ 5 in 5 min | A single denial is normal; a burst suggests probing or credential misuse |
| `SecureHealth-InputAttackProbing` | ≥ 10 in 5 min | Sustained rejections look like automated payload scanning |
| `SecureHealth-ApiServerErrors` | ≥ 5 5xx in 5 min | Availability: the API is failing, not just being probed |
| `SecureHealth-ApiThrottling` | ≥ 20 4xx over 10 min | The DoS throttling control is engaging |
| `SecureHealth-PatientsFunctionErrors` | ≥ 3 in 5 min | Function-level failure independent of the gateway |

Thresholds are deliberately asymmetric: integrity failures alarm on a single
event because they indicate data has already been altered, whereas denials and
rejections are expected in normal operation and only matter in volume.

## Dashboard

`SecureHealth-Security` in CloudWatch, nine widgets:

1. Integrity alerts (tamper detections) with the alarm threshold annotated
2. Denied access attempts, split by RBAC denials and audit-read denials
3. Input validation rejections
4. PHI access volume — the baseline that makes an anomaly visible
5. API Gateway requests vs 4xx vs 5xx
6. Lambda invocations and errors
7. API latency, p50 and p99
8. DynamoDB consumed capacity for both tables
9. A live Logs Insights table of the most recent 50 security events

## Subscribe to alerts (once per deployment)

```bash
aws sns subscribe \
  --topic-arn <AlertTopicArn from stack outputs> \
  --protocol email --notification-endpoint you@example.com \
  --region ca-central-1
```

Confirm via the emailed link. Until a subscription is confirmed, alarms still
fire and change state — they simply have nowhere to deliver.

## Demo script

1. Open the dashboard; note the quiet baseline.
2. Sign in as `reception1` and attempt to create a patient → 403.
3. Repeat four more times (five denials in the window).
4. Submit an injection payload as `admin1` → 400.
5. Tamper with a record in DynamoDB, then read it → 409.
6. Refresh the dashboard: the tamper, denial and rejection widgets all move, and
   the Logs Insights table lists the individual events with user and role.
7. Show `SecureHealth-RecordTamperDetected` in ALARM state.

Metrics appear within roughly one to two minutes; alarms evaluate on a
five-minute period, so allow time before expecting a state change on stage.

## Known limitations

- Alarms notify by email only; production would route to an on-call system.
- No anomaly detection on `PhiAccessEvents` — a per-user baseline (e.g. a
  clinician reading far more records than usual) would be the next step.
- Audit immutability rests on application design plus IAM; an S3 Object Lock
  export would make it cryptographically tamper-evident.
- Lambda log groups use the default (never-expire) retention because explicit
  log-group declarations collided with AWS auto-provisioning; setting a retention
  policy per group is straightforward follow-up work. Healthcare retention
  requirements would in any case exceed a short default.