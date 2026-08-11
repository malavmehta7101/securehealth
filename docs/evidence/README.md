# Evidence Index

Artefacts supporting the *Testing & Validation* section of the report and the
live demonstration. Each item names the control it evidences and the STRIDE
category it addresses.

| File | Evidences | Control | STRIDE |
|---|---|---|---|
| `01-unauthenticated-401.png` | A request with no token is rejected at the gateway before any application code runs | Authentication | Spoofing |
| `02-authenticated-200.png` | Successful MFA login; the role is extracted from the validated Cognito group claim | Authentication, RBAC | Spoofing |
| `03-dynamodb-ciphertext.png` | Clinical fields stored as KMS ciphertext with a SHA-256 hash; no plaintext at rest | Encryption, Integrity | Information Disclosure |
| `04-receptionist-403.png` | A low-privilege role is refused a write by the API, not by the interface | RBAC | Elevation of Privilege |
| `05-receptionist-redacted.png` | Clinical fields returned as `[REDACTED]` while demographics remain visible | Redaction | Information Disclosure |
| `06-injection-400.png` | An injection payload is rejected and is not reflected back in the error | Input validation | Tampering |
| `07-tamper-409.png` | A record altered directly in DynamoDB fails verification on read | Integrity | Tampering |
| `08-dashboard-integrity-banner.png` | The tampered record is withheld from search results and the user is told why | Integrity, safe failure | Tampering |
| `09-audit-log.png` | Complete trail including successful access, denials and validation rejections | Logging | Repudiation |
| `10-pytest-run.png` | 142 passing tests, each carrying its STRIDE marker | Test coverage | All six |
| `11-cloudwatch-alarms.png` | Six security alarms deployed and in a healthy state | Monitoring | All six |
| `bandit-report.txt` / `.json` | Static analysis: no issues at any severity across 428 lines of handler code | Secure coding | Tampering, Info Disclosure |
| `zap-01-baseline.pdf` | Initial dynamic scan of the running frontend | — | — |
| `zap-02-before-remediation.pdf` | Four actionable header findings, no high-risk issues | Secure API | Information Disclosure |
| `zap-03-after-remediation.pdf` | Findings remediated; remaining CSP alerts accepted as a development-mode requirement | Secure API | Information Disclosure |

## Reproducing the captures

Screenshots 01-09 follow the demo script in `../TEST-MATRIX.md`; 10 is a
`pytest tests/ -v` run and 11 is the CloudWatch alarms overview. All were taken
against the deployed stack in `ca-central-1` using the three test accounts
(`admin1`, `doctor1`, `reception1`) and fictional patient data only.

## Note on redaction

These captures contain API endpoints, Cognito pool identifiers and CloudWatch
resource names. None are secrets, but bearer tokens were excluded from every
capture, and no real patient data exists anywhere in the system.