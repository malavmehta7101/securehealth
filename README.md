# SecureHealth — AWS-Based Secure Patient Records Portal

MCSC-6002-RNA Applied Group Project · Humber Polytechnic
Malav Mehta · Robert Ruiz Villalta · Zawad Hossain · Cinderella Akash Gill

A serverless patient-records portal built so that every security control is
enforced on the server, not in the interface. Deployed and running in
`ca-central-1`.

**Status:** complete. Six controls implemented, 145 automated tests passing,
Bandit clean, OWASP ZAP findings remediated, monitoring live.

## The six controls

| Control | Implementation |
|---|---|
| Authentication & MFA | Amazon Cognito, TOTP enforced, 12-character policy, admin-only provisioning |
| Role-based access control | Deny-by-default matrix; identity read only from validated token claims |
| Input validation | Server-side whitelist; unknown fields rejected; strict per-field patterns |
| Encryption (AES-256-GCM) | AWS KMS customer-managed key; per-record encryption context; TLS in transit |
| Integrity verification | SHA-256 over the plaintext record, re-checked on every read; tampering returns 409 |
| Logging & monitoring | Append-only audit trail, CloudWatch metrics, six alarms, CloudTrail |

Three roles: **Admin** (full access plus the audit log), **Doctor** (full
clinical access), **Receptionist** (demographics only — clinical fields
redacted server-side, writes refused).

## Repository layout

```
backend/              SAM application — API Gateway, Lambda, DynamoDB, Cognito, KMS
  template.yaml       Infrastructure as code for the whole stack
  src/handlers/       common.py (shared security pipeline), patients.py, audit.py, health.py
  tests/              145 tests, each marked with the STRIDE category it validates
  login.py            First-time login and MFA enrolment for one account
  get_tokens.py       Fetch tokens for all three roles into .test-env
frontend/             Next.js dashboard — login with MFA, role-aware views, audit viewer
iot/                  Equipment-monitoring extension (separate stack, built beyond scope)
docs/
  api-contract.md     REST API contract — the source of truth for frontend and backend
  TEST-MATRIX.md      Every test mapped to its STRIDE threat and control
  PHASE2.md           Security implementation notes
  MONITORING.md       Logging, metrics, alarms and dashboard
  evidence/           Screenshots and scan reports, with an index
```

## Setup (each member, ~45 min)

Every member runs their **own AWS account** and deploys their **own copy** of
the stack. Malav's deployment is the canonical demo environment.

1. Create an AWS account (new accounts default to the free plan with USD $100
   in credits — services stop rather than bill).
2. Enable MFA on the root user immediately, then stop using root.
3. Install Python 3.13, Node 20+, AWS CLI v2, AWS SAM CLI, Git.
4. Create an IAM admin user for daily work, generate an access key, and run
   `aws configure` (region `ca-central-1`).
5. Run the one-time account setup below **before** your first deploy.
6. Deploy and verify the 401/200 gate.

### One-time AWS account setup

API Gateway can only write access logs once an account-level CloudWatch role is
registered. This is per account and region, not per stack, and does not exist in
a fresh account. Skipping it makes `sam deploy` fail with *"CloudWatch Logs role
ARN must be set in account settings"*.

```powershell
@'
{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"apigateway.amazonaws.com"},"Action":"sts:AssumeRole"}]}
'@ | Out-File -Encoding ascii trust-policy.json

aws iam create-role --role-name APIGatewayCloudWatchLogs --assume-role-policy-document file://trust-policy.json
aws iam attach-role-policy --role-name APIGatewayCloudWatchLogs --policy-arn arn:aws:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs

# wait ~30 s for IAM to propagate, then (substitute your account id):
aws apigateway update-account --patch-operations op=replace,path=/cloudwatchRoleArn,value=arn:aws:iam::ACCOUNT_ID:role/APIGatewayCloudWatchLogs --region ca-central-1
```

Your account id: `aws sts get-caller-identity --query Account --output text`

## Deploy

```bash
cd backend
sam validate --lint          # catches template errors in a second
sam build
sam deploy --guided          # stack: securehealth, region: ca-central-1
```

Outputs give the API URL, Cognito pool and client IDs, dashboard URL and the
alert topic ARN.

### Create the test users

```bash
POOL=<UserPoolId from outputs>
for u in admin1 doctor1 reception1; do
  aws cognito-idp admin-create-user --user-pool-id $POOL --username $u \
    --temporary-password 'TempPass#2026' --message-action SUPPRESS --region ca-central-1
done
aws cognito-idp admin-add-user-to-group --user-pool-id $POOL --username admin1     --group-name Admin        --region ca-central-1
aws cognito-idp admin-add-user-to-group --user-pool-id $POOL --username doctor1    --group-name Doctor       --region ca-central-1
aws cognito-idp admin-add-user-to-group --user-pool-id $POOL --username reception1 --group-name Receptionist --region ca-central-1
```

Each account needs one first login to set a permanent password and enrol MFA:

```bash
cd backend
python login.py admin1       # then doctor1, then reception1
```

### Verify the security gate

```bash
curl.exe -i <ApiUrl>/health                                    # 401 — no token
curl.exe -i <ApiUrl>/health -H "Authorization: Bearer $TOKEN"  # 200 — with your role
```

## Frontend

```bash
cd frontend
npm install
cp .env.local.example .env.local     # values come from the stack outputs
npm run dev                          # http://localhost:3000
```

`.env.local` is gitignored. Sign in as `admin1`, `doctor1` or `reception1` to
see the role differences.

## Tests

```bash
cd backend
python -m pytest tests/ -q                   # 115 unit tests, no AWS needed

python get_tokens.py                         # sign in as all three roles
source .test-env                             # Git Bash / macOS / Linux
python -m pytest tests/ -v                   # all 145, including integration
```

Every test carries a `@pytest.mark.stride(...)` marker. `docs/TEST-MATRIX.md`
maps each one to the threat it validates and the control that mitigates it.

### Security scans

```bash
python -m bandit -r src/handlers/            # static analysis — currently clean
```

OWASP ZAP is run against the running frontend; reports are in `docs/evidence/`.

## IoT extension

`iot/` holds a secure equipment-monitoring extension built after the assessed
scope was complete — an ESP32 with a temperature sensor publishing to AWS IoT
Core over mutual TLS, with a simulator for running it without hardware. It
deploys as a **separate stack** so this one is never at risk. See
`iot/README.md`.

## Rules of the road

- **No secrets in code or commits.** Keys live in KMS and environment config;
  `.env.local`, `.test-env`, `token.txt`, `iot/certs/` and `firmware/secrets.h`
  are all gitignored.
- **Infrastructure changes go in the repo as a commit**, never as a manual edit
  to a working copy. A fix that exists only locally will eventually be
  overwritten by a file copy — this happened to us three times.
- `docs/api-contract.md` is the contract; changes need agreement from Malav and
  Robert.
- Capture evidence screenshots into `docs/evidence/` as you work, not at the end.

## Troubleshooting

- **`sam: command not found` in Git Bash** — the installer ships `sam.cmd`; use
  PowerShell, or add `alias sam='sam.cmd'`.
- **Stack stuck in `ROLLBACK_COMPLETE`** — it cannot be updated, only deleted:
  `aws cloudformation delete-stack --stack-name securehealth --region ca-central-1`,
  then `aws cloudformation wait stack-delete-complete ...`, then redeploy.
- **`Invalid value for 'Auth' property`** — a YAML indentation error in the
  `Api` resource. `sam validate --lint` pinpoints it.
- **Frontend loads but shows no data** — check the browser console for a CORS
  error; the `Cors` block and `AddDefaultAuthorizerToCorsPreflight: false` must
  both be present on the `Api` resource.
- **502 from an endpoint** — `sam logs --stack-name securehealth --region ca-central-1`.
  A KMS `AccessDenied` means the function's policy is missing `kms:Decrypt` or
  `kms:GenerateDataKey` on the customer-managed key.
- **Token expired** — tokens last one hour. Re-run `python get_tokens.py` and
  `source .test-env`. Note `login.py` writes `token.txt` relative to the
  directory you launch it from.
- **Python runtime mismatch on `sam build`** — the template targets Python 3.13.

## Deliverables

| Item | Where |
|---|---|
| Project report | `SecureHealth_Project_Report.docx` |
| Presentation | `SecureHealth_Presentation.pptx` |
| Threat model | OWASP Threat Dragon model, 15 threats across all six STRIDE categories |
| Test matrix | `docs/TEST-MATRIX.md` |
| Evidence | `docs/evidence/` with an index README |