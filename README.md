# SecureHealth — AWS-Based Secure Patient Records Portal

MCSC-6002-RNA Applied Group Project — Humber Polytechnic
Team: Malav Mehta, Robert Ruiz Villalta, Zawad Hossain, Cinderella Akash Gill

SecureHealth is a serverless patient-records portal implementing six security
controls: Cognito authentication with MFA, role-based access control, input
validation, AES-256-GCM encryption + KMS, SHA-256 integrity verification, and
append-only audit logging with CloudWatch/CloudTrail.

## Repository layout

```
backend/            SAM application (API Gateway + Lambda + DynamoDB + Cognito + KMS)
  template.yaml     Infrastructure as code — deploys the whole stack
  src/handlers/     Lambda function code (Python 3.12)
docs/
  api-contract.md   REST API contract (endpoints, schemas, roles) — source of truth
frontend/           Next.js dashboard (created in Phase 2 — see below)
```

## Phase 0 setup (each member, ~45 min)

Each member runs their **own AWS account** and deploys their **own copy** of the
stack for development. Malav's deployment is the **canonical demo environment** —
the graded demo, seeded sample patients, and the final frontend configuration
all point at his stack outputs.

1. Create an AWS account at aws.amazon.com (new accounts default to the free
   account plan with USD $100 credits — services stop rather than bill).
2. Immediately enable MFA on your root user: account menu (top right) →
   Security credentials → Assign MFA device → Authenticator app.
3. Install: Python 3.12, Node 20+, AWS CLI v2, AWS SAM CLI, Git.
4. Create an IAM admin user for daily work (don't keep using root), generate
   an access key, and run `aws configure` (region: `ca-central-1`).
5. Clone this repo; confirm `sam validate` passes inside `backend/`.
6. Deploy your own stack (next section) and verify the 401/200 gate.

**Never commit stack outputs, tokens, or `.env` files.** Frontend configuration
(ApiUrl, UserPoolId, ClientId) lives in `frontend/.env.local`, which is
gitignored — Malav shares the canonical demo values in the team chat, not in git.

## Deploy the skeleton (Phase 1 gate)

```bash
cd backend
sam build
sam deploy --guided        # stack name: securehealth, region: ca-central-1
```

Outputs include the API base URL, Cognito User Pool ID, and Client ID.

### Create test users (one per role)

```bash
POOL=<UserPoolId from outputs>
for u in admin1 doctor1 reception1; do
  aws cognito-idp admin-create-user --user-pool-id $POOL --username $u \
    --temporary-password 'TempPass#2026' --message-action SUPPRESS
done
aws cognito-idp admin-add-user-to-group --user-pool-id $POOL --username admin1     --group-name Admin
aws cognito-idp admin-add-user-to-group --user-pool-id $POOL --username doctor1    --group-name Doctor
aws cognito-idp admin-add-user-to-group --user-pool-id $POOL --username reception1 --group-name Receptionist
```

### Verify the security gate (Phase 1 exit criterion)

```bash
curl -i <ApiUrl>/health                          # expect 401 Unauthorized
curl -i <ApiUrl>/health -H "Authorization: Bearer <IdToken>"   # expect 200 + your role
```

Getting an IdToken for testing: use `aws cognito-idp initiate-auth` with
USER_PASSWORD_AUTH (enabled on the app client), or the frontend login once it exists.

## Rules of the road

- **No secrets in code or commits.** Keys live in KMS/environment config.
- All work on feature branches → PR → review by one other member → merge.
- `docs/api-contract.md` is the contract: frontend and backend both build to it.
  Changes to it require agreement from Malav + Robert.
- Capture evidence screenshots AS YOU WORK into `docs/evidence/` (report needs them).

## Phase plan

See SecureHealth_Phase_Plan.docx (shared) — compressed timeline:
Phase 0+1 → Aug 11 | Phase 2 → Aug 13 | Phase 3 → Aug 14 | Phase 4 → Aug 15 | Submit Aug 16
